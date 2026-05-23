"""
Authentication views for login and signup with JWT tokens.
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework.throttling import AnonRateThrottle
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth import logout as django_logout
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.utils import extend_schema, OpenApiExample
from .serializers import UserCreateSerializer, UserSerializer
from .two_factor import verify_two_factor
from .location import update_user_location_async
from users.throttles import SignupRateThrottle, TokenRefreshRateThrottle
from users.throttles import PhoneVerifyConfirmAnonRateThrottle, PhoneVerifyResendAnonRateThrottle
import logging
import secrets

logger = logging.getLogger(__name__)


def _enterprise_verification_enabled() -> bool:
    from django.conf import settings

    return bool(getattr(settings, 'ENTERPRISE_VERIFICATION_ENABLED', False))


def _get_client_ip_for_logging(request):
    try:
        from utils.request_ip import get_client_ip

        return get_client_ip(request)
    except Exception:
        return request.META.get('REMOTE_ADDR')


def _mask_phone(phone: str) -> str:
    p = str(phone or '')
    if len(p) <= 4:
        return '***'
    return f"***{p[-4:]}"


def _update_geo_async(user_id: int, ip: str, *, include_registration: bool = False) -> None:
    """Fire-and-forget: persist IP + geo data on the user record."""
    update_user_location_async(user_id, ip, include_registration=include_registration)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([SignupRateThrottle])
def signup_start_view(request):
    """Strict signup step 1: validate input, send SMS, store PendingSignup.

    No User record is created until phone verification succeeds.
    """
    from django.conf import settings
    if not bool(getattr(settings, 'SMS_VERIFICATION_ENABLED', True)):
        return Response(
            {
                'error': (
                    'SMS verification is temporarily disabled. '
                    'Use /api/auth/signup/ to register with email verification.'
                )
            },
            status=status.HTTP_410_GONE,
        )

    from datetime import timedelta
    from django.utils import timezone
    from django.contrib.auth.hashers import make_password
    from users.models import PendingSignup, User
    from users.serializers import UserCreateSerializer
    from users.services.phone_verification import PhoneVerificationService
    from users.services.captcha import verify_turnstile

    # CAPTCHA token is not part of UserCreateSerializer; strip it before validation.
    data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
    captcha_token = str(data.pop('captcha_token', '') or data.pop('turnstile_token', '') or '').strip()

    ok, captcha_error = verify_turnstile(captcha_token, remote_ip=_get_client_ip_for_logging(request))
    if not ok:
        return Response({'error': captcha_error}, status=status.HTTP_400_BAD_REQUEST)

    serializer = UserCreateSerializer(data=data, context={'request': request})
    if not serializer.is_valid():
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    email = serializer.validated_data['email']
    phone = serializer.validated_data.get('phone', '') or ''

    if User.objects.filter(email__iexact=email).exists():
        return Response({'error': 'Account with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

    svc = PhoneVerificationService()

    # Abuse controls (DB-backed so it works even without shared cache/Redis).
    now = timezone.now()
    client_ip = _get_client_ip_for_logging(request)
    if client_ip:
        recent_ip_count = PendingSignup.objects.filter(
            ip_address=client_ip,
            created_at__gte=now - timedelta(hours=1),
        ).count()
        if recent_ip_count >= 5:
            return Response(
                {'error': 'Too many signup attempts. Please try again later.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

    # Create pending signup token + code
    token = secrets.token_urlsafe(32)
    code = svc.generate_code()

    # Cleanup old pending signups for same email (best-effort)
    PendingSignup.objects.filter(email__iexact=email).delete()

    pending = PendingSignup.objects.create(
        token=token,
        email=email,
        password_hash=make_password(serializer.validated_data['password']),
        first_name=serializer.validated_data.get('first_name', ''),
        middle_name=serializer.validated_data.get('middle_name', ''),
        last_name=serializer.validated_data.get('last_name', ''),
        phone=phone,
        address=serializer.validated_data.get('address', ''),
        code_hash=make_password(code),
        expires_at=timezone.now() + timedelta(minutes=10),
        ip_address=client_ip,
        user_agent=str(request.META.get('HTTP_USER_AGENT', '') or ''),
    )

    # Send the 6-digit code to the user's email (free — no SMS provider required)
    ok, message = svc.send_email_code(email, code)
    if not ok:
        pending.delete()
        return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)

    return Response(
        {
            'signup_token': token,
            'email': email,
            'message': 'Verification code sent to your email.'
        },
        status=status.HTTP_200_OK,
    )


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PhoneVerifyConfirmAnonRateThrottle])
def signup_confirm_phone_view(request):
    """Strict signup step 2: verify email OTP code and create the User."""
    from django.conf import settings
    if not bool(getattr(settings, 'SMS_VERIFICATION_ENABLED', True)):
        return Response(
            {'error': 'SMS verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )

    from django.utils import timezone
    from django.contrib.auth.hashers import check_password
    from users.models import PendingSignup
    from users.models import User
    from users.serializers import UserSerializer
    from subscriptions.models import Plan, Subscription

    token = str(request.data.get('signup_token', '') or '').strip()
    code = str(request.data.get('code', '') or '').strip()
    if not token or not code:
        return Response(
            {'error': 'signup_token and code are required'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    pending = PendingSignup.objects.filter(token=token).first()
    if not pending:
        return Response({'error': 'Invalid or expired signup token'}, status=status.HTTP_400_BAD_REQUEST)

    if pending.expires_at and timezone.now() > pending.expires_at:
        pending.delete()
        return Response(
            {'error': 'Verification code expired. Please register again.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    pending.attempts = int(pending.attempts or 0) + 1
    if pending.attempts > 10:
        pending.delete()
        return Response({'error': 'Too many attempts. Please register again.'}, status=status.HTTP_400_BAD_REQUEST)
    pending.save(update_fields=['attempts'])

    if not check_password(code, pending.code_hash):
        return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email__iexact=pending.email).exists():
        pending.delete()
        return Response({'error': 'Account with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

    # Create the real user (phone verified)
    user = User(
        email=pending.email,
        first_name=pending.first_name,
        middle_name=pending.middle_name,
        last_name=pending.last_name,
        phone=pending.phone,
        phone_verified=True,
        address=pending.address,
        is_active=True,
    )
    user.password = pending.password_hash
    user.save()
    _update_geo_async(
        user.pk,
        pending.ip_address or _get_client_ip_for_logging(request),
        include_registration=True,
    )

    # Legal acceptance audit trail
    try:
        from users.models import LegalAcceptance

        versions = getattr(settings, 'LEGAL_DOC_VERSIONS', None) or {
            'terms': '2026-01-23',
            'privacy': '2026-01-23',
            'disclaimer': '2026-01-23',
            'aup': '2026-01-23',
        }
        LegalAcceptance.objects.create(
            user=user,
            event=LegalAcceptance.EVENT_SIGNUP,
            documents={
                'terms': versions.get('terms'),
                'privacy': versions.get('privacy'),
                'disclaimer': versions.get('disclaimer'),
                'aup': versions.get('aup'),
            },
            accepted=True,
            ip_address=pending.ip_address,
            user_agent=pending.user_agent,
            meta={'path': getattr(request, 'path', None)},
        )
    except Exception:
        pass

    # Free plan subscription
    try:
        free_plan = Plan.objects.get(name__iexact='free')
        Subscription.objects.create(user=user, plan=free_plan, status='active')
    except Exception:
        pass

    # Create Django session for template views + JWT
    try:
        django_login(request, user)
    except Exception:
        pass

    refresh = RefreshToken.for_user(user)
    pending.delete()

    return Response(
        {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
        },
        status=status.HTTP_201_CREATED,
    )


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PhoneVerifyResendAnonRateThrottle])
def signup_resend_phone_view(request):
    """Resend SMS code for a pending signup."""
    from django.conf import settings
    if not bool(getattr(settings, 'SMS_VERIFICATION_ENABLED', True)):
        return Response(
            {'error': 'SMS verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )

    from django.utils import timezone
    from datetime import timedelta
    from django.contrib.auth.hashers import make_password
    from users.models import PendingSignup
    from users.services.phone_verification import PhoneVerificationService

    token = str(request.data.get('signup_token', '') or '').strip()
    if not token:
        return Response({'error': 'signup_token is required'}, status=status.HTTP_400_BAD_REQUEST)

    pending = PendingSignup.objects.filter(token=token).first()
    if not pending:
        return Response({'error': 'Invalid or expired signup token'}, status=status.HTTP_400_BAD_REQUEST)

    svc = PhoneVerificationService()
    code = svc.generate_code()

    ok, message = svc.send_email_code(pending.email, code)
    if not ok:
        return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)

    pending.code_hash = make_password(code)
    pending.expires_at = timezone.now() + timedelta(minutes=10)
    pending.attempts = 0
    pending.save(update_fields=['code_hash', 'expires_at', 'attempts'])

    return Response({'success': True, 'message': 'Verification code resent.'}, status=status.HTTP_200_OK)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([SignupRateThrottle])
def signup_enterprise_start_view(request):
    """Strict Enterprise signup step 1: validate input, send SMS, store PendingSignup.

    Enterprise details are provided again at confirm step (kept client-side).
    """
    from django.conf import settings
    if not _enterprise_verification_enabled():
        return Response(
            {'error': 'Enterprise verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )
    if not bool(getattr(settings, 'SMS_VERIFICATION_ENABLED', True)):
        return Response(
            {'error': 'SMS verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )

    from datetime import timedelta
    from django.utils import timezone
    from django.contrib.auth.hashers import make_password
    from users.models import PendingSignup, User
    from users.serializers import UserCreateSerializer
    from users.services.phone_verification import PhoneVerificationService
    from users.services.captcha import verify_turnstile

    # Map billing address to user address if needed.
    data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
    captcha_token = str(data.pop('captcha_token', '') or data.pop('turnstile_token', '') or '').strip()

    ok, captcha_error = verify_turnstile(captcha_token, remote_ip=_get_client_ip_for_logging(request))
    if not ok:
        return Response({'error': captcha_error}, status=status.HTTP_400_BAD_REQUEST)

    if not data.get('address'):
        data['address'] = data.get('billing_address') or ''

    serializer = UserCreateSerializer(data=data, context={'request': request})
    if not serializer.is_valid():
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    # Minimal enterprise field validation upfront
    company_name = str(data.get('company_name', '') or '').strip()
    billing_address = str(data.get('billing_address', '') or '').strip()
    billing_city = str(data.get('billing_city', '') or '').strip()
    billing_country = str(data.get('billing_country', '') or '').strip()
    if not company_name:
        return Response({'error': 'company_name is required'}, status=status.HTTP_400_BAD_REQUEST)
    if not billing_address or not billing_city:
        return Response({'error': 'billing_address and billing_city are required'}, status=status.HTTP_400_BAD_REQUEST)
    if not billing_country:
        billing_country = 'Bulgaria'

    email = serializer.validated_data['email']
    phone = serializer.validated_data.get('phone', '') or ''

    if User.objects.filter(email__iexact=email).exists():
        return Response({'error': 'Account with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

    svc = PhoneVerificationService()

    # Abuse controls (DB-backed so it works even without shared cache/Redis).
    now = timezone.now()
    client_ip = _get_client_ip_for_logging(request)
    if client_ip:
        recent_ip_count = PendingSignup.objects.filter(
            ip_address=client_ip,
            created_at__gte=now - timedelta(hours=1),
        ).count()
        if recent_ip_count >= 5:
            return Response(
                {'error': 'Too many signup attempts. Please try again later.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

    token = secrets.token_urlsafe(32)
    code = svc.generate_code()

    PendingSignup.objects.filter(email__iexact=email).delete()

    pending = PendingSignup.objects.create(
        token=token,
        email=email,
        password_hash=make_password(serializer.validated_data['password']),
        first_name=serializer.validated_data.get('first_name', ''),
        middle_name=serializer.validated_data.get('middle_name', ''),
        last_name=serializer.validated_data.get('last_name', ''),
        phone=phone,
        address=serializer.validated_data.get('address', ''),
        code_hash=make_password(code),
        expires_at=now + timedelta(minutes=10),
        ip_address=client_ip,
        user_agent=str(request.META.get('HTTP_USER_AGENT', '') or ''),
    )

    # Send the 6-digit code to the user's email (free — no SMS provider required)
    ok, message = svc.send_email_code(email, code)
    if not ok:
        pending.delete()
        return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)

    return Response(
        {
            'signup_token': token,
            'email': email,
            'message': 'Verification code sent to your email.'
        },
        status=status.HTTP_200_OK,
    )


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PhoneVerifyConfirmAnonRateThrottle])
def signup_enterprise_confirm_phone_view(request):
    """Strict Enterprise signup step 2: verify email OTP code, create User,

    then create EnterpriseCustomer + Stripe checkout.
    """
    from django.conf import settings
    if not _enterprise_verification_enabled():
        return Response(
            {'error': 'Enterprise verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )
    if not bool(getattr(settings, 'SMS_VERIFICATION_ENABLED', True)):
        return Response(
            {'error': 'SMS verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )

    from django.utils import timezone
    from django.conf import settings
    from django.contrib.auth.hashers import check_password
    from users.models import PendingSignup, User
    from users.serializers import UserSerializer
    from subscriptions.models import Plan, Subscription, EnterpriseCustomer
    from subscriptions.stripe_service import StripeService

    token = str(request.data.get('signup_token', '') or '').strip()
    code = str(request.data.get('code', '') or '').strip()
    if not token or not code:
        return Response(
            {'error': 'signup_token and code are required'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    pending = PendingSignup.objects.filter(token=token).first()
    if not pending:
        return Response({'error': 'Invalid or expired signup token'}, status=status.HTTP_400_BAD_REQUEST)

    if pending.expires_at and timezone.now() > pending.expires_at:
        pending.delete()
        return Response(
            {'error': 'Verification code expired. Please register again.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    pending.attempts = int(pending.attempts or 0) + 1
    if pending.attempts > 10:
        pending.delete()
        return Response({'error': 'Too many attempts. Please register again.'}, status=status.HTTP_400_BAD_REQUEST)
    pending.save(update_fields=['attempts'])

    if not check_password(code, pending.code_hash):
        return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email__iexact=pending.email).exists():
        pending.delete()
        return Response({'error': 'Account with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

    # Create the real user (phone verified)
    user = User(
        email=pending.email,
        first_name=pending.first_name,
        middle_name=pending.middle_name,
        last_name=pending.last_name,
        phone=pending.phone,
        phone_verified=True,
        address=pending.address,
        is_active=True,
    )
    user.password = pending.password_hash
    user.save()
    _update_geo_async(
        user.pk,
        pending.ip_address or _get_client_ip_for_logging(request),
        include_registration=True,
    )

    # Legal acceptance audit trail (best-effort)
    try:
        from users.models import LegalAcceptance

        versions = getattr(settings, 'LEGAL_DOC_VERSIONS', None) or {
            'terms': '2026-01-23',
            'privacy': '2026-01-23',
            'disclaimer': '2026-01-23',
            'aup': '2026-01-23',
        }
        LegalAcceptance.objects.create(
            user=user,
            event=LegalAcceptance.EVENT_SIGNUP,
            documents={
                'terms': versions.get('terms'),
                'privacy': versions.get('privacy'),
                'disclaimer': versions.get('disclaimer'),
                'aup': versions.get('aup'),
            },
            accepted=True,
            ip_address=pending.ip_address,
            user_agent=pending.user_agent,
            meta={'path': getattr(request, 'path', None), 'enterprise': True},
        )
    except Exception:
        pass

    # Ensure user has at least a Free subscription so the app remains usable pre-payment.
    try:
        free_plan = Plan.objects.get(name__iexact='free')
        Subscription.objects.create(user=user, plan=free_plan, status='active')
    except Exception:
        pass

    # Enterprise customer details from request (stored client-side until verification)
    company_name = str(request.data.get('company_name', '') or '').strip()
    billing_address = str(request.data.get('billing_address', '') or '').strip()
    billing_city = str(request.data.get('billing_city', '') or '').strip()
    billing_country = str(request.data.get('billing_country', '') or '').strip() or 'Bulgaria'

    if not company_name:
        pending.delete()
        return Response({'error': 'company_name is required'}, status=status.HTTP_400_BAD_REQUEST)
    if not billing_address or not billing_city:
        pending.delete()
        return Response({'error': 'billing_address and billing_city are required'}, status=status.HTTP_400_BAD_REQUEST)

    # Create enterprise customer record (best-effort)
    try:
        EnterpriseCustomer.objects.create(
            user=user,
            company_name=company_name,
            vat_number=str(request.data.get('vat_number', '') or ''),
            registration_number=str(request.data.get('registration_number', '') or ''),
            billing_address=billing_address,
            billing_city=billing_city,
            billing_country=billing_country,
            billing_zip=str(request.data.get('billing_zip', '') or ''),
            billing_email=str(request.data.get('billing_email', '') or user.email),
            billing_phone=str(request.data.get('billing_phone', '') or pending.phone),
            accounting_contact_name=str(request.data.get('accounting_contact_name', '') or ''),
            accounting_contact_email=str(request.data.get('accounting_contact_email', '') or ''),
            payment_terms=str(request.data.get('payment_terms', '') or 'net_30'),
            use_stripe=True,
        )
    except Exception:
        # Do not block login if enterprise record fails
        logger.exception("Failed creating EnterpriseCustomer")

    # Stripe checkout
    checkout_url = None
    requires_payment = True
    try:
        enterprise_plan = Plan.objects.get(name__iexact='enterprise')
        frontend_url = str(getattr(settings, 'FRONTEND_URL', '') or '').rstrip('/')
        checkout_session = StripeService.create_checkout_session(
            user=user,
            plan=enterprise_plan,
            success_url=f"{frontend_url}/payment-success",
            cancel_url=f"{frontend_url}/register-enterprise?payment=cancelled",
        )
        checkout_url = getattr(checkout_session, 'url', None)
    except Exception:
        frontend_url = str(getattr(settings, 'FRONTEND_URL', '') or '').rstrip('/')
        checkout_url = f"{frontend_url}/pricing" if frontend_url else None
        requires_payment = True

    refresh = RefreshToken.for_user(user)
    pending.delete()

    return Response(
        {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
            'requires_payment': requires_payment,
            'checkout_url': checkout_url,
        },
        status=status.HTTP_201_CREATED,
    )


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PhoneVerifyResendAnonRateThrottle])
def signup_enterprise_resend_phone_view(request):
    """Resend email OTP code for a pending enterprise signup."""
    if not _enterprise_verification_enabled():
        return Response(
            {'error': 'Enterprise verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )

    # Same behavior as the generic strict resend.
    return signup_resend_phone_view(request)


# Custom throttle for login attempts
class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'  # Uses 'login' rate from settings

    def wait(self):
        """Return wait time in seconds with better formatting"""
        wait_seconds = super().wait()
        if wait_seconds:
            # Convert to minutes if more than 60 seconds
            if wait_seconds >= 60:
                wait_minutes = int(wait_seconds / 60)
                return wait_minutes * 60  # Return in minute increments
            return wait_seconds
        return None


@extend_schema(
    summary="User Login",
    description="Authenticate user and return JWT access and refresh tokens",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string', 'format': 'email'},
                'password': {'type': 'string', 'format': 'password'}
            },
            'required': ['email', 'password']
        }
    },
    responses={
        200: {
            'type': 'object',
            'properties': {
                'access': {'type': 'string', 'description': 'JWT access token'},
                'refresh': {'type': 'string', 'description': 'JWT refresh token'},
                'user': {'type': 'object', 'description': 'User information'}
            }
        },
        401: {
            'type': 'object',
            'properties': {
                'error': {'type': 'string'}
            }
        }
    },
    examples=[
        OpenApiExample(
            'Login Example',
            value={
                'email': 'user@example.com',
                'password': 'SecurePass123!'
            }
        )
    ]
)
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def login_view(request):
    """
    User login endpoint with rate limiting (5 attempts per hour).

    Accepts email and password, returns JWT tokens and user data.
    """
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response(
            {'error': 'Email and password are required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Verify CAPTCHA token if Turnstile is enabled
    data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
    captcha_token = str(data.pop('captcha_token', '') or data.pop('turnstile_token', '') or '').strip()
    from users.services.captcha import verify_turnstile
    ok, captcha_error = verify_turnstile(captcha_token, remote_ip=_get_client_ip_for_logging(request))
    if not ok:
        return Response({'error': captcha_error}, status=status.HTTP_400_BAD_REQUEST)

    # Authenticate user
    user = authenticate(request, username=email, password=password)

    if user is None:
        logger.warning(f"Failed login attempt for email: {email} from IP: {request.META.get('REMOTE_ADDR')}")
        return Response(
            {'error': 'Invalid email or password'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    if not user.is_active:
        return Response(
            {'error': 'Account is deactivated'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Enforce 2FA (TOTP or backup code) if enabled
    if getattr(user, 'two_factor_enabled', False):
        code = request.data.get('otp') or request.data.get('code')
        if not code:
            return Response(
                {'detail': 'Two-factor code required', 'two_factor_required': True},
                status=status.HTTP_401_UNAUTHORIZED
            )

        result = verify_two_factor(
            secret=getattr(user, 'two_factor_secret', None),
            backup_codes=getattr(user, 'two_factor_backup_codes', []) or [],
            code=code,
        )
        if not result.ok:
            return Response(
                {'detail': 'Invalid two-factor code'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Invalidate used backup code (if any)
        if result.used_backup_code and result.backup_code_index is not None:
            try:
                codes = list(user.two_factor_backup_codes or [])
                codes.pop(result.backup_code_index)
                user.two_factor_backup_codes = codes
                user.save(update_fields=['two_factor_backup_codes'])
            except Exception:
                pass

    # Create Django session for template views
    django_login(request, user)

    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)

    # Serialize user data
    user_serializer = UserSerializer(user)

    # Update last seen location from IP (async, best-effort)
    _update_geo_async(user.pk, _get_client_ip_for_logging(request))

    return Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': user_serializer.data
    }, status=status.HTTP_200_OK)


@extend_schema(
    summary="OIDC SSO Login",
    description="Exchange an OpenID Connect id_token for local JWT access/refresh tokens.",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'id_token': {'type': 'string', 'description': 'OIDC ID token'},
            },
            'required': ['id_token'],
        }
    },
    responses={
        200: {
            'type': 'object',
            'properties': {
                'access': {'type': 'string'},
                'refresh': {'type': 'string'},
                'user': {'type': 'object'},
            },
        },
        400: {'type': 'object', 'properties': {'error': {'type': 'string'}}},
        401: {'type': 'object', 'properties': {'error': {'type': 'string'}}},
        501: {'type': 'object', 'properties': {'error': {'type': 'string'}}},
    },
)
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def oidc_login_view(request):
    """OIDC SSO: verify id_token and mint local JWT tokens."""
    from django.conf import settings
    from django.contrib.auth import get_user_model

    try:
        import jwt  # PyJWT
    except Exception:
        return Response({"error": "OIDC support not installed"}, status=status.HTTP_501_NOT_IMPLEMENTED)

    id_token = request.data.get('id_token')
    if not id_token:
        return Response({'error': 'id_token is required'}, status=status.HTTP_400_BAD_REQUEST)

    issuer = getattr(settings, 'OIDC_ISSUER', None)
    audience = getattr(settings, 'OIDC_AUDIENCE', None)
    jwks_url = getattr(settings, 'OIDC_JWKS_URL', None)
    if not jwks_url:
        return Response({'error': 'OIDC_JWKS_URL is not configured'}, status=status.HTTP_501_NOT_IMPLEMENTED)

    try:
        jwk_client = jwt.PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token).key
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256", "ES256", "RS384", "RS512"],
            audience=audience,
            issuer=issuer,
            options={
                'verify_aud': bool(audience),
                'verify_iss': bool(issuer),
            },
        )
    except Exception as exc:
        logger.warning("OIDC token verification failed: %s", exc)
        return Response({'error': 'Invalid id_token'}, status=status.HTTP_401_UNAUTHORIZED)

    email = claims.get('email') or claims.get('upn') or claims.get('preferred_username')
    if not email:
        return Response({'error': 'id_token is missing an email claim'}, status=status.HTTP_400_BAD_REQUEST)

    User = get_user_model()
    user = User.objects.filter(email__iexact=email).first()
    if not user:
        user = User.objects.create_user(
            email=email,
            password=secrets.token_urlsafe(32),
            first_name=claims.get('given_name') or claims.get('first_name') or '',
            last_name=claims.get('family_name') or claims.get('last_name') or '',
        )
        # Best-effort: if this project tracks verification, mark verified.
        if hasattr(user, 'is_verified'):
            try:
                user.is_verified = True
                user.save(update_fields=['is_verified'])
            except Exception:
                pass
        _update_geo_async(user.pk, _get_client_ip_for_logging(request), include_registration=True)

    if not user.is_active:
        return Response({'error': 'Account is deactivated'}, status=status.HTTP_403_FORBIDDEN)

    django_login(request, user)
    refresh = RefreshToken.for_user(user)
    user_serializer = UserSerializer(user)
    return Response(
        {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': user_serializer.data,
        },
        status=status.HTTP_200_OK,
    )


@extend_schema(
    summary="User Registration",
    description="Register a new user account and return JWT tokens",
    tags=["Authentication"],
    request=UserCreateSerializer,
    responses={
        201: {
            'type': 'object',
            'properties': {
                'access': {'type': 'string', 'description': 'JWT access token'},
                'refresh': {'type': 'string', 'description': 'JWT refresh token'},
                'user': {'type': 'object', 'description': 'User information'}
            }
        },
        400: {
            'type': 'object',
            'properties': {
                'errors': {'type': 'object'}
            }
        }
    },
    examples=[
        OpenApiExample(
            'Registration Example',
            value={
                'email': 'newuser@example.com',
                'password': 'SecurePass123!',
                'password_confirm': 'SecurePass123!',
                'first_name': 'John',
                'last_name': 'Doe',
                'accept_terms': True,
                'accept_privacy': True,
                'accept_disclaimer': True,
                'accept_aup': True,
            }
        )
    ]
)
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([SignupRateThrottle])
def signup_view(request):
    """
    User registration endpoint with optional plan selection.

    Creates a new user account and returns JWT tokens.
    If a paid plan (Pro/Enterprise) is selected, also returns checkout URL.
    """
    # Never log raw signup payloads (they include credentials).
    try:
        email = str(request.data.get('email', '') or '')
        domain = email.split('@', 1)[1] if '@' in email else ''
    except Exception:
        domain = ''
    logger.info(
        "Signup request received",
        extra={
            'ip': request.META.get('REMOTE_ADDR'),
            'email_domain': domain,
            'path': getattr(request, 'path', ''),
        },
    )

    # Email-only signup with pending verification
    from users.serializers import UserCreateSerializer
    from users.services.captcha import verify_turnstile
    from django.utils import timezone
    from django.contrib.auth.hashers import make_password
    from django.conf import settings
    from datetime import timedelta
    from users.models import PendingEmailSignup, User
    from users.email_views import _get_frontend_url
    from django.utils.http import urlsafe_base64_encode
    from django.utils.encoding import force_bytes
    from django.core import signing
    from utils.sendgrid_service import sendgrid_service

    data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
    captcha_token = str(data.pop('captcha_token', '') or data.pop('turnstile_token', '') or '').strip()

    ok, captcha_error = verify_turnstile(captcha_token, remote_ip=_get_client_ip_for_logging(request))
    if not ok:
        return Response({'error': captcha_error}, status=status.HTTP_400_BAD_REQUEST)

    serializer = UserCreateSerializer(data=data, context={'request': request})
    if not serializer.is_valid():
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    email = serializer.validated_data['email']
    if User.objects.filter(email__iexact=email).exists():
        return Response({'error': 'Account with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

    versions = getattr(settings, 'LEGAL_DOC_VERSIONS', None) or {
        'terms': '2026-01-23',
        'privacy': '2026-01-23',
        'disclaimer': '2026-01-23',
        'aup': '2026-01-23',
    }

    expires_seconds = int(getattr(settings, 'EMAIL_SIGNUP_TOKEN_TTL_SECONDS', 172800) or 172800)
    expires_at = timezone.now() + timedelta(seconds=expires_seconds)

    pending, _created = PendingEmailSignup.objects.update_or_create(
        email=email,
        defaults={
            'password_hash': make_password(serializer.validated_data['password']),
            'first_name': serializer.validated_data.get('first_name', ''),
            'middle_name': serializer.validated_data.get('middle_name', ''),
            'last_name': serializer.validated_data.get('last_name', ''),
            'phone': serializer.validated_data.get('phone', ''),
            'address': serializer.validated_data.get('address', ''),
            'accepted_documents': {
                'terms': versions.get('terms'),
                'privacy': versions.get('privacy'),
                'disclaimer': versions.get('disclaimer'),
                'aup': versions.get('aup'),
            },
            'accepted_at': timezone.now(),
            'ip_address': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT', '') or '',
            'is_bot_suspected': False,
            'bot_signals': [],
            'expires_at': expires_at,
        },
    )

    uid = urlsafe_base64_encode(force_bytes(pending.id))
    token = signing.dumps({'id': str(pending.id), 'email': pending.email}, salt='email-signup')
    frontend_url = _get_frontend_url(request)
    verification_url = f"{frontend_url}/verify-email/{uid}/{token}/"

    try:
        email_sent = sendgrid_service.send_verification_email(
            user_email=pending.email,
            user_name=pending.first_name or pending.email.split('@')[0],
            verification_url=verification_url,
        )
    except Exception:
        logger.exception(
            'Failed to send signup verification email',
            extra={'email_domain': domain, 'path': getattr(request, 'path', '')},
        )
        return Response(
            {'error': 'Failed to send verification email. Please try again later.'},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if not email_sent:
        logger.error(
            'Signup verification email was not accepted by provider',
            extra={'email_domain': domain, 'path': getattr(request, 'path', '')},
        )
        return Response(
            {'error': 'Failed to send verification email. Please try again later.'},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    return Response(
        {
            'message': 'Verification email sent. Please check your inbox to activate your account.',
        },
        status=status.HTTP_202_ACCEPTED,
    )


@extend_schema(
    summary="Enterprise Registration",
    description="Register a new enterprise customer account with company details",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string'},
                'password': {'type': 'string'},
                'password_confirm': {'type': 'string'},
                'first_name': {'type': 'string'},
                'last_name': {'type': 'string'},
                'phone': {'type': 'string'},
                'company_name': {'type': 'string'},
                'vat_number': {'type': 'string'},
                'registration_number': {'type': 'string'},
                'billing_address': {'type': 'string'},
                'billing_city': {'type': 'string'},
                'billing_country': {'type': 'string'},
                'payment_terms': {'type': 'string'},
                'accept_terms': {'type': 'boolean'},
                'accept_privacy': {'type': 'boolean'},
                'accept_disclaimer': {'type': 'boolean'},
                'accept_aup': {'type': 'boolean'},
            }
        }
    },
    responses={201: {'type': 'object'}}
)
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([SignupRateThrottle])
def signup_enterprise_view(request):
    """Enterprise customer registration with company details."""
    return Response(
        {
            'error': 'Enterprise signup is temporarily disabled.',
        },
        status=status.HTTP_410_GONE,
    )


@extend_schema(
    summary="Refresh JWT Token",
    description="Obtain a new access token using a refresh token",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {'type': 'string', 'description': 'JWT refresh token'}
            },
            'required': ['refresh']
        }
    },
    responses={
        200: {
            'type': 'object',
            'properties': {
                'access': {'type': 'string', 'description': 'New JWT access token'}
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([TokenRefreshRateThrottle])
def token_refresh_view(request):
    """
    Refresh JWT access token.

    Accepts a refresh token and returns a new access token.
    """
    refresh_token = request.data.get('refresh')

    if not refresh_token:
        return Response(
            {'error': 'Refresh token is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        serializer = TokenRefreshSerializer(data={'refresh': refresh_token})
        serializer.is_valid(raise_exception=True)
        # May include rotated refresh token depending on SIMPLE_JWT settings.
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    except Exception:
        return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutRateThrottle(AnonRateThrottle):
    scope = 'logout'


@extend_schema(
    summary="Logout",
    description="Invalidate refresh token (blacklist) and clear server-side session.",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {'type': 'string', 'description': 'Refresh token to blacklist'}
            },
            'required': ['refresh']
        }
    },
    responses={200: {'type': 'object'}}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([LogoutRateThrottle])
def logout_view(request):
    refresh_token = request.data.get('refresh')
    if not refresh_token:
        return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

    # Clear Django session (used by template views)
    try:
        django_logout(request)
    except Exception:
        pass

    # Blacklist refresh token (requires token_blacklist app)
    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
    except Exception:
        # Return generic response to avoid token probing.
        return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

    return Response({'message': 'Logged out'}, status=status.HTTP_200_OK)
