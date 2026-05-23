"""
API views for phone and company verification
"""
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .services import PhoneVerificationService, CompanyVerificationService

from .throttles import (
    PhoneVerifySendRateThrottle,
    PhoneVerifyResendRateThrottle,
    PhoneVerifyConfirmRateThrottle,
    CompanyVerifyRateThrottle,
    CompanySearchRateThrottle,
)


def _phone_verification_disabled_response():
    if not bool(getattr(settings, 'SMS_VERIFICATION_ENABLED', True)):
        return Response(
            {'error': 'Phone verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )
    return None


def _enterprise_verification_disabled_response():
    if not bool(getattr(settings, 'ENTERPRISE_VERIFICATION_ENABLED', False)):
        return Response(
            {'error': 'Enterprise verification is temporarily disabled.'},
            status=status.HTTP_410_GONE,
        )
    return None


@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    """
    Get or partially update current authenticated user info

    GET  /api/auth/me/
    PATCH /api/auth/me/  — accepts: address, company_country
    """
    user = request.user

    if request.method == 'PATCH':
        allowed_fields = {'address', 'company_country'}
        data = {k: v for k, v in request.data.items() if k in allowed_fields}
        if not data:
            return Response({'error': 'No updatable fields provided'}, status=status.HTTP_400_BAD_REQUEST)
        if 'company_country' in data:
            code = str(data['company_country']).strip().upper()
            if len(code) != 2 or not code.isalpha():
                return Response(
                    {'error': 'company_country must be a 2-letter ISO 3166-1 alpha-2 code'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            data['company_country'] = code
        if 'address' in data:
            data['address'] = str(data['address']).strip()[:500]
        for field, value in data.items():
            setattr(user, field, value)
        user.save(update_fields=list(data.keys()))
        return Response({'updated': list(data.keys())})

    # Get client IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(',')[0]
    else:
        client_ip = request.META.get('REMOTE_ADDR')

    # Get subscription plan
    current_plan = 'Free'
    try:
        from usage.models import Subscription
        subscription = Subscription.objects.filter(user=user, status='active').first()
        if subscription:
            current_plan = subscription.plan.display_name
    except Exception:
        pass

    # Latest legal acceptance (signup / other events)
    legal_acceptance = None
    try:
        from users.models import LegalAcceptance

        latest = (
            LegalAcceptance.objects.filter(user=user, accepted=True)
            .order_by('-accepted_at')
            .first()
        )
        if latest:
            legal_acceptance = {
                'accepted_at': latest.accepted_at,
                'event': latest.event,
                'documents': latest.documents or {},
                'ip_address': latest.ip_address,
                'user_agent': latest.user_agent,
            }
    except Exception:
        legal_acceptance = None

    throttle_rates = getattr(settings, 'REST_FRAMEWORK', {}).get('DEFAULT_THROTTLE_RATES', {}) or {}

    def _effective(user_attr, scope):
        val = getattr(user, user_attr, None)
        return f"{val}/hour" if val is not None else throttle_rates.get(scope)

    api_limits = {
        'user': throttle_rates.get('user'),
        'scan_start': _effective('scan_start_hourly_limit', 'scan_start'),
        'scan_stop': _effective('scan_stop_hourly_limit', 'scan_stop'),
        'export': _effective('export_hourly_limit', 'export'),
    }

    return Response({
        'id': user.id,
        'email': user.email,
        'is_verified': user.is_verified,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'last_name': user.last_name,
        'full_name': user.full_name,
        'phone': user.phone,
        'phone_verified': user.phone_verified,
        'company_name': user.company_name,
        'company_registration_number': user.company_registration_number,
        'company_address': user.company_address,
        'company_country': user.company_country,
        'company_verified': user.company_verified,
        'address': user.address,
        'is_superuser': user.is_superuser,
        'is_staff': user.is_staff,
        'is_admin': user.is_admin,
        'two_factor_enabled': user.two_factor_enabled,
        'date_joined': user.date_joined,
        'client_ip': client_ip,
        'current_plan': current_plan,
        'legal_acceptance': legal_acceptance,
        'api_limits': api_limits,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([PhoneVerifySendRateThrottle])
def send_phone_verification(request):
    """
    Send email OTP verification code.
    Phone is optional — the code is sent to the user's email address.

    POST /api/users/verify-phone/send/
    {
        "phone": "+359888123456"  # Optional — stored on profile if provided
    }
    """
    disabled = _phone_verification_disabled_response()
    if disabled is not None:
        return disabled

    # Get optional phone from request body or user profile
    phone = request.data.get('phone') or request.user.phone or ''

    service = PhoneVerificationService()

    # Validate phone format only if a phone number was supplied
    if phone:
        valid, message = service.validate_phone_format(phone)
        if not valid:
            return Response(
                {'error': message},
                status=status.HTTP_400_BAD_REQUEST
            )

    # Send verification code via email
    success, code, message = service.send_verification_code(request.user, phone)

    if success:
        response_data = {
            'success': True,
            'message': message,
        }
        # In development include code in response for easy testing
        if settings.DEBUG and code:
            response_data['code'] = code
        return Response(response_data)
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([PhoneVerifyConfirmRateThrottle])
def verify_phone_code(request):
    """
    Verify email OTP code

    POST /api/users/verify-phone/confirm/
    {
        "code": "123456"
    }
    """
    disabled = _phone_verification_disabled_response()
    if disabled is not None:
        return disabled

    code = request.data.get('code')

    if not code:
        return Response(
            {'error': 'Verification code is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    service = PhoneVerificationService()
    success, message = service.verify_code(request.user, code)

    if success:
        return Response({
            'success': True,
            'message': message,
            'phone_verified': True,
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([PhoneVerifyResendRateThrottle])
def resend_phone_verification(request):
    """
    Resend verification code to user's email

    POST /api/users/verify-phone/resend/
    """
    disabled = _phone_verification_disabled_response()
    if disabled is not None:
        return disabled

    service = PhoneVerificationService()
    success, code, message = service.resend_code(request.user)

    if success:
        return Response({
            'success': True,
            'message': message,
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([CompanyVerifyRateThrottle])
def verify_company(request):
    """
    Verify company registration

    POST /api/users/verify-company/
    {
        "company_name": "Example Ltd",
        "registration_number": "123456789",
        "country_code": "bg"
    }
    """
    disabled = _enterprise_verification_disabled_response()
    if disabled is not None:
        return disabled

    company_name = request.data.get('company_name')
    registration_number = request.data.get('registration_number')
    country_code = request.data.get('country_code')

    # Validate required fields
    if not all([company_name, registration_number, country_code]):
        return Response(
            {'error': 'company_name, registration_number, and country_code are required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Validate country code
    service = CompanyVerificationService()
    supported_countries = service.get_supported_countries()

    if country_code.lower() not in supported_countries:
        return Response(
            {
                'error': f'Country code {country_code} not supported',
                'supported_countries': supported_countries
            },
            status=status.HTTP_400_BAD_REQUEST
        )

    # Validate registration number format
    valid, message = service.validate_registration_number(registration_number, country_code)
    if not valid:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check subscription plan (Enterprise only)
    if not hasattr(request.user, 'subscription'):
        return Response(
            {'error': 'No active subscription found'},
            status=status.HTTP_403_FORBIDDEN
        )

    if request.user.subscription.plan.name != 'enterprise':
        return Response(
            {'error': 'Company verification is only available for Enterprise plan'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Verify company
    success, message, data = service.verify_company(
        request.user,
        company_name,
        registration_number,
        country_code
    )

    if success:
        return Response({
            'success': True,
            'message': message,
            'company_verified': True,
            'company_data': data,
        })
    else:
        return Response({
            'success': False,
            'message': message,
            'company_verified': False,
            'manual_review_required': True,
        }, status=status.HTTP_202_ACCEPTED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([CompanySearchRateThrottle])
def search_company(request):
    """
    Search for company (for autocomplete/lookup)

    GET /api/users/search-company/?q=example&country=bg
    """
    disabled = _enterprise_verification_disabled_response()
    if disabled is not None:
        return disabled

    query = request.GET.get('q')
    country = request.GET.get('country')

    if not query:
        return Response(
            {'error': 'Query parameter "q" is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    service = CompanyVerificationService()
    result = service.search_company(query, country)

    return Response(result)


@api_view(['GET'])
def get_supported_countries(request):
    """
    Get list of supported countries for company verification

    GET /api/users/supported-countries/
    """
    disabled = _enterprise_verification_disabled_response()
    if disabled is not None:
        return disabled

    service = CompanyVerificationService()
    countries = service.get_supported_countries()

    return Response({
        'countries': [
            {'code': code, 'name': name}
            for code, name in countries.items()
        ]
    })
