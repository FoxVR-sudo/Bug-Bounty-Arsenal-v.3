"""
Email Verification and Password Reset Views
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from utils.sendgrid_service import sendgrid_service
from drf_spectacular.utils import extend_schema, OpenApiExample
import logging
from django.core import signing
from users.location import update_user_location_async

from users.throttles import (
    EmailVerifyRequestRateThrottle,
    EmailVerifyConfirmRateThrottle,
    PasswordResetRequestRateThrottle,
    PasswordResetConfirmRateThrottle,
)


def _get_frontend_url(request) -> str:
    origin = str(request.headers.get('Origin', '') or '').strip()
    configured = str(getattr(settings, 'FRONTEND_URL', '') or '').strip()
    if configured:
        if origin:
            try:
                from urllib.parse import urlsplit

                cfg = urlsplit(configured)
                org = urlsplit(origin)
                if cfg.scheme and cfg.netloc and org.scheme and org.netloc and cfg.netloc != org.netloc:
                    logger.warning(
                        'FRONTEND_URL host mismatch; using request Origin for email links. '
                        'configured=%s origin=%s',
                        configured,
                        origin,
                    )
                    return origin.rstrip('/')
            except Exception:
                pass

        return configured.rstrip('/')

    if origin:
        return origin.rstrip('/')

    referer = str(request.headers.get('Referer', '') or '').strip()
    if referer:
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(referer)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}".rstrip('/')
        except Exception:
            pass

    return f"{request.scheme}://{request.get_host()}".rstrip('/')


User = get_user_model()
logger = logging.getLogger(__name__)


def _send_welcome_email_with_retry(user) -> bool:
    user_name = user.get_full_name() or user.email.split('@')[0]

    success = sendgrid_service.send_welcome_email(
        user_email=user.email,
        user_name=user_name,
    )
    if success:
        logger.info(
            'Welcome email sent successfully for user_id=%s email=%s',
            user.pk,
            user.email,
        )
        return True

    logger.warning(
        'Welcome email failed on first attempt for user_id=%s email=%s; retrying once',
        user.pk,
        user.email,
    )
    retry_success = sendgrid_service.send_welcome_email(
        user_email=user.email,
        user_name=user_name,
    )
    if retry_success:
        logger.info(
            'Welcome email sent successfully on retry for user_id=%s email=%s',
            user.pk,
            user.email,
        )
        return True

    logger.error(
        'Welcome email failed after retry for user_id=%s email=%s',
        user.pk,
        user.email,
    )
    return False


@extend_schema(
    summary="Request email verification",
    description="Send email verification link to user's email address",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string', 'format': 'email'}
            },
            'required': ['email']
        }
    },
    responses={
        200: {
            'description': 'Verification email sent',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Verification email sent. Please check your inbox.'
                    }
                }
            }
        }
    },
    examples=[
        OpenApiExample(
            'Email Verification Request',
            value={'email': 'user@example.com'}
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([EmailVerifyRequestRateThrottle])
def request_email_verification(request):
    """
    Send email verification link to user
    """
    email = request.data.get('email')

    if not email:
        return Response(
            {'error': 'Email is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)

        if user.is_verified:
            return Response(
                {'message': 'Email is already verified'},
                status=status.HTTP_200_OK
            )

        # Generate verification token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Create verification URL
        frontend_url = _get_frontend_url(request)
        verification_url = f"{frontend_url}/verify-email/{uid}/{token}/"

        # Send email
        success = sendgrid_service.send_verification_email(
            user_email=user.email,
            user_name=user.get_full_name() or user.email.split('@')[0],
            verification_url=verification_url
        )

        if success:
            return Response(
                {'message': 'Verification email sent. Please check your inbox.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Failed to send email. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    except User.DoesNotExist:
        # Try pending email signups (do not reveal existence)
        try:
            from users.models import PendingEmailSignup

            pending = PendingEmailSignup.objects.filter(email__iexact=email).first()
            if pending:
                uid = urlsafe_base64_encode(force_bytes(pending.id))
                token = signing.dumps({'id': str(pending.id), 'email': pending.email}, salt='email-signup')
                frontend_url = _get_frontend_url(request)
                verification_url = f"{frontend_url}/verify-email/{uid}/{token}/"
                sendgrid_service.send_verification_email(
                    user_email=pending.email,
                    user_name=pending.first_name or pending.email.split('@')[0],
                    verification_url=verification_url,
                )
        except Exception:
            pass

        # Don't reveal if email exists or not (security)
        return Response(
            {'message': 'If this email exists, a verification link has been sent.'},
            status=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f'Email verification error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Verify email address",
    description="Verify user's email address using token from email",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'uid': {'type': 'string'},
                'token': {'type': 'string'}
            },
            'required': ['uid', 'token']
        }
    },
    responses={
        200: {
            'description': 'Email verified successfully',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Email verified successfully!'
                    }
                }
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([EmailVerifyConfirmRateThrottle])
def verify_email(request):
    """
    Verify email using uid and token from verification link
    """
    uid = request.data.get('uid')
    token = request.data.get('token')

    if not uid or not token:
        return Response(
            {'error': 'Invalid verification link'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Decode user ID
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)

        # Verify token
        if default_token_generator.check_token(user, token):
            user.is_verified = True
            user.save()

            welcome_email_sent = _send_welcome_email_with_retry(user)
            message = 'Email verified successfully! You can now log in.'
            if not welcome_email_sent:
                message = (
                    'Email verified successfully! You can now log in, but the '
                    'welcome email could not be sent right now.'
                )

            return Response(
                {'message': message, 'welcome_email_sent': welcome_email_sent},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Invalid or expired verification link'},
                status=status.HTTP_400_BAD_REQUEST
            )

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        pass

    # Attempt pending email signup verification
    try:
        from users.models import PendingEmailSignup, LegalAcceptance
        from django.contrib.auth import get_user_model

        pending_id = force_str(urlsafe_base64_decode(uid))
        pending = PendingEmailSignup.objects.get(pk=pending_id)

        max_age = int(getattr(settings, 'EMAIL_SIGNUP_TOKEN_TTL_SECONDS', 172800) or 172800)
        payload = signing.loads(token, salt='email-signup', max_age=max_age)
        if payload.get('id') != str(pending.id) or payload.get('email') != pending.email:
            return Response({'error': 'Invalid verification link'}, status=status.HTTP_400_BAD_REQUEST)

        UserModel = get_user_model()
        if UserModel.objects.filter(email__iexact=pending.email).exists():
            pending.delete()
            return Response({'message': 'Email already verified. You can now log in.'}, status=status.HTTP_200_OK)

        user = UserModel(
            email=pending.email,
            first_name=pending.first_name,
            middle_name=pending.middle_name,
            last_name=pending.last_name,
            phone=pending.phone,
            address=pending.address,
            is_verified=True,
        )
        user.password = pending.password_hash
        user.save()
        update_user_location_async(user.pk, pending.ip_address, include_registration=True)

        try:
            LegalAcceptance.objects.create(
                user=user,
                event=LegalAcceptance.EVENT_SIGNUP,
                documents=pending.accepted_documents or {},
                accepted=True,
                ip_address=pending.ip_address,
                user_agent=pending.user_agent or '',
                meta={'source': 'email_pending_signup'},
            )
        except Exception:
            pass

        # Best-effort: create a free subscription record for compatibility (no billing).
        try:
            from subscriptions.models import Plan, Subscription

            free_plan = Plan.objects.filter(name__iexact='free').first()
            if free_plan is not None:
                Subscription.objects.get_or_create(user=user, defaults={'plan': free_plan, 'status': 'active'})
        except Exception:
            pass

        pending.delete()

        welcome_email_sent = _send_welcome_email_with_retry(user)
        message = 'Email verified successfully! You can now log in.'
        if not welcome_email_sent:
            message = (
                'Email verified successfully! You can now log in, but the '
                'welcome email could not be sent right now.'
            )

        return Response(
            {'message': message, 'welcome_email_sent': welcome_email_sent},
            status=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f'Email verification error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Request password reset",
    description="Send password reset link to user's email",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string', 'format': 'email'}
            },
            'required': ['email']
        }
    },
    examples=[
        OpenApiExample(
            'Password Reset Request',
            value={'email': 'user@example.com'}
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PasswordResetRequestRateThrottle])
def request_password_reset(request):
    """
    Send password reset link to user's email
    """
    email = request.data.get('email')

    if not email:
        return Response(
            {'error': 'Email is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)

        # Generate reset token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Create reset URL
        frontend_url = _get_frontend_url(request)
        reset_url = f"{frontend_url}/reset-password/{uid}/{token}/"

        # Send email
        success = sendgrid_service.send_password_reset_email(
            user_email=user.email,
            user_name=user.get_full_name() or user.email.split('@')[0],
            reset_url=reset_url
        )

        if success:
            return Response(
                {'message': 'Password reset link sent. Please check your email.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Failed to send email. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    except User.DoesNotExist:
        # Don't reveal if email exists (security)
        return Response(
            {'message': 'If this email exists, a reset link has been sent.'},
            status=status.HTTP_200_OK
        )
    except Exception as e:
        logger.error(f'Password reset error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Reset password",
    description="Reset user's password using token from email",
    tags=["Authentication"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'uid': {'type': 'string'},
                'token': {'type': 'string'},
                'new_password': {'type': 'string', 'minLength': 8}
            },
            'required': ['uid', 'token', 'new_password']
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PasswordResetConfirmRateThrottle])
def reset_password(request):
    """
    Reset password using uid, token, and new password
    """
    uid = request.data.get('uid')
    token = request.data.get('token')
    new_password = request.data.get('new_password')

    if not all([uid, token, new_password]):
        return Response(
            {'error': 'Missing required fields'},
            status=status.HTTP_400_BAD_REQUEST
        )

    if len(new_password) < 8:
        return Response(
            {'error': 'Password must be at least 8 characters'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Decode user ID
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)

        # Verify token
        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()

            return Response(
                {'message': 'Password reset successfully! You can now log in.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Invalid or expired reset link'},
                status=status.HTTP_400_BAD_REQUEST
            )

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response(
            {'error': 'Invalid reset link'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f'Password reset error: {str(e)}')
        return Response(
            {'error': 'An error occurred. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
