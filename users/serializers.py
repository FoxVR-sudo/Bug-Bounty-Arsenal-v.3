from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.conf import settings
from .models import User
from .models import LegalAcceptance
from utils.request_ip import get_client_ip
import logging

logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model with read-only password field"""

    two_factor_enabled = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'is_admin',
                  'two_factor_enabled',
                  'date_joined', 'last_login', 'is_active', 'is_staff',
                  'address', 'company_country',
                  'last_seen_city', 'last_seen_country']
        read_only_fields = ['id', 'date_joined', 'last_login', 'last_seen_city', 'last_seen_country']


class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new users with password validation"""
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    accept_terms = serializers.BooleanField(write_only=True, required=True)
    accept_privacy = serializers.BooleanField(write_only=True, required=True)
    accept_disclaimer = serializers.BooleanField(write_only=True, required=True)
    accept_aup = serializers.BooleanField(write_only=True, required=True)

    class Meta:
        model = User
        fields = [
            'email',
            'password',
            'password_confirm',
            'first_name',
            'middle_name',
            'last_name',
            'phone',
            'address',
            'accept_terms',
            'accept_privacy',
            'accept_disclaimer',
            'accept_aup',
        ]

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        required_acceptances = {
            'accept_terms': 'Terms of Service',
            'accept_privacy': 'Privacy Policy',
            'accept_disclaimer': 'Disclaimer',
            'accept_aup': 'Acceptable Use Policy',
        }
        missing = [label for key, label in required_acceptances.items() if not attrs.get(key, False)]
        if missing:
            raise serializers.ValidationError(
                {
                    'legal': f"You must accept: {', '.join(missing)}."
                }
            )
        return attrs

    def _get_request_ip(self):
        request = self.context.get('request') if isinstance(self.context, dict) else None
        if not request:
            return None

        return get_client_ip(request)

    def _get_request_user_agent(self):
        request = self.context.get('request') if isinstance(self.context, dict) else None
        if not request:
            return ''
        return request.META.get('HTTP_USER_AGENT', '') or ''

    def create(self, validated_data):
        validated_data.pop('password_confirm')

        # Pop legal acceptance flags (used only for audit/enforcement)
        validated_data.pop('accept_terms', None)
        validated_data.pop('accept_privacy', None)
        validated_data.pop('accept_disclaimer', None)
        validated_data.pop('accept_aup', None)

        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            middle_name=validated_data.get('middle_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone=validated_data.get('phone', ''),
            address=validated_data.get('address', '')
        )

        # Best-effort: send verification email after signup.
        # Do not block signup if email delivery fails.
        try:
            request = self.context.get('request') if isinstance(self.context, dict) else None
            if request and hasattr(user, 'is_verified') and not bool(getattr(user, 'is_verified', False)):
                from django.utils.http import urlsafe_base64_encode
                from django.utils.encoding import force_bytes
                from django.contrib.auth.tokens import default_token_generator
                from urllib.parse import urlsplit
                from utils.sendgrid_service import sendgrid_service

                origin = str(request.headers.get('Origin', '') or '').strip()
                configured = str(getattr(settings, 'FRONTEND_URL', '') or '').strip()

                frontend_url = ''
                if configured:
                    if origin:
                        try:
                            cfg = urlsplit(configured)
                            org = urlsplit(origin)
                            if (
                                cfg.scheme
                                and cfg.netloc
                                and org.scheme
                                and org.netloc
                                and cfg.netloc != org.netloc
                            ):
                                frontend_url = origin.rstrip('/')
                        except Exception:
                            pass
                    if not frontend_url:
                        frontend_url = configured.rstrip('/')
                elif origin:
                    frontend_url = origin.rstrip('/')
                else:
                    frontend_url = f"{request.scheme}://{request.get_host()}".rstrip('/')

                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                verification_url = f"{frontend_url}/verify-email/{uid}/{token}/"
                sendgrid_service.send_verification_email(
                    user_email=user.email,
                    user_name=user.get_full_name() or user.email.split('@')[0],
                    verification_url=verification_url,
                )
        except Exception:
            logger.exception(
                'Failed to send verification email to %s after signup', user.email
            )

        try:
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
                ip_address=self._get_request_ip(),
                user_agent=self._get_request_user_agent(),
                meta={
                    'path': getattr(
                        self.context.get('request'),
                        'path',
                        None) if isinstance(
                        self.context,
                        dict) else None,
                },
            )
        except Exception:
            # Best-effort audit trail; do not block signup if logging fails.
            pass

        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile"""

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing user password"""
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user
