from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from utils.request_ip import get_client_ip


class LoginRateThrottle(AnonRateThrottle):
    scope = "login"


class SignupRateThrottle(AnonRateThrottle):
    scope = "signup"

    def get_cache_key(self, request, view):
        # Override to avoid trusting client-supplied XFF by default.
        ip = get_client_ip(request) or ""
        if not ip:
            return None
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip,
        }


class TokenRefreshRateThrottle(AnonRateThrottle):
    scope = "token_refresh"


class JwtLoginRateThrottle(AnonRateThrottle):
    scope = "jwt_login"


class EmailVerifyRequestRateThrottle(AnonRateThrottle):
    scope = "email_verify_request"


class PasswordResetRequestRateThrottle(AnonRateThrottle):
    scope = "password_reset_request"


class EmailVerifyConfirmRateThrottle(AnonRateThrottle):
    scope = "email_verify_confirm"


class PhoneVerifyConfirmAnonRateThrottle(AnonRateThrottle):
    scope = "phone_verify_confirm_anon"

    def get_cache_key(self, request, view):
        ip = get_client_ip(request) or ""
        if not ip:
            return None
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip,
        }


class PhoneVerifyResendAnonRateThrottle(AnonRateThrottle):
    scope = "phone_verify_resend_anon"

    def get_cache_key(self, request, view):
        ip = get_client_ip(request) or ""
        if not ip:
            return None
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip,
        }


class PasswordResetConfirmRateThrottle(AnonRateThrottle):
    scope = "password_reset_confirm"


class PhoneVerifySendRateThrottle(UserRateThrottle):
    scope = "phone_verify_send"


class PhoneVerifyResendRateThrottle(UserRateThrottle):
    scope = "phone_verify_resend"


class PhoneVerifyConfirmRateThrottle(UserRateThrottle):
    scope = "phone_verify_confirm"


class CompanyVerifyRateThrottle(UserRateThrottle):
    scope = "company_verify"


class CompanySearchRateThrottle(UserRateThrottle):
    scope = "company_search"
