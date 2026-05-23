"""
Verification service — sends 6-digit OTP codes via email (free).
Twilio SMS is still supported when TWILIO_ENABLED=True, but email is the default.
"""
import random
import string
from datetime import timedelta
import logging
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache


class PhoneVerificationService:
    """
    Verification service that sends OTP codes via email (default) or SMS (Twilio).
    Email delivery is free and requires no third-party SMS provider.
    """

    def __init__(self):
        self.use_twilio = getattr(settings, 'TWILIO_ENABLED', False)
        self.allow_dev_fallback = bool(getattr(settings, 'PHONE_VERIFICATION_FALLBACK_ENABLED', False))
        self.voice_fallback_enabled = bool(getattr(settings, 'TWILIO_VOICE_ENABLED', False))
        if self.use_twilio:
            try:
                from twilio.rest import Client
                account_sid = str(getattr(settings, 'TWILIO_ACCOUNT_SID', '') or '').strip()
                auth_token = str(getattr(settings, 'TWILIO_AUTH_TOKEN', '') or '').strip()
                from_number = str(getattr(settings, 'TWILIO_PHONE_NUMBER', '') or '').strip()

                if not account_sid or not auth_token or not from_number:
                    logging.getLogger(__name__).warning(
                        "Twilio enabled but credentials are missing; phone verification disabled"
                    )
                    self.use_twilio = False
                    return

                self.client = Client(account_sid, auth_token)
                self.from_number = from_number
                voice_from = str(getattr(settings, 'TWILIO_VOICE_FROM_NUMBER', '') or '').strip()
                self.voice_from_number = voice_from or self.from_number
            except ImportError:
                logging.getLogger(__name__).warning("Twilio SDK not installed; phone verification disabled")
                self.use_twilio = False
            except AttributeError:
                logging.getLogger(__name__).warning("Twilio credentials missing; phone verification disabled")
                self.use_twilio = False

    def generate_code(self, length=6):
        """Generate random numeric verification code"""
        return ''.join(random.choices(string.digits, k=length))

    # ------------------------------------------------------------------
    # Email OTP delivery (free — no SMS provider needed)
    # ------------------------------------------------------------------

    def send_email_code(self, email: str, code: str, user_name: str = '') -> tuple:
        """Send 6-digit OTP to an email address.

        Returns: (success: bool, message: str)
        """
        subject = 'Your BugBounty Arsenal verification code'
        body = (
            f"Your verification code is: {code}\n\n"
            "It is valid for 10 minutes.\n\n"
            "Do not share this code with anyone."
        )
        try:
            from django.core.mail import send_mail
            send_mail(
                subject=subject,
                message=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            return True, 'Verification code sent to your email.'
        except Exception:
            logging.getLogger(__name__).exception(
                "Failed sending email OTP to %s", email
            )
            return False, 'Failed to send verification email. Please try again.'

    def send_verification_code(self, user, phone_number):
        """Send a 6-digit OTP to the user's email address (free, no SMS provider needed).

        Falls back to Twilio SMS only when TWILIO_ENABLED=True and email delivery fails.
        Returns: (success: bool, code: str | None, message: str)
        """
        # Rate limiting: max 5 attempts per user per hour
        cache_key = f'otp_rate_limit_{user.pk}'
        attempts = cache.get(cache_key, 0)

        if attempts >= 5:
            return False, None, 'Rate limit exceeded. Try again in 1 hour.'

        # Generate code
        code = self.generate_code()

        # Hash the code before storing it
        from django.contrib.auth.hashers import make_password
        hashed_code = make_password(code)

        # Save to user model
        user.phone = phone_number
        user.phone_verification_code = hashed_code
        user.phone_verification_expires = timezone.now() + timedelta(minutes=10)
        user.phone_verified = False
        user.save()

        # Try email delivery first (always free)
        if user.email:
            ok, msg = self.send_email_code(user.email, code)
            if ok:
                cache.set(cache_key, attempts + 1, 3600)
                return True, None, msg

        # Optional SMS fallback via Twilio
        success, message = self._send_sms(phone_number, code)

        if success:
            # Increment rate limit counter
            cache.set(cache_key, attempts + 1, 3600)  # 1 hour
            # Never return the actual code in production responses.
            include_code = bool(
                getattr(settings, 'DEBUG', False)
                or (not self.use_twilio and self.allow_dev_fallback)
            )
            return True, (code if include_code else None), 'Verification code sent successfully'
        else:
            # Don't leave an active verification code around if delivery failed.
            try:
                user.phone_verification_code = None
                user.phone_verification_expires = None
                user.save(update_fields=['phone_verification_code', 'phone_verification_expires'])
            except Exception:
                logging.getLogger(__name__).exception("Failed clearing phone verification code after send failure")
            return False, None, message

    def _send_sms(self, phone_number, code):
        """
        Internal method to send SMS
        Returns: (success: bool, message: str)
        """
        message_text = (
            f"Your BugBounty Arsenal verification code is: {code}\n\n"
            'Valid for 10 minutes.\n\n'
            'Do not share this code with anyone.'
        )

        if self.use_twilio:
            sms_ok, sms_msg = self._send_twilio_sms(phone_number, message_text)
            if sms_ok:
                return True, sms_msg

            # If authentication failed, a voice fallback will fail too.
            if isinstance(sms_msg, str) and 'authentication failed' in sms_msg.lower():
                return False, sms_msg

            if self.voice_fallback_enabled:
                voice_ok, voice_msg = self._send_twilio_voice_call(phone_number, code)
                if voice_ok:
                    return True, voice_msg

                if sms_msg == voice_msg:
                    return False, sms_msg
                return False, f"SMS failed; voice call failed. {sms_msg} | {voice_msg}"

            return False, sms_msg

        else:
            if not self.allow_dev_fallback:
                return False, (
                    'Phone verification is not configured (Twilio disabled). '
                    'Set TWILIO_ENABLED=True and provide TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_PHONE_NUMBER, '
                    'or enable PHONE_VERIFICATION_FALLBACK_ENABLED for non-production environments.'
                )
            logging.getLogger(__name__).warning(
                "Phone verification running in development fallback mode; no SMS provider configured"
            )

            # Helpful in dev/staging: log the code (never returned to clients unless explicitly enabled).
            logging.getLogger(__name__).warning(
                "Phone verification code (fallback mode) for %s: %s",
                phone_number,
                code,
            )

            # Also send email notification if configured
            try:
                from django.core.mail import send_mail
                from django.contrib.auth import get_user_model
                User = get_user_model()

                user = User.objects.filter(phone=phone_number).first()
                if user and user.email:
                    send_mail(
                        subject='Phone Verification Code',
                        message=message_text,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
            except Exception:
                logging.getLogger(__name__).exception("Failed sending fallback verification email")

            return True, 'Verification code sent (development mode)'

    def _send_twilio_sms(self, phone_number: str, message_text: str):
        """Send SMS via Twilio."""

        try:
            try:
                from twilio.base.exceptions import TwilioRestException
            except Exception:
                TwilioRestException = None

            message = self.client.messages.create(
                body=message_text,
                from_=self.from_number,
                to=phone_number,
            )

            if getattr(message, 'sid', None):
                return True, f"SMS sent (SID: {message.sid})"
            return False, 'Failed to send SMS'
        except Exception as exc:
            # Twilio SDK raises TwilioRestException with status/code.
            try:
                from twilio.base.exceptions import TwilioRestException
                if isinstance(exc, TwilioRestException):
                    friendly = self._twilio_user_facing_error(exc)
                    if friendly is not None:
                        return False, friendly
            except Exception:
                pass
            logging.getLogger(__name__).exception("Twilio error while sending SMS")
            return False, f"Twilio SMS error: {str(exc)}"

    def _send_twilio_voice_call(self, phone_number: str, code: str):
        """Fallback: place a voice call and read the code using TwiML."""

        try:
            digits_spaced = ' '.join(list(code))
            twiml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<Response>'
                '<Say voice="alice">'
                'Your Bug Bounty Arsenal verification code is '
                f'{digits_spaced}.'
                '</Say>'
                '<Pause length="1"/>'
                '<Say voice="alice">'
                'I repeat. Your verification code is '
                f'{digits_spaced}.'
                '</Say>'
                '</Response>'
            )

            call = self.client.calls.create(
                twiml=twiml,
                from_=self.voice_from_number,
                to=phone_number,
            )

            if getattr(call, 'sid', None):
                return True, f"Voice call initiated (SID: {call.sid})"
            return False, 'Failed to initiate voice call'
        except Exception as exc:
            try:
                from twilio.base.exceptions import TwilioRestException
                if isinstance(exc, TwilioRestException):
                    friendly = self._twilio_user_facing_error(exc)
                    if friendly is not None:
                        return False, friendly
            except Exception:
                pass
            logging.getLogger(__name__).exception("Twilio error while placing voice call")
            return False, f"Twilio voice error: {str(exc)}"

    @staticmethod
    def _twilio_user_facing_error(exc):
        """Map common Twilio errors to safe, user-friendly messages."""

        status = getattr(exc, 'status', None)
        raw = str(exc)
        raw_lower = raw.lower()

        if status == 401:
            return (
                'Twilio authentication failed (401). '
                'Check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN.'
            )

        # Common case: user entered a number that is not a valid E.164 destination.
        # Example Twilio message:
        # "HTTP 400 error: Unable to create record: Invalid 'To' Phone Number: +088..."
        if status == 400 and (
            "invalid 'to' phone number" in raw_lower
            or 'you are attempting to call' in raw_lower and 'is not valid' in raw_lower
            or 'is not valid' in raw_lower
            or 'not a valid phone number' in raw_lower
        ):
            return 'Please enter a valid phone number.'

        return None

    def verify_code(self, user, code):
        """
        Verify SMS code
        Returns: (success: bool, message: str)
        """
        # Check if code exists
        if not user.phone_verification_code:
            return False, 'No verification code found. Request a new code.'

        # Check if code expired (check before comparing to avoid timing oracles on expired codes)
        if user.phone_verification_expires and timezone.now() > user.phone_verification_expires:
            return False, 'Verification code expired. Request a new code.'

        # Check if code matches using constant-time comparison (check_password)
        from django.contrib.auth.hashers import check_password
        if not check_password(code, user.phone_verification_code):
            return False, 'Invalid verification code'

        # Check if code expired
        if user.phone_verification_expires and timezone.now() > user.phone_verification_expires:
            return False, 'Verification code expired. Request a new code.'

        # Mark phone as verified
        user.phone_verified = True
        user.phone_verification_code = None
        user.phone_verification_expires = None
        user.save()

        # Clear rate limit
        cache_key = f'sms_rate_limit_{user.phone}'
        cache.delete(cache_key)

        return True, 'Phone number verified successfully'

    def resend_code(self, user):
        """
        Resend verification code to existing phone number
        Returns: (success: bool, code: str, message: str)
        """
        if not user.phone:
            return False, None, 'No phone number found'

        return self.send_verification_code(user, user.phone)

    @staticmethod
    def format_phone_number(phone, country_code='359'):
        """
        Format phone number to international format
        Examples:
            0888123456 -> +359888123456
            888123456 -> +359888123456
            +359888123456 -> +359888123456
        """
        # Remove spaces and dashes
        phone = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')

        # If starts with +, assume already formatted
        if phone.startswith('+'):
            return phone

        # If starts with 0, remove it
        if phone.startswith('0'):
            phone = phone[1:]

        # Add country code
        return f'+{country_code}{phone}'

    @staticmethod
    def validate_phone_format(phone):
        """
        Validate phone number format
        Returns: (valid: bool, message: str)
        """
        import re

        # Must start with + and contain only digits
        if not re.match(r'^\+\d{10,15}$', phone):
            return False, 'Phone number must be in international format (+XXXXXXXXXXX)'

        return True, 'Valid phone number format'

    def send_test_sms(self, phone_number):
        """
        Send test SMS (admin only)
        Returns: (success: bool, message: str)
        """
        code = self.generate_code()
        return self._send_sms(phone_number, code)
