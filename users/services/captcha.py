import logging
from typing import Optional, Tuple

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def verify_turnstile(token: str, *, remote_ip: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Verify Cloudflare Turnstile token.

    Returns:
        (ok, error_message)

    Notes:
        - This must be called server-side.
        - If TURNSTILE is disabled in settings, returns (True, None).
    """

    if not getattr(settings, 'TURNSTILE_ENABLED', False):
        return True, None

    token = str(token or '').strip()
    if not token:
        return False, (
            'Please complete the CAPTCHA. '
            'If you do not see the CAPTCHA widget, the site may need a frontend rebuild '
            '(REACT_APP_TURNSTILE_ENABLED / REACT_APP_TURNSTILE_SITE_KEY).'
        )

    secret = str(getattr(settings, 'TURNSTILE_SECRET_KEY', '') or '').strip()
    if not secret:
        # Misconfiguration: fail closed.
        return False, 'CAPTCHA is not configured. Please try again later.'

    payload = {
        'secret': secret,
        'response': token,
    }
    if remote_ip:
        payload['remoteip'] = str(remote_ip)

    try:
        timeout = float(getattr(settings, 'TURNSTILE_TIMEOUT_SECONDS', 3.0))
        verify_url = str(
            getattr(settings, 'TURNSTILE_VERIFY_URL', 'https://challenges.cloudflare.com/turnstile/v0/siteverify')
        )

        resp = requests.post(verify_url, data=payload, timeout=timeout)
        data = resp.json() if resp is not None else {}
    except Exception:
        logger.exception('Turnstile verification request failed')
        return False, 'CAPTCHA verification failed. Please try again.'

    if data.get('success') is True:
        return True, None

    # Example error codes: missing-input-response, invalid-input-response, timeout-or-duplicate
    err_codes = data.get('error-codes')
    logger.info('Turnstile verification failed', extra={'error_codes': err_codes})
    return False, 'CAPTCHA verification failed. Please try again.'
