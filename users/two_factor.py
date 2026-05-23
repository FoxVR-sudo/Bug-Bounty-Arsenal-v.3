from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterable, List, Optional

import pyotp
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password


DEFAULT_ISSUER = getattr(settings, "TWO_FACTOR_ISSUER", "BugBounty Arsenal")


@dataclass(frozen=True)
class TwoFactorVerifyResult:
    ok: bool
    used_backup_code: bool = False
    backup_code_index: Optional[int] = None


def generate_totp_secret() -> str:
    # pyotp.random_base32() returns a base32 string (typically length 32)
    return pyotp.random_base32()


def build_provisioning_uri(*, email: str, secret: str, issuer: str = DEFAULT_ISSUER) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I


def _format_backup_code(code: str) -> str:
    # ABCDE-FGHIJ style
    return f"{code[:5]}-{code[5:]}" if len(code) > 5 else code


def generate_backup_codes(count: int = 10, length: int = 10) -> List[str]:
    if count <= 0:
        return []
    if length < 8:
        length = 8

    codes: List[str] = []
    for _ in range(count):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(length))
        codes.append(_format_backup_code(raw))
    return codes


def _normalize_code(code: str) -> str:
    return (code or "").replace("-", "").strip().upper()


def hash_backup_codes(codes: Iterable[str]) -> List[str]:
    return [make_password(_normalize_code(c)) for c in codes]


def verify_totp_code(*, secret: str, code: str, valid_window: int = 1) -> bool:
    if not secret:
        return False
    normalized = _normalize_code(code)
    if not normalized:
        return False
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(normalized, valid_window=valid_window))


def verify_backup_code(*, hashed_codes: List[str], code: str) -> Optional[int]:
    """Returns index of matching backup code, else None."""
    normalized = _normalize_code(code)
    if not normalized:
        return None

    for idx, hashed in enumerate(hashed_codes or []):
        if check_password(normalized, hashed):
            return idx
    return None


def verify_two_factor(*, secret: str, backup_codes: List[str], code: str) -> TwoFactorVerifyResult:
    if verify_totp_code(secret=secret, code=code):
        return TwoFactorVerifyResult(ok=True, used_backup_code=False)

    idx = verify_backup_code(hashed_codes=backup_codes or [], code=code)
    if idx is not None:
        return TwoFactorVerifyResult(ok=True, used_backup_code=True, backup_code_index=idx)

    return TwoFactorVerifyResult(ok=False)
