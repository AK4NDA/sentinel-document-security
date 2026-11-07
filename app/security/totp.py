"""TOTP secret handling and code verification (spec 0004)."""

import hmac
import time
from datetime import UTC, datetime
from urllib.parse import quote

import pyotp
import segno

from app.core.config import get_settings
from app.security.encryption import open_blob, seal

STEP_SECONDS = 30
CODE_DIGITS = 6


def generate_secret() -> str:
    return pyotp.random_base32()


def seal_secret(secret: str) -> bytes:
    return seal(secret.encode("utf-8"))


def open_secret(blob: bytes) -> str:
    return open_blob(blob).decode("utf-8")


def provisioning_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=quote(username, safe=""),
        issuer_name=get_settings().totp_issuer,
    )


def qr_svg(uri: str) -> str:
    return segno.make(uri, error="m").svg_inline()


def verify_code(secret: str, code: str, last_counter: int | None) -> int | None:
    """Return the matched time step counter, or None if invalid or replayed."""
    if not code.isdigit() or len(code) != CODE_DIGITS:
        return None
    totp = pyotp.TOTP(secret)
    now_counter = int(time.time() // STEP_SECONDS)
    skew = get_settings().totp_skew_steps
    for step in range(now_counter - skew, now_counter + skew + 1):
        if step < 0:
            continue
        expected = totp.at(for_time=datetime.fromtimestamp(step * STEP_SECONDS, UTC))
        if hmac.compare_digest(expected, code):
            if last_counter is not None and step <= last_counter:
                return None
            return step
    return None
