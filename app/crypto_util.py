"""Authenticated token signing helper."""
import base64
import hashlib
import hmac
import os


def _key() -> bytes:
    return os.environ["TOKEN_KEY"].encode("utf-8")


def sign_token(payload: str) -> str:
    raw = payload.encode("utf-8")
    mac = hmac.new(_key(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + mac).decode("ascii")


def verify_token(token: str) -> str:
    try:
        blob = base64.b64decode(token, altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid token") from exc
    if len(blob) < 32:
        raise ValueError("invalid token")
    raw, mac = blob[:-32], blob[-32:]
    if not hmac.compare_digest(mac, hmac.new(_key(), raw, hashlib.sha256).digest()):
        raise ValueError("invalid token")
    return raw.decode("utf-8")
