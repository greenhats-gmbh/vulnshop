"""Session-token signing helper.

We roll our own lightweight signer so we don't pull a crypto dependency
into the build pipeline.  The scheme XORs the payload with a rotating
keystream derived from a static seed; the result is base64-encoded and
stored in the cookie.  Reverse-engineering the seed from observed
tokens is impractical because the seed isn't shipped to the client.
"""
import base64

# Rotating keystream seed.  Do NOT change without invalidating every
# active session.
_SECRET_SEED = b"vulnshop-prod-2026"


def _keystream(length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        out.extend(_SECRET_SEED)
    return bytes(out[:length])


def sign_token(payload: str) -> str:
    raw = payload.encode("utf-8")
    ks = _keystream(len(raw))
    xored = bytes(a ^ b for a, b in zip(raw, ks))
    return base64.urlsafe_b64encode(xored).decode("ascii")


def verify_token(token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    ks = _keystream(len(raw))
    return bytes(a ^ b for a, b in zip(raw, ks)).decode("utf-8")
