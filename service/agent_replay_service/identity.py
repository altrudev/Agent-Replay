from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


class IdentityError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedIdentity:
    subject: str
    email: str | None
    email_verified: bool
    expires_at: int


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def issue_test_identity_token(
    *,
    secret: str,
    subject: str,
    email: str | None = None,
    email_verified: bool = False,
    ttl_seconds: int = 900,
    now: int | None = None,
) -> str:
    """Issue a short-lived token for local/test harnesses only."""
    current = int(time.time() if now is None else now)
    payload = {
        "sub": subject,
        "email": email,
        "email_verified": bool(email_verified),
        "exp": current + ttl_seconds,
        "iat": current,
        "typ": "agent-replay-test-identity-v1",
    }
    encoded = _b64url_encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = hmac.new(
        secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{encoded}.{_b64url_encode(signature)}"


def verify_test_identity_token(
    token: str,
    *,
    secret: str,
    now: int | None = None,
) -> VerifiedIdentity:
    try:
        encoded, supplied_sig = token.split(".", 1)
    except ValueError as exc:
        raise IdentityError("invalid identity token") from exc

    expected = hmac.new(
        secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
    ).digest()
    try:
        supplied = _b64url_decode(supplied_sig)
    except Exception as exc:
        raise IdentityError("invalid identity token signature") from exc

    if not hmac.compare_digest(expected, supplied):
        raise IdentityError("invalid identity token signature")

    try:
        payload = json.loads(_b64url_decode(encoded))
    except Exception as exc:
        raise IdentityError("invalid identity token payload") from exc

    if payload.get("typ") != "agent-replay-test-identity-v1":
        raise IdentityError("unsupported identity token type")

    current = int(time.time() if now is None else now)
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp <= current:
        raise IdentityError("identity token expired")

    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise IdentityError("identity subject missing")

    email = payload.get("email")
    if email is not None and not isinstance(email, str):
        raise IdentityError("invalid identity email")

    return VerifiedIdentity(
        subject=subject.strip(),
        email=email.strip().lower() if email else None,
        email_verified=bool(payload.get("email_verified", False)),
        expires_at=exp,
    )
