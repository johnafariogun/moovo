import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import bcrypt
import requests
from cryptography.fernet import Fernet, InvalidToken
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from jose import JWTError, jwt

from app.config import settings
from app.utils.logger import logger

GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

# Reused across requests: internally this caches Google's public signing
# certs (and refetches them once they rotate/expire), so building a fresh
# one per call would throw away that caching for no benefit.
_google_request = google_requests.Request()

# bcrypt has a hard 72-byte input limit; truncate defensively so unusually
# long passwords fail closed with a clear error instead of raising deep
# inside the library.
_BCRYPT_MAX_BYTES = 72


def _prepare(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if len(encoded) > _BCRYPT_MAX_BYTES:
        raise ValueError("Password must be 72 bytes or fewer once UTF-8 encoded")
    return encoded


# ---------- Passwords ----------

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(_prepare(password), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(plain_password), hashed_password.encode("utf-8"))
    except ValueError:
        return False


# ---------- JWT helpers ----------

class TokenError(Exception):
    """Raised when a token is missing, malformed, expired, or the wrong type."""


def _create_token(
    subject: str,
    token_type: Literal["access", "refresh"],
    expires_delta: timedelta,
    jti: str | None = None,
) -> tuple[str, str, datetime]:
    now = datetime.now(timezone.utc)
    expire = now + expires_delta
    jti = jti or str(uuid.uuid4())
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": expire,
        "jti": jti,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
    return token, jti, expire


def create_access_token(user_id: str) -> str:
    token, _, _ = _create_token(
        user_id, "access", timedelta(minutes=settings.access_token_expire_minutes)
    )
    return token


def create_refresh_token(user_id: str) -> tuple[str, str, datetime]:
    """Returns (token, jti, expires_at). Caller persists jti/expiry server-side."""
    return _create_token(
        user_id, "refresh", timedelta(days=settings.refresh_token_expire_days)
    )


def decode_token(token: str, expected_type: Literal["access", "refresh"]) -> dict:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError as exc:
        raise TokenError("Invalid or expired token") from exc

    if payload.get("type") != expected_type:
        raise TokenError(f"Expected a {expected_type} token")

    return payload


# ---------- Google Sign-In ----------

class GoogleTokenError(Exception):
    """Raised when a Google ID token is missing, malformed, expired, or not for this app."""


def verify_google_id_token(id_token_str: str) -> dict:
    """
    Verifies a Google-issued ID token (JWT) and returns its decoded claims.

    This checks the token's signature against Google's public certs, that it
    hasn't expired, and — critically — that its `aud` claim matches our own
    OAuth client ID, so a token issued for some *other* app can't be replayed
    here. Useful claims on success: `sub` (Google's stable user id), `email`,
    `email_verified`, `name`, `picture`.
    """
    if not settings.google_client_id:
        logger.error("GOOGLE_CLIENT_ID is not set; cannot verify Google ID token")
        raise GoogleTokenError("Google sign-in is not configured (GOOGLE_CLIENT_ID is unset)")

    try:
        # logger.info("Verifying Google ID token")
        logger.addFilter(lambda record: "Verifying Google ID token" in record.getMessage())
        claims = google_id_token.verify_oauth2_token(
            id_token_str, _google_request, audience=settings.google_client_id
        )
        logger.info("Google ID token verified successfully")
    except ValueError as exc:
        # google-auth raises ValueError for a malformed/invalid/expired
        # token, but also raises google.auth.exceptions.* (e.g.
        # TransportError) if it can't reach Google's cert endpoint. Both are
        # "this attempt failed", so both come back as one clean 401 rather
        # than leaking a raw 500.
        logger.warning("Failed to verify Google ID token")
        raise GoogleTokenError("Invalid or expired Google ID token") from exc
    except Exception as exc:
        logger.error("Unexpected error occurred while verifying Google ID token")
        raise GoogleTokenError("Invalid or expired Google ID token") from exc

    # verify_oauth2_token already checks iss is accounts.google.com /
    # https://accounts.google.com, but double-check defensively since this
    # claim is what stops a token from an unrelated Google-verified issuer
    # (there are none here, but this keeps the check explicit and cheap).
    if claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        logger.warning(f"Invalid token issuer: {claims.get('iss')}")
        raise GoogleTokenError("Invalid token issuer")


    logger.info(f"Google ID token claims: {claims}")
    return claims


def exchange_google_server_auth_code(server_auth_code: str) -> dict:
    """
    Exchanges a one-time serverAuthCode (from a native SDK's separate
    authorization step) for Google tokens. Unlike verify_google_id_token,
    this hits Google's network token endpoint directly and requires our
    client_secret, since it's proving *our backend's* identity to Google, not
    just checking a signature.

    Returns Google's raw JSON response, notably: access_token, expires_in,
    scope, and — only on first consent for these scopes — refresh_token.
    """
    logger.info("Exchanging Google serverAuthCode for tokens")
    if not settings.google_client_id or not settings.google_client_secret:
        logger.error("GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET is not set; cannot exchange serverAuthCode")
        raise GoogleTokenError(
            "Google authorization is not configured "
            "(GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are unset)"
        )

    try:
        logger.info("Sending request to Google's token endpoint")
        response = requests.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "code": server_auth_code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "grant_type": "authorization_code",
                # Deliberately empty: this is the "serverAuthCode from a
                # native SDK" flavor of the exchange, which (unlike a normal
                # web authorization-code flow) was never associated with a
                # redirect_uri in the first place.
                "redirect_uri": "",
            },
            timeout=10,
        )
        logger.info(f"Received response from Google's token endpoint: {response.status_code}")
    except requests.RequestException as exc:
        logger.error("Failed to reach Google's token endpoint")
        raise GoogleTokenError("Could not reach Google's token endpoint") from exc

    if response.status_code != 200:
        # Most common cause: an expired/already-used code (they're single-use
        # and short-lived) or a client_id/client_secret mismatch.
        logger.error(f"Google token exchange failed: {response.text}")
        raise GoogleTokenError(f"Google token exchange failed: {response.text}")
    logger.info("Google token exchange successful")
    return response.json()


def encrypt_secret(raw: str) -> str:
    return _get_fernet().encrypt(raw.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str) -> str:
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise TokenError("Could not decrypt stored secret") from exc


_fernet_instance: Fernet | None = None


def _get_fernet() -> Fernet:
    """Lazily built: only needed once /auth/google/authorize is actually used."""
    global _fernet_instance
    if _fernet_instance is None:
        if not settings.google_token_encryption_key:
            raise GoogleTokenError(
                "GOOGLE_TOKEN_ENCRYPTION_KEY is not configured "
                "(generate one with Fernet.generate_key())"
            )
        _fernet_instance = Fernet(settings.google_token_encryption_key.encode("utf-8"))
    return _fernet_instance


def hash_token(token: str) -> str:
    """
    One-way hash used to store refresh tokens in the DB, so a DB leak alone
    doesn't hand out valid tokens. SHA-256 (not bcrypt) is fine here since the
    input is already a high-entropy random JWT, not a low-entropy password.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
