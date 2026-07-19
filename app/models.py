import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)

    # Nullable because Google-only accounts never set a password. Guard any
    # future password-based flow (e.g. "set a password") with a None check.
    hashed_password = Column(String, nullable=True)

    # Google's stable, unique per-account identifier (the ID token's "sub"
    # claim). Unique + nullable: at most one user per Google account, but
    # plenty of users will have no Google account linked at all.
    google_sub = Column(String, unique=True, index=True, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Set only after /auth/google/authorize succeeds (native-SDK serverAuthCode
    # exchange). Encrypted at rest with Fernet — a DB leak alone shouldn't
    # hand out live access to the user's Google account. Distinct from
    # google_sub/ID-token sign-in above, which never involves a refresh token.
    google_refresh_token_encrypted = Column(String, nullable=True)
    google_authorized_scopes = Column(String, nullable=True)

    # Any access token whose `iat` (issued-at) is earlier than this is treated
    # as invalid, regardless of its `exp`. Set on signout-all, since we don't
    # track individual access-token jtis for every session and so can't
    # target them one by one the way we can with a single signout.
    tokens_invalid_before = Column(DateTime(timezone=True), nullable=True)

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    """
    Server-side record of issued refresh tokens.

    We never store the raw refresh token, only a hash of it, so a leaked
    database dump can't be replayed as a valid token. Storing tokens (even
    hashed) server-side is what makes signout / revocation / rotation possible,
    since JWTs are otherwise stateless and can't be individually invalidated.
    """

    __tablename__ = "refresh_tokens"

    id = Column(String, primary_key=True, default=_uuid)  # == the token's "jti" claim
    token_hash = Column(String, nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")


class RevokedAccessToken(Base):
    """
    Denylist of individually-revoked access tokens, keyed by their `jti`.

    Access tokens are normally stateless (no DB lookup needed to validate
    one) — that's what makes them fast and what limits their default
    lifetime to a few minutes. When a single session signs out, we add that
    one token's jti here so it stops working immediately instead of quietly
    remaining valid until it naturally expires.

    `expires_at` mirrors the token's own `exp` claim, so rows can be safely
    garbage-collected once the token they refer to would have expired anyway.
    """

    __tablename__ = "revoked_access_tokens"

    jti = Column(String, primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
