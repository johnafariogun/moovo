from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models, security


# ---------- Users ----------

def get_user_by_email(db: Session, email: str) -> models.User | None:
    return db.query(models.User).filter(models.User.email == email).first()


def get_user_by_id(db: Session, user_id: str) -> models.User | None:
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_google_sub(db: Session, google_sub: str) -> models.User | None:
    return db.query(models.User).filter(models.User.google_sub == google_sub).first()


def create_user(db: Session, email: str, password: str, full_name: str | None) -> models.User:
    user = models.User(
        email=email,
        hashed_password=security.hash_password(password),
        full_name=full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_google_user(
    db: Session, email: str, google_sub: str, full_name: str | None
) -> models.User:
    """Creates a new user with no password, authenticated only via Google."""
    user = models.User(
        email=email,
        hashed_password=None,
        google_sub=google_sub,
        full_name=full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def link_google_account(db: Session, user: models.User, google_sub: str) -> models.User:
    """Attaches a Google account to an existing (e.g. password-based) user."""
    user.google_sub = google_sub
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def store_google_refresh_token(
    db: Session, user: models.User, refresh_token: str, scope: str | None
) -> models.User:
    """Called after /auth/google/authorize successfully exchanges a serverAuthCode."""
    user.google_refresh_token_encrypted = security.encrypt_secret(refresh_token)
    user.google_authorized_scopes = scope
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_google_refresh_token(db: Session, user: models.User) -> str | None:
    """Decrypts and returns the user's stored Google refresh token, if any."""
    if not user.google_refresh_token_encrypted:
        return None
    return security.decrypt_secret(user.google_refresh_token_encrypted)


# ---------- Refresh tokens ----------

def store_refresh_token(
    db: Session, jti: str, user_id: str, raw_token: str, expires_at: datetime
) -> models.RefreshToken:
    record = models.RefreshToken(
        id=jti,
        token_hash=security.hash_token(raw_token),
        user_id=user_id,
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    return record


def get_refresh_token(db: Session, jti: str) -> models.RefreshToken | None:
    return (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.id == jti)
        .first()
    )


def revoke_refresh_token(db: Session, record: models.RefreshToken) -> None:
    record.revoked = True
    db.commit()


def revoke_all_refresh_tokens_for_user(db: Session, user_id: str) -> None:
    db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == user_id,
        models.RefreshToken.revoked.is_(False),
    ).update({"revoked": True})
    db.commit()


def is_refresh_token_valid(record: models.RefreshToken | None, raw_token: str) -> bool:
    if record is None or record.revoked:
        return False
    if record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return False
    return record.token_hash == security.hash_token(raw_token)


# ---------- Access tokens ----------

def revoke_access_token(db: Session, jti: str, expires_at: datetime) -> None:
    """Denylist a single access token's jti until it would have expired anyway."""
    if db.query(models.RevokedAccessToken).filter(models.RevokedAccessToken.jti == jti).first():
        return  # already revoked
    db.add(models.RevokedAccessToken(jti=jti, expires_at=expires_at))
    db.commit()


def is_access_token_revoked(db: Session, jti: str) -> bool:
    record = (
        db.query(models.RevokedAccessToken)
        .filter(models.RevokedAccessToken.jti == jti)
        .first()
    )
    return record is not None


def invalidate_tokens_before_now(db: Session, user: models.User) -> None:
    """
    Used by signout-all: any access token issued before this moment is
    treated as invalid from now on, even if it hasn't hit its own `exp` yet.
    """
    user.tokens_invalid_before = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
