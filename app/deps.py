from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app import crud, models, security
from app.database import get_db

# HTTPBearer (rather than OAuth2PasswordBearer) is used deliberately: this API
# issues tokens via a JSON /auth/signin endpoint, not an OAuth2 password-grant
# form. HTTPBearer makes Swagger's "Authorize" dialog just ask for a token to
# paste in (matching how the API actually works), instead of showing a
# username/password form that would POST form-data to /auth/signin and fail.
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user_and_payload(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> tuple[models.User, dict]:
    """
    Validates the access token and returns (user, decoded_payload).

    Beyond the normal signature/expiry check, this also enforces the two
    revocation mechanisms that make signout actually take effect on access
    tokens (which are otherwise stateless and can't be individually killed):
      1. a denylist of specific revoked jtis (single-session signout)
      2. a per-user "issued before X is invalid" cutoff (signout-all)
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise credentials_exception

    token = credentials.credentials

    try:
        payload = security.decode_token(token, expected_type="access")
    except security.TokenError:
        raise credentials_exception

    user_id: str | None = payload.get("sub")
    jti: str | None = payload.get("jti")
    if user_id is None or jti is None:
        raise credentials_exception

    if crud.is_access_token_revoked(db, jti):
        raise credentials_exception

    user = crud.get_user_by_id(db, user_id)
    if user is None:
        raise credentials_exception

    if user.tokens_invalid_before is not None:
        issued_at = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        cutoff = user.tokens_invalid_before.replace(tzinfo=timezone.utc)
        if issued_at < cutoff:
            raise credentials_exception

    return user, payload


def get_current_user(
    user_and_payload: tuple[models.User, dict] = Depends(get_current_user_and_payload),
) -> models.User:
    return user_and_payload[0]


def get_current_active_user(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
