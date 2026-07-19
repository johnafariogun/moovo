from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import crud, schemas, security
from app.database import get_db
from app.deps import get_current_user, get_current_user_and_payload
from app.models import User
from ..utils.logger import logger
router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_token_pair(db: Session, user: User) -> schemas.TokenPair:
    logger.info(f"Issuing new token pair for user_id={user.id}")
    access_token = security.create_access_token(user.id)
    logger.info(f"Access token created for user_id={user.id}")
    refresh_token, jti, expires_at = security.create_refresh_token(user.id)
    logger.info(f"Refresh token created for user_id={user.id}")
    crud.store_refresh_token(db, jti, user.id, refresh_token, expires_at)
    logger.info(f"Refresh token stored for user_id={user.id}")

    return schemas.TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post("/signup", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def signup(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, payload.email)
    if user:
        logger.warning(f"Attempt to sign up with existing email: {payload.email}")
    
        if user.google_sub is not None:
            # User previously signed up with Google SSO
            logger.warning(f"Email {payload.email} is associated with a Google account; cannot sign up with password")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is associated with a Google account. Please sign in with Google.",
            )
 
        else:
            logger.warning(f"Email {payload.email} is already registered; cannot sign up again")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email already exists",
            )
    logger.info(f"Creating new user with email: {payload.email}")
    user = crud.create_user(db, payload.email, payload.password, payload.full_name)
    logger.info(f"User created with email: {payload.email}")
    return user


@router.post("/signin", response_model=schemas.TokenPair)
def signin(payload: schemas.SignInRequest, db: Session = Depends(get_db)):
    logger.info(f"Attempting to sign in user with email: {payload.email}")
    user = crud.get_user_by_email(db, payload.email)
    if user is None or not security.verify_password(payload.password, user.hashed_password):
        logger.warning(f"Failed sign-in attempt for email: {payload.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if not user.is_active:
        logger.warning(f"Attempt to sign in inactive user: {payload.email}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    logger.info(f"User signed in successfully: {payload.email}")
    return _issue_token_pair(db, user)


@router.post("/google", response_model=schemas.TokenPair)
def google_signin(payload: schemas.GoogleSignInRequest, db: Session = Depends(get_db)):
    """
    Signs in (or transparently signs up) a user via a Google ID token.

    The frontend obtains this ID token from Google Identity Services — this
    endpoint never sees the user's Google password, and no separate OAuth
    "code exchange" is needed since ID tokens are verified directly.

    Account resolution, in order:
      1. A user already linked to this Google account (google_sub) -> use it.
      2. No link yet, but an existing user shares this (verified) email
         -> link this Google account to it (covers "signed up with a
         password first, now using 'Sign in with Google'").
      3. Neither -> create a brand new Google-only user (no password set).
    """
    logger.info("Attempting Google sign-in")
    try:
        logger.info("Verifying Google ID token")
        claims = security.verify_google_id_token(payload.id_token)
        logger.info("Google ID token verified successfully")
    except security.GoogleTokenError:

        logger.warning("Failed to verify Google ID token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired Google ID token"
        )

    google_sub = claims["sub"]
    email = claims.get("email")
    email_verified = claims.get("email_verified", False)

    if not email or not email_verified:
        # Google lets some accounts (e.g. unverified custom-domain emails)
        # through without verification; we require it since we're about to
        # trust this email for account matching / as the account's identity.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account has no verified email",
        )

    user = crud.get_user_by_google_sub(db, google_sub)

    if user is None:
        existing = crud.get_user_by_email(db, email)
        if existing is not None:
            user = crud.link_google_account(db, existing, google_sub)
        else:
            user = crud.create_google_user(db, email, google_sub, claims.get("name"))

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    logger.info(f"Google sign-in successful for user_id={user.id}")
    return _issue_token_pair(db, user)


@router.post("/google/authorize", response_model=schemas.GoogleAuthorizeResponse)
def google_authorize(
    payload: schemas.GoogleAuthorizeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Exchanges a one-time serverAuthCode — obtained natively on Android via a
    separate AuthorizationClient request, or on iOS alongside the ID token —
    for a Google refresh token, and stores it (encrypted) against the
    *currently signed-in* user.

    This is deliberately a separate step from /auth/google: that endpoint
    only ever sees an ID token and can't grant API access, while this one
    requires our own access token so a stolen/leaked serverAuthCode can't be
    used to attach Google API access to an attacker-controlled account.
    """
    try:
        token_response = security.exchange_google_server_auth_code(payload.server_auth_code)
    except security.GoogleTokenError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    refresh_token = token_response.get("refresh_token")
    scope = token_response.get("scope")

    if not refresh_token:
        # Google omits refresh_token if this user already granted these
        # scopes before and the client didn't force re-consent (Android:
        # forceCodeForRefreshToken(true); iOS: re-prompting). Nothing new to
        # persist, but this isn't an error — they may already have one stored.
        return schemas.GoogleAuthorizeResponse(granted=False, scope=scope)

    crud.store_google_refresh_token(db, current_user, refresh_token, scope)
    return schemas.GoogleAuthorizeResponse(granted=True, scope=scope)


@router.post("/refresh", response_model=schemas.TokenPair)
def refresh(payload: schemas.RefreshRequest, db: Session = Depends(get_db)):
    """
    Exchanges a valid, non-revoked refresh token for a brand new access +
    refresh token pair. The old refresh token is revoked immediately
    (rotation), so each refresh token can only be used once.
    """
    try:
        claims = security.decode_token(payload.refresh_token, expected_type="refresh")
    except security.TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    jti = claims.get("jti")
    user_id = claims.get("sub")
    record = crud.get_refresh_token(db, jti) if jti else None

    if not crud.is_refresh_token_valid(record, payload.refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    user = crud.get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Rotate: revoke the used refresh token, then issue a fresh pair.
    crud.revoke_refresh_token(db, record)
    return _issue_token_pair(db, user)


@router.post("/signout", status_code=status.HTTP_204_NO_CONTENT)
def signout(
    payload: schemas.SignOutRequest,
    db: Session = Depends(get_db),
    user_and_payload: tuple[User, dict] = Depends(get_current_user_and_payload),
):
    """
    Signs out the current session by revoking BOTH the refresh token given in
    the body and the access token used to authenticate this very request.
    Requires a valid access token so an attacker can't revoke tokens they
    don't own just by guessing/stealing a refresh token string.
    """
    current_user, access_claims = user_and_payload
    logger.info(f"Attempting to sign out user_id={current_user.id}")
    # Revoke the access token used to call this endpoint, so it stops working
    # immediately instead of remaining valid until it naturally expires.
    access_jti = access_claims.get("jti")
    access_exp = access_claims.get("exp")
    if access_jti and access_exp:
        crud.revoke_access_token(
            db, access_jti, datetime.fromtimestamp(access_exp, tz=timezone.utc)
        )

    # Revoke the refresh token supplied in the body.
    try:
        refresh_claims = security.decode_token(payload.refresh_token, expected_type="refresh")
    except security.TokenError:
        # Already invalid/expired -> effectively signed out already.
        return

    if refresh_claims.get("sub") != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token does not belong to this user")

    refresh_jti = refresh_claims.get("jti")
    record = crud.get_refresh_token(db, refresh_jti) if refresh_jti else None
    if record is not None:
        crud.revoke_refresh_token(db, record)


@router.post("/signout-all", status_code=status.HTTP_204_NO_CONTENT)
def signout_all(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revokes every refresh token for the current user, and invalidates every
    access token issued before this moment (all devices/sessions).

    We don't track every access token's jti individually, so instead of a
    denylist we use a per-user cutoff timestamp: any access token whose
    `iat` predates it is rejected, no matter its own `exp`.
    """
    crud.revoke_all_refresh_tokens_for_user(db, current_user.id)
    crud.invalidate_tokens_before_now(db, current_user)
