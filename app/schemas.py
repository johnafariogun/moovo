from datetime import datetime

from pydantic import BaseModel, EmailStr, ConfigDict, Field


# ---------- Users ----------

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    full_name: str | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    full_name: str | None
    is_active: bool
    created_at: datetime


# ---------- Auth ----------

class SignInRequest(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class AccessTokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SignOutRequest(BaseModel):
    refresh_token: str


class GoogleSignInRequest(BaseModel):
    # The ID token returned to the frontend by Google Identity Services
    # (google.accounts.id.initialize / renderButton, or the One Tap prompt).
    # This is a JWT signed by Google, NOT an OAuth access token.
    id_token: str


class GoogleAuthorizeRequest(BaseModel):
    # A one-time code from a native SDK: Android's separate AuthorizationClient
    # API, or iOS's GIDSignIn (which returns it alongside the ID token). This
    # is what /auth/google/authorize exchanges for a Google refresh token.
    server_auth_code: str


class GoogleAuthorizeResponse(BaseModel):
    # False if Google didn't include a refresh_token in the exchange — it
    # only issues one the first time a user grants a given scope set, so a
    # repeat authorize() with no new scopes can legitimately return nothing
    # new to store.
    granted: bool
    scope: str | None = None
