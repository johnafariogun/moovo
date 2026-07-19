from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings, loaded from environment variables / a .env file.
    See .env.example for the full list of variables.
    """

    # Postgres, e.g. postgresql://user:password@localhost:5432/user_management
    # (add the driver to requirements.txt if you swap it, e.g. psycopg2-binary
    # is already included below).
    database_url: str = "postgresql://postgres:postgres@localhost:5432/user_management"

    secret_key: str = "insecure-dev-secret-change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # OAuth Client ID from Google Cloud Console (Credentials -> OAuth 2.0
    # Client IDs, type "Web application"). Used both to verify that Google ID
    # tokens presented to /auth/google were issued for *this* app (the "aud"
    # claim check), and as the client_id when exchanging a serverAuthCode.
    google_client_id: str = ""

    # That same Web application client's secret. Only needed for
    # /auth/google/authorize (exchanging a native-SDK serverAuthCode for a
    # Google refresh token) — the plain /auth/google ID-token flow never
    # needs it. Never sent to any frontend.
    google_client_secret: str = ""

    # Fernet key (Fernet.generate_key()) used to encrypt Google refresh
    # tokens before they're stored in the DB. Required only if you use
    # /auth/google/authorize.
    google_token_encryption_key: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
