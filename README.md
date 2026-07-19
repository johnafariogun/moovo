# User Management Service

A complete FastAPI service for signup, signin, signout, and JWT access/refresh
token handling.

## Features

- **Signup** — creates a user with a bcrypt-hashed password.
- **Signin** — verifies credentials, returns a short-lived **access token**
  and a longer-lived **refresh token**.
- **Google Sign-In** — verifies a Google-issued ID token and returns the same
  access/refresh token pair as a normal signin, creating the user (or linking
  Google to an existing password account with the same email) on first use.
- **Access tokens** — stateless JWTs, verified on every request, short expiry
  (15 min by default).
- **Refresh tokens** — JWTs whose `jti` is also stored (hashed) in the
  database. This is what makes it possible to:
  - **Rotate** tokens on every `/auth/refresh` call (old one is revoked,
    a fresh pair is issued — protects against replay of a stolen refresh
    token).
  - **Sign out** a single session (`/auth/signout`) by revoking just that
    refresh token.
  - **Sign out everywhere** (`/auth/signout-all`) by revoking all of a
    user's refresh tokens at once.
- Passwords are hashed with `bcrypt` directly (never stored or logged in
  plaintext).
- Refresh tokens are stored **hashed** (SHA-256) in the DB — a database leak
  alone doesn't hand out usable tokens.

## Project layout

```
app/
  main.py          FastAPI app, router registration, table creation
  config.py         Settings (reads from environment / .env)
  database.py       SQLAlchemy engine/session setup
  models.py         User, RefreshToken ORM models
  schemas.py        Pydantic request/response models
  security.py       Password hashing + JWT create/decode helpers
  crud.py           DB read/write helpers
  deps.py           `get_current_user` auth dependency
  routers/
    auth.py         /auth/signup, /auth/signin, /auth/google, /auth/refresh, /auth/signout, /auth/signout-all
    users.py        /users/me
requirements.txt
.env.example
docker-compose.yml   Local Postgres for development (`docker compose up -d db`)
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# then edit .env and set a real SECRET_KEY, e.g.:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Database (Postgres)

This app expects Postgres. Easiest local option, using the included
`docker-compose.yml`:

```bash
docker compose up -d db
```

That matches the default `DATABASE_URL` in `.env.example`
(`postgresql://postgres:postgres@localhost:5432/user_management`) — no
further config needed for local dev.

Using an existing/remote Postgres instead: create the database yourself and
point `DATABASE_URL` at it, e.g.
`postgresql://user:password@host:5432/dbname`. No manual schema setup is
needed — `Base.metadata.create_all()` in `main.py` creates the tables on
first run (see the migrations note below for production).

### Google Sign-In setup

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
   create an **OAuth client ID** of type **Web application**.
2. Add every origin your frontend runs on (e.g. `http://localhost:5173`,
   `https://yourapp.com`) under **Authorized JavaScript origins**. No redirect
   URI is needed — the frontend flow below never leaves the page.
3. Put the client ID in `.env` as `GOOGLE_CLIENT_ID`. This is *not* a secret
   (it's sent to the browser), but it must match exactly or token
   verification will fail.
4. Existing databases need the new `users` columns (`hashed_password`
   becoming nullable, plus `google_sub`, `google_refresh_token_encrypted`,
   `google_authorized_scopes`). Easiest for a fresh local dev database:
   `docker compose down -v && docker compose up -d db` to recreate it and let
   `create_all` rebuild the schema. In production, write a proper migration
   (see the Alembic note below) instead of dropping data.

By default the app uses a local SQLite file (`app.db`); set `DATABASE_URL` in
`.env` to point at Postgres/MySQL/etc. instead (e.g.
`postgresql://user:pass@host/dbname`, and add the matching driver like
`psycopg2-binary` to requirements.txt).

## Run

```bash
uvicorn app.main:app --reload
```

Interactive API docs: http://127.0.0.1:8000/docs

## API

| Method | Path                | Auth required          | Description                              |
|--------|---------------------|-------------------------|-------------------------------------------|
| POST   | `/auth/signup`       | —                       | Create a new user                          |
| POST   | `/auth/signin`       | —                       | Get an access + refresh token pair         |
| POST   | `/auth/google`       | —                       | Sign in/up via a Google ID token           |
| POST   | `/auth/refresh`      | refresh token in body   | Rotate: get a new access + refresh pair    |
| POST   | `/auth/signout`      | access token + body     | Revoke one refresh token (this session)    |
| POST   | `/auth/signout-all`  | access token            | Revoke all refresh tokens for the user     |
| GET    | `/users/me`          | access token            | Get the current user's profile             |
| GET    | `/health`            | —                       | Health check                               |

### Example flow

```bash
# 1. Sign up
curl -X POST localhost:8000/auth/signup -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","password":"supersecret123","full_name":"Jane Doe"}'

# 2. Sign in -> access_token + refresh_token
curl -X POST localhost:8000/auth/signin -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","password":"supersecret123"}'

# 3. Call a protected route
curl localhost:8000/users/me -H "Authorization: Bearer <access_token>"

# 4. When the access token expires, use the refresh token to get a new pair
curl -X POST localhost:8000/auth/refresh -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# 5. Sign out (revokes that refresh token; access token remains valid
#    until it naturally expires, since it's stateless)
curl -X POST localhost:8000/auth/signout -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" -d '{"refresh_token":"<refresh_token>"}'
```

### Google Sign-In flow

The backend never talks to Google directly for this flow — the **frontend**
gets an ID token from Google Identity Services, sends *that* to
`/auth/google`, and the backend verifies it and returns the usual token pair.

```html
<script src="https://accounts.google.com/gsi/client" async></script>
<div id="g_id_onload"
     data-client_id="YOUR_GOOGLE_CLIENT_ID"
     data-callback="handleGoogleSignIn">
</div>
<div class="g_id_signin" data-type="standard"></div>

<script>
  async function handleGoogleSignIn(response) {
    // response.credential is the Google ID token (a JWT)
    const res = await fetch("http://localhost:8000/auth/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id_token: response.credential }),
    });
    const { access_token, refresh_token } = await res.json();
    // store these exactly like a normal /auth/signin response
  }
</script>
```

```bash
# Backend side, once you have an id_token from the frontend above:
curl -X POST localhost:8000/auth/google -H "Content-Type: application/json" \
  -d '{"id_token":"<google_id_token>"}'
```

Account resolution on `/auth/google`:

- A user already linked to that Google account signs in as usual.
- A user with a matching **verified** email but no Google link yet gets that
  Google account linked to their existing (e.g. password-based) account.
- Otherwise a brand-new, password-less user is created.

Signed-in-with-Google users have `hashed_password = NULL`; there's currently
no "set a password" endpoint, so those accounts can only sign in via Google
unless you add one.

## Notes / production considerations

- **Access token revocation**: `/auth/signout` denylists that one access
  token's `jti` immediately; `/auth/signout-all` invalidates every access
  token issued before that moment via a per-user cutoff timestamp. This
  means every authenticated request now does a DB lookup (no longer fully
  stateless) — for high-throughput deployments, move the denylist/cutoff
  check into Redis instead of the relational DB.
- **Migrations**: `Base.metadata.create_all()` is used for simplicity. For a
  real deployment, use [Alembic](https://alembic.sqlalchemy.org/) migrations
  instead — this matters especially for Google Sign-In, since it requires
  altering `hashed_password` to be nullable and adding `google_sub`,
  `google_refresh_token_encrypted`, and `google_authorized_scopes` on an
  existing `users` table, none of which `create_all()` will do for you.
- **Connection pooling**: the default SQLAlchemy `QueuePool` (used here via
  `pool_pre_ping=True`) is fine for a single instance; for many instances
  against one Postgres server, consider PgBouncer in front of it.
- **Rate limiting**: consider adding rate limiting (e.g. `slowapi`) on
  `/auth/signin` and `/auth/signup` to slow down brute-force/enumeration
  attempts.
- **HTTPS**: always serve this over HTTPS in production — tokens are bearer
  credentials.
- **CORS**: add `CORSMiddleware` in `main.py` if this API is called from a
  browser-based frontend on a different origin.
