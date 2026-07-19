from fastapi import FastAPI

from app.database import Base, engine
from app.routers import auth, users

# In production, use Alembic migrations instead of create_all.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="User Management Service",
    description="Signup, signin, signout, and JWT access/refresh token handling.",
    version="1.0.0",
)

app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok"}
