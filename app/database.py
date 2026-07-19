from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

# `check_same_thread` is only relevant for SQLite; harmless to guard for
# other DBs. This app defaults to Postgres, but the guard is kept so you can
# still point DATABASE_URL at a local sqlite file for quick manual testing
# without standing up a real Postgres instance.
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

# pool_pre_ping issues a cheap "SELECT 1" before handing out a pooled
# connection, so a connection Postgres (or a proxy/load balancer in front of
# it) silently closed while idle gets transparently replaced instead of
# surfacing as an `OperationalError` on the next real query.
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
