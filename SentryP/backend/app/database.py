import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
# Allow tests / alternate deployments to redirect the DB without editing code.
DB_PATH = Path(os.environ.get("SENTRY_DB_PATH", str(DATA_DIR / "barbarika.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
print(f"[DEBUG] Database path: {DB_PATH}")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    future=True,
)

@event.listens_for(engine, "connect")
def _set_wal(dbapi_connection, _):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    # Wait (up to 5s) for a competing writer instead of failing immediately with
    # "database is locked" — the dashboard/benchmark read /events while the agent
    # is writing, and WAL alone does not serialize concurrent writers.
    cursor.execute("PRAGMA busy_timeout=5000;")
    # WAL + NORMAL is the durable-enough, much faster commit mode for the demo.
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

Base = declarative_base()
