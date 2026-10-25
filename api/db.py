"""Small DB-API adapter with PostgreSQL as the deployed source of truth.

SQLite is available for local development and isolated tests. Production refuses it.
"""
from contextlib import contextmanager
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from . import settings

MIGRATIONS = Path(__file__).parent / "migrations"


class Connection:
    def __init__(self, raw, dialect):
        self.raw = raw
        self.dialect = dialect

    def execute(self, sql, params=()):
        if self.dialect == "postgres":
            from psycopg.rows import dict_row
            return self.raw.execute(sql.replace("?", "%s"), params)
        return self.raw.execute(sql, params)

    def one(self, sql, params=()):
        row = self.execute(sql, params).fetchone()
        return dict(row) if row is not None and self.dialect == "sqlite" else row

    def all(self, sql, params=()):
        rows = self.execute(sql, params).fetchall()
        return [dict(row) for row in rows] if self.dialect == "sqlite" else rows


def _connect():
    url = settings.DATABASE_URL
    if not url:
        raise RuntimeError("DATABASE_URL is required. Set it to PostgreSQL; tests may use a temporary SQLite database.")
    if url.startswith("sqlite:"):
        if settings.APP_ENV == "production":
            raise RuntimeError("SQLite is disabled in production; configure PostgreSQL.")
        db_path = url.removeprefix("sqlite:///")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        raw = sqlite3.connect(db_path, timeout=10)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys=ON")
        raw.execute("PRAGMA journal_mode=WAL")
        return Connection(raw, "sqlite")
    if url.startswith(("postgres://", "postgresql://")):
        import psycopg
        from psycopg.rows import dict_row
        raw = psycopg.connect(url, row_factory=dict_row)
        return Connection(raw, "postgres")
    raise RuntimeError("DATABASE_URL must use postgresql:// or sqlite:/// for isolated development tests.")


@contextmanager
def transaction():
    conn = _connect()
    try:
        yield conn
        conn.raw.commit()
    except Exception:
        conn.raw.rollback()
        raise
    finally:
        conn.raw.close()


def migrate():
    with transaction() as conn:
        if conn.dialect == "postgres":
            conn.execute("SELECT pg_advisory_xact_lock(721553260241)")
        else:
            # The preview API and background worker can start together. Take
            # SQLite's write lock before reading the migration ledger so only
            # one process applies a pending migration.
            conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {row["version"] if isinstance(row, dict) else row[0] for row in conn.all("SELECT version FROM schema_migrations")}
        for path in sorted(MIGRATIONS.glob("*.sql")):
            version = path.name.split("_", 1)[0]
            if version in applied:
                continue
            for statement in path.read_text(encoding="utf-8").split(";"):
                if statement.strip():
                    conn.execute(statement)
            conn.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", (version, datetime.now(timezone.utc).isoformat()))
