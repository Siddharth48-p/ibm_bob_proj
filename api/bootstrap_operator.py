"""Create the first operator from one-time environment credentials."""
import os

from . import db
from .main import stamp, uid, _audit
from .security import password_hash


def main():
    email = os.getenv("BOOTSTRAP_OPERATOR_EMAIL", "").strip().lower()
    password = os.getenv("BOOTSTRAP_OPERATOR_PASSWORD", "")
    if not email or len(password) < 12:
        raise SystemExit("Set BOOTSTRAP_OPERATOR_EMAIL and a unique 12+ character BOOTSTRAP_OPERATOR_PASSWORD first.")
    db.migrate()
    ident = uid()
    with db.transaction() as conn:
        if conn.one("SELECT id FROM users WHERE role='operator' LIMIT 1"):
            raise SystemExit("An operator already exists; bootstrap will not create or reset accounts.")
        conn.execute("INSERT INTO users(id,email,password_hash,role,created_at) VALUES(?,?,?,'operator',?)", (ident,email,password_hash(password),stamp()))
        _audit(conn, ident, "operator_bootstrapped", "user", ident)
    print("Initial operator account created. Remove BOOTSTRAP_OPERATOR_PASSWORD from the environment now.")


if __name__ == "__main__":
    main()
