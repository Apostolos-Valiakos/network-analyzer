"""
Database start-up: schema migrations, TimescaleDB and the first admin account.

Schema changes live in server/migrations (Alembic). The server applies pending
migrations on boot, under a PostgreSQL advisory lock so that several processes
starting together take turns.
"""
import logging
import os
import time
from contextlib import contextmanager
from functools import lru_cache

from flask import Flask
from werkzeug.security import generate_password_hash

import settings
from models import db, User

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = os.path.join(settings.SERVER_DIR, "migrations")

_MAX_DB_RETRIES = 12
_DB_RETRY_DELAY = 5  # seconds between attempts
_STARTUP_LOCK_ID = 7426001  # arbitrary; identifies this app's start-up lock


def configure_database(app) -> None:
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "postgresql://postgres:pass@localhost:5432/network_analyzer"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)


@lru_cache(maxsize=1)
def database_only_app():
    """An app with nothing but the database, for pipeline child processes: they
    need the role cache, not routes, and setup has already run in the parent."""
    settings.configure_logging()
    app = Flask("pipeline_worker")
    configure_database(app)
    return app


@contextmanager
def _startup_lock():
    """Lets one process at a time do start-up work. Other PostgreSQL clients are
    not blocked; the lock only coordinates processes that also take it."""
    if db.engine.dialect.name != "postgresql":
        yield
        return
    with db.engine.connect() as lock_connection:
        lock_connection.execute(db.text(f"SELECT pg_advisory_lock({_STARTUP_LOCK_ID})"))
        lock_connection.commit()
        try:
            yield
        finally:
            lock_connection.execute(db.text(f"SELECT pg_advisory_unlock({_STARTUP_LOCK_ID})"))
            lock_connection.commit()


def apply_migrations() -> None:
    """Upgrades the database to the latest migration. Needs an app context."""
    from flask_migrate import upgrade

    upgrade(directory=MIGRATIONS_DIR)


def _ensure_timescale() -> None:
    """Runs on every start, so installing TimescaleDB later takes effect on the
    next boot. Not having it is not an error."""
    if db.engine.dialect.name != "postgresql":
        return
    try:
        db.session.execute(db.text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"))
        db.session.execute(
            db.text("SELECT create_hypertable('flow_statistics', 'ts', if_not_exists => TRUE);")
        )
        db.session.commit()
        print("TimescaleDB initialized successfully.")
    except Exception as e:
        print(f"TimescaleDB warning (ensure it is installed on PG server): {e}")
        db.session.rollback()


def _seed_admin() -> None:
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    if not (username and password):
        return
    if User.query.filter_by(is_admin=True).first():
        return
    db.session.add(User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=True,
    ))
    db.session.commit()
    logger.info("Seeded admin user: %s", username)


def init_database(app) -> None:
    """Brings the database up to date, retrying while it is still starting."""
    with app.app_context():
        for attempt in range(1, _MAX_DB_RETRIES + 1):
            try:
                with _startup_lock():
                    apply_migrations()
                    _ensure_timescale()
                    _seed_admin()
                return
            except Exception as exc:
                db.session.rollback()
                if attempt == _MAX_DB_RETRIES:
                    raise RuntimeError(
                        f"Could not initialise database after {_MAX_DB_RETRIES} attempts."
                    ) from exc
                print(f"[DB] Attempt {attempt}/{_MAX_DB_RETRIES} failed: {exc}. Retrying in {_DB_RETRY_DELAY}s...")
                time.sleep(_DB_RETRY_DELAY)
