"""
Schema migrations against every kind of database the old start-up code could
have left behind. Runs on SQLite, and also on PostgreSQL when
PENM_TEST_POSTGRES_URL points at a throwaway database whose name contains
"test" (its public schema is wiped before each test).
"""

import os
import sys

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from flask import Flask
from flask_migrate import Migrate

_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

import db_setup
from models import db as _db, User

ALL_TABLES = {
    "users", "pcap_files", "flow_statistics", "role_snapshots",
    "ip_roles", "ue_sessions", "cluster_results",
}
_POSTGRES_URL = os.environ.get("PENM_TEST_POSTGRES_URL")
_BACKENDS = ["sqlite"] + (["postgresql"] if _POSTGRES_URL else [])


def _wipe_postgres(url):
    name = sa.engine.make_url(url).database
    assert "test" in name, f"refusing to wipe database {name!r}"
    engine = sa.create_engine(url)
    with engine.begin() as connection:
        connection.execute(sa.text("DROP SCHEMA public CASCADE"))
        connection.execute(sa.text("CREATE SCHEMA public"))
    engine.dispose()


@pytest.fixture(params=_BACKENDS)
def migration_app(request, tmp_path, monkeypatch):
    if request.param == "postgresql":
        url = _POSTGRES_URL
        _wipe_postgres(url)
    else:
        url = "sqlite:///" + str(tmp_path / "migrate.db").replace("\\", "/")
    monkeypatch.setenv("DATABASE_URL", url)

    app = Flask("migration_test")
    db_setup.configure_database(app)
    Migrate(app, _db, directory=db_setup.MIGRATIONS_DIR)
    with app.app_context():
        yield app
        _db.session.remove()
        _db.engine.dispose()


def _tables():
    return set(sa.inspect(_db.engine).get_table_names())


def _columns(table):
    return {c["name"] for c in sa.inspect(_db.engine).get_columns(table)}


def _version():
    with _db.engine.connect() as connection:
        return connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


def _head():
    script = ScriptDirectory(db_setup.MIGRATIONS_DIR)
    heads = script.get_heads()
    assert len(heads) == 1, f"migrations have diverged: {heads}"
    return heads[0]


def _execute(*statements):
    with _db.engine.begin() as connection:
        for statement in statements:
            connection.execute(sa.text(statement))


def test_empty_database_gets_the_whole_schema(migration_app):
    db_setup.apply_migrations()
    assert ALL_TABLES <= _tables()
    assert _version() == _head()


def test_models_match_the_migrations(migration_app):
    """Fails when a model changes without a migration."""
    db_setup.apply_migrations()
    with _db.engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        differences = compare_metadata(context, _db.metadata)
    assert differences == []


def test_database_created_by_the_old_startup_code_keeps_its_rows(migration_app):
    """Up-to-date tables with no alembic_version: the state of every current install."""
    _db.create_all()
    _db.session.add(User(username="existing", password_hash="h", is_admin=True))
    _db.session.commit()

    db_setup.apply_migrations()

    assert _version() == _head()
    assert User.query.filter_by(username="existing").one().is_admin is True


def test_older_database_gets_missing_columns_and_keeps_rows(migration_app):
    _execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(80) UNIQUE NOT NULL, "
        "password_hash VARCHAR(128) NOT NULL, created_at TIMESTAMP)",
        "CREATE TABLE pcap_files (id VARCHAR(36) PRIMARY KEY, user_id INTEGER REFERENCES users(id), "
        "filename VARCHAR(255) UNIQUE NOT NULL, original_filename VARCHAR(255), "
        "file_path VARCHAR(512) NOT NULL, file_size BIGINT, upload_time TIMESTAMP, status VARCHAR(50))",
        "CREATE TABLE ip_roles (id INTEGER PRIMARY KEY, pcap_id VARCHAR(36) NOT NULL REFERENCES pcap_files(id), "
        "ip_address VARCHAR(45) NOT NULL, role VARCHAR(100), confidence FLOAT, reasoning TEXT)",
        "CREATE TABLE cluster_results (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), "
        "filename VARCHAR(255) UNIQUE NOT NULL, created_at TIMESTAMP)",
        "INSERT INTO users (id, username, password_hash) VALUES (1, 'old', 'h')",
        "INSERT INTO pcap_files (id, user_id, filename, file_path) VALUES ('p1', 1, 'a.pcap', '/a.pcap')",
        "INSERT INTO ip_roles (id, pcap_id, ip_address, role) VALUES (1, 'p1', '10.0.0.1', 'AMF')",
    )

    db_setup.apply_migrations()

    assert {"is_admin"} <= _columns("users")
    assert {"source", "analysis_result"} <= _columns("pcap_files")
    assert {"engine_version"} <= _columns("ip_roles")
    assert {"result_json", "pcap_id", "original_filename"} <= _columns("cluster_results")
    assert ALL_TABLES <= _tables()  # tables that did not exist yet were created
    with _db.engine.connect() as connection:
        row = connection.execute(sa.text(
            "SELECT u.username, u.is_admin, p.source, r.role, r.engine_version FROM users u "
            "JOIN pcap_files p ON p.user_id = u.id JOIN ip_roles r ON r.pcap_id = p.id"
        )).one()
    assert (row[0], bool(row[1]), row[2], row[3], row[4]) == ("old", False, "upload", "AMF", "")


def test_upgrading_again_changes_nothing(migration_app):
    db_setup.apply_migrations()
    _db.session.add(User(username="kept", password_hash="h", is_admin=False))
    _db.session.commit()
    db_setup.apply_migrations()
    assert _version() == _head()
    assert User.query.count() == 1


def test_init_database_seeds_one_admin(migration_app, monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "first_admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "first-password")
    db_setup.init_database(migration_app)
    db_setup.init_database(migration_app)
    admins = User.query.filter_by(is_admin=True).all()
    assert [a.username for a in admins] == ["first_admin"]


def test_init_database_without_admin_settings_creates_no_user(migration_app, monkeypatch):
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    db_setup.init_database(migration_app)
    assert User.query.count() == 0
