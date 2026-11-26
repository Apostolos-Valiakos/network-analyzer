"""
Shared fixtures for all backend tests.

Run from the project root:
    pip install -r server/requirements.txt -r tests/requirements.txt
    pytest                          # everything
    pytest -m "not integration"     # skip tests that need real tshark
    pytest --update-snapshots       # re-record tests/backend/snapshots/*.json

Snapshot tests (test_characterization.py, test_route_snapshots.py) record what
the code returns today. If one fails after a change that was meant to keep
behaviour, the diff shows what changed. Re-record only for intended changes,
and review the snapshot diff before committing.
"""

import atexit
import os
import sys
import shutil
from unittest.mock import MagicMock

# ── 1. Environment variables (must be set before app is imported) ─────────────
import tempfile as _tempfile

os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-testing-only")
# One SQLite file per test run, in its own temp folder: two runs at once (a
# terminal and the IDE, say) used to share tests/backend/test_penm.db and drop
# each other's tables mid-test. Pipeline child processes inherit the variable,
# so they open the same file as the run that started them.
_TEST_DB_DIR = _tempfile.mkdtemp(prefix="penm_tests_")
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite:///" + os.path.join(_TEST_DB_DIR, "test_penm.db").replace("\\", "/"),
)
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "admin123")
os.environ.setdefault("SECRET_TOKEN", "test-secret-token")
os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost")
# Forced, not setdefault: the real log is forwarded to R13's syslog collector,
# so test runs must never append to it.
os.environ["WP5_NOTICE_LOG"] = os.path.join(
    _tempfile.gettempdir(), "penm_tests_wp5_notices.log"
)

# ── 2. Stub modules with import-time side effects ──────────────────────────
_sched_mod = MagicMock()
_sched_mod.start_scheduler = MagicMock()
sys.modules.setdefault("snapshot_scheduler", _sched_mod)

# ── 3. Add server/ to sys.path so 'from app import ...' resolves ─────────────
_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "server")
)
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

# ── 4. Build the app; the fresh_db fixture creates the schema ────────────────
import pytest
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token

from app import create_app
from extensions import limiter as _limiter
from models import db as _db, User, PcapFile, ClusterResult, FlowStatistic, RoleSnapshot
from packet_table import CACHE_SUFFIX as PACKET_CACHE_SUFFIX

flask_app = create_app(init_database=False)


def _remove_test_db():
    """Deletes this run's database folder at exit, once nothing holds the file
    open (Windows refuses to delete an open SQLite file). Only the folder this
    run created; a DATABASE_URL from the environment is never touched."""
    import gc

    with flask_app.app_context():
        _db.session.remove()
        _db.engine.dispose()
    gc.collect()
    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)


atexit.register(_remove_test_db)

# Disable rate limiting so tests can call endpoints freely. Flask-Limiter reads
# RATELIMIT_ENABLED only at init, so setting the config here has no effect;
# the extension's own switch does.
_limiter.enabled = False

# Path to the sample PCAP shipped with the tests
FIXTURE_PCAP = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")

from snapshot_utils import FIXTURE_DIR, Snapshot


def pytest_addoption(parser):
    parser.addoption(
        "--update-snapshots",
        action="store_true",
        default=False,
        help="Rewrite tests/backend/snapshots/*.json from current output.",
    )


@pytest.fixture()
def snapshot(request):
    return Snapshot(update=request.config.getoption("--update-snapshots"))


@pytest.fixture()
def capture_copy(tmp_path):
    """Returns a function that copies a fixture capture into tmp_path, so
    caches written next to the pcap (.packets.tsv) never land in
    tests/backend/fixtures."""

    def _copy(name):
        dest = tmp_path / name
        shutil.copy2(os.path.join(FIXTURE_DIR, name), dest)
        return str(dest)

    return _copy


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def app():
    flask_app.config["TESTING"] = True
    yield flask_app
    # The database folder is removed at exit (_remove_test_db).


@pytest.fixture()
def fresh_db(app):
    """Drop and recreate all tables before each test for full isolation."""
    with app.app_context():
        _db.drop_all()
        _db.create_all()
    yield
    with app.app_context():
        _db.session.remove()


@pytest.fixture()
def client(app, fresh_db):
    return app.test_client()


@pytest.fixture()
def admin_user(app, fresh_db):
    with app.app_context():
        u = User(
            username="admin_test",
            password_hash=generate_password_hash("admin123"),
            is_admin=True,
        )
        _db.session.add(u)
        _db.session.commit()
        _db.session.refresh(u)
        return {"id": u.id, "username": u.username, "is_admin": True}


@pytest.fixture()
def regular_user(app, fresh_db):
    with app.app_context():
        u = User(
            username="user_test",
            password_hash=generate_password_hash("userpass1"),
            is_admin=False,
        )
        _db.session.add(u)
        _db.session.commit()
        _db.session.refresh(u)
        return {"id": u.id, "username": u.username, "is_admin": False}


@pytest.fixture()
def admin_headers(app, admin_user):
    with app.app_context():
        token = create_access_token(identity=str(admin_user["id"]))
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture()
def user_headers(app, regular_user):
    with app.app_context():
        token = create_access_token(identity=str(regular_user["id"]))
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture()
def pcap_in_db(app, fresh_db, admin_user):
    """
    Copies sample.pcap into server/generated_pcaps/ and inserts a PcapFile row.
    Cleans up after the test.
    """
    from settings import PCAP_GEN_OUTPUT_DIR

    test_filename = "test_sample_fixture.pcap"
    dest_path = os.path.join(PCAP_GEN_OUTPUT_DIR, test_filename)
    shutil.copy2(FIXTURE_PCAP, dest_path)

    with app.app_context():
        record = PcapFile(
            filename=test_filename,
            original_filename="sample.pcap",
            file_path=dest_path,
            file_size=os.path.getsize(dest_path),
            status="COMPLETED",
            source="generated",
            user_id=admin_user["id"],
        )
        _db.session.add(record)
        _db.session.commit()
        _db.session.refresh(record)
        pcap_id = record.id

    yield {"id": pcap_id, "filename": test_filename, "path": dest_path, "user_id": admin_user["id"]}

    for path in (dest_path, dest_path + PACKET_CACHE_SUFFIX):
        if os.path.exists(path):
            os.remove(path)
