"""
Unit tests for authentication endpoints:
  POST /auth/login
  POST /auth/register   (admin only)
  GET  /auth/users      (admin only)
  DELETE /auth/users/<id> (admin only)
"""

import json
import pytest
from werkzeug.security import generate_password_hash
from models import db as _db
from models import User


# ── Helpers ───────────────────────────────────────────────────────────────────


def _add_user(app, username, password, is_admin=False):
    with app.app_context():
        u = User(
            username=username,
            password_hash=generate_password_hash(password),
            is_admin=is_admin,
        )
        _db.session.add(u)
        _db.session.commit()
        _db.session.refresh(u)
        return {"id": u.id, "username": u.username}


def _post_login(client, username, password):
    return client.post(
        "/auth/login",
        data=json.dumps({"username": username, "password": password}),
        content_type="application/json",
    )


# ── /auth/login ───────────────────────────────────────────────────────────────


class TestLogin:
    def test_login_success_returns_token(self, client, app):
        _add_user(app, "alice", "password1", is_admin=False)
        res = _post_login(client, "alice", "password1")
        assert res.status_code == 200
        data = res.get_json()
        assert "access_token" in data
        assert data["is_admin"] is False

    def test_login_admin_flag_set(self, client, app):
        _add_user(app, "superuser", "password1", is_admin=True)
        res = _post_login(client, "superuser", "password1")
        assert res.status_code == 200
        assert res.get_json()["is_admin"] is True

    def test_login_wrong_password_returns_401(self, client, app):
        _add_user(app, "bob", "correctpass", is_admin=False)
        res = _post_login(client, "bob", "wrongpass")
        assert res.status_code == 401
        assert "error" in res.get_json()

    def test_login_nonexistent_user_returns_401(self, client):
        res = _post_login(client, "nobody", "pass")
        assert res.status_code == 401

    def test_login_missing_username_returns_400(self, client):
        res = client.post(
            "/auth/login",
            data=json.dumps({"username": "", "password": "pass"}),
            content_type="application/json",
        )
        assert res.status_code == 400

    def test_login_missing_password_returns_400(self, client):
        res = client.post(
            "/auth/login",
            data=json.dumps({"username": "alice", "password": ""}),
            content_type="application/json",
        )
        assert res.status_code == 400

    def test_login_empty_body_returns_400(self, client):
        res = client.post(
            "/auth/login",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert res.status_code == 400

    def test_login_whitespace_username_treated_as_empty(self, client):
        res = client.post(
            "/auth/login",
            data=json.dumps({"username": "   ", "password": "pass"}),
            content_type="application/json",
        )
        assert res.status_code == 400


# ── /auth/register ────────────────────────────────────────────────────────────


class TestRegister:
    def test_register_success_by_admin(self, client, admin_headers):
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "newuser", "password": "password1"}),
            headers=admin_headers,
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["username"] == "newuser"
        assert data["is_admin"] is False

    def test_register_admin_user(self, client, admin_headers):
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "newadmin", "password": "password1", "is_admin": True}),
            headers=admin_headers,
        )
        assert res.status_code == 201
        assert res.get_json()["is_admin"] is True

    def test_register_requires_admin_token(self, client, user_headers):
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "x", "password": "password1"}),
            headers=user_headers,
        )
        assert res.status_code == 403

    def test_register_requires_any_token(self, client):
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "x", "password": "password1"}),
            content_type="application/json",
        )
        assert res.status_code == 401

    def test_register_duplicate_username_returns_409(self, client, app, admin_headers):
        _add_user(app, "taken", "password1")
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "taken", "password": "password1"}),
            headers=admin_headers,
        )
        assert res.status_code == 409

    def test_register_short_password_returns_400(self, client, admin_headers):
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "newuser2", "password": "short"}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_register_missing_username_returns_400(self, client, admin_headers):
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "", "password": "password1"}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_register_exactly_8_char_password_accepted(self, client, admin_headers):
        res = client.post(
            "/auth/register",
            data=json.dumps({"username": "u8chars", "password": "12345678"}),
            headers=admin_headers,
        )
        assert res.status_code == 201


# ── /auth/users ───────────────────────────────────────────────────────────────


class TestListUsers:
    def test_list_users_admin_returns_200(self, client, admin_headers):
        res = client.get("/auth/users", headers=admin_headers)
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

    def test_list_users_includes_admin_user(self, client, app, admin_headers, admin_user):
        res = client.get("/auth/users", headers=admin_headers)
        usernames = [u["username"] for u in res.get_json()]
        assert admin_user["username"] in usernames

    def test_list_users_non_admin_returns_403(self, client, user_headers):
        res = client.get("/auth/users", headers=user_headers)
        assert res.status_code == 403

    def test_list_users_no_token_returns_401(self, client):
        res = client.get("/auth/users")
        assert res.status_code == 401


# ── DELETE /auth/users/<id> ───────────────────────────────────────────────────


class TestDeleteUser:
    def test_delete_user_success(self, client, app, admin_headers):
        victim = _add_user(app, "victim", "password1")
        res = client.delete(f"/auth/users/{victim['id']}", headers=admin_headers)
        assert res.status_code == 200

    def test_delete_own_account_returns_400(self, client, admin_user, admin_headers):
        res = client.delete(f"/auth/users/{admin_user['id']}", headers=admin_headers)
        assert res.status_code == 400

    def test_delete_nonexistent_user_returns_404(self, client, admin_headers):
        res = client.delete("/auth/users/99999", headers=admin_headers)
        assert res.status_code == 404

    def test_delete_user_non_admin_returns_403(self, client, user_headers):
        res = client.delete("/auth/users/1", headers=user_headers)
        assert res.status_code == 403

    def test_delete_user_no_token_returns_401(self, client):
        res = client.delete("/auth/users/1")
        assert res.status_code == 401
