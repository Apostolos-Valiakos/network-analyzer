"""
Pins the web layer's outward shape: every URL with its methods, rate limits and
response without a login, plus the Swagger spec and CORS preflight. Moving
routes between modules must leave all of this unchanged.

    pytest tests/backend/test_route_table.py --update-snapshots   # after an intended change
"""

import re

from flask_limiter.util import get_qualified_name

_PLACEHOLDER = re.compile(r"<(?:[a-z]+:)?[a-z_]+>")
_NO_LOGIN_METHODS = ("GET", "POST", "DELETE", "PUT")
_INTERNAL_ENDPOINTS = ("static",)


def _concrete(rule):
    def fill(match):
        return "1" if match.group(0).startswith("<int:") else "x"

    return _PLACEHOLDER.sub(fill, rule)


def _limits(app, limiter, endpoint):
    """Rate limits declared on a route, or ["exempt"]."""
    manager = limiter.limit_manager
    name = get_qualified_name(app.view_functions[endpoint])
    limits = sorted(str(limit.limit) for limit in manager.decorated_limits(name))
    if manager.exemption_scope(app, endpoint, None):
        limits.append("exempt")
    return limits


def test_route_table(app, client, snapshot):
    from extensions import limiter

    table = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint in _INTERNAL_ENDPOINTS:
            continue
        methods = sorted(m for m in rule.methods if m in _NO_LOGIN_METHODS)
        without_login = {}
        for method in methods:
            res = client.open(_concrete(rule.rule), method=method)
            without_login[method] = res.status_code
        table[rule.rule] = {
            "methods": methods,
            "without_login": without_login,
            "rate_limits": _limits(app, limiter, rule.endpoint),
        }
    snapshot.assert_match("web_route_table", table)


def test_swagger_spec(client, snapshot):
    res = client.get("/apispec_1.json")
    assert res.status_code == 200
    spec = res.get_json()
    assert len(spec["paths"]) >= 20
    snapshot.assert_match("web_swagger_spec", spec)


def test_cors_preflight(client, snapshot):
    res = client.options(
        "/auth/login",
        headers={
            "Origin": "http://localhost",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization, content-type",
        },
    )
    disallowed = client.options(
        "/auth/login",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"},
    )
    snapshot.assert_match("web_cors", {
        "status": res.status_code,
        "allow_origin": res.headers.get("Access-Control-Allow-Origin"),
        "allow_methods": sorted(res.headers.get("Access-Control-Allow-Methods", "").split(", ")),
        "allow_headers": sorted(
            h.lower() for h in res.headers.get("Access-Control-Allow-Headers", "").split(", ")
        ),
        "disallowed_status": disallowed.status_code,
        "disallowed_allow_origin": disallowed.headers.get("Access-Control-Allow-Origin"),
    })
