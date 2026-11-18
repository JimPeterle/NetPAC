"""Static checks on app/netpac.py: every route is protected unless it is meant to be public."""

import ast
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parent.parent / "app" / "netpac.py"

# Routes without login: login steps and icons
PUBLIC_ROUTES = {"login", "totp_setup", "totp_verify", "totp_abort", "favicon", "apple_touch_icon"}

# POST routes every logged-in user may use (own password, own settings, logout)
POST_WITHOUT_ROLE = {"login", "totp_setup", "totp_verify", "totp_abort", "settings", "change_password", "logout"}

# The API may only touch hosts and groups
API_PATH_PREFIXES = ("/api/v1/hosts", "/api/v1/groups")


def load_routes():
    """Returns (name, paths, decorator names, methods) for every Flask route."""

    routes = []
    for node in ast.parse(SOURCE.read_text()).body:
        if not isinstance(node, ast.FunctionDef):
            continue
        route_calls = [d for d in node.decorator_list if isinstance(d, ast.Call) and ast.unparse(d.func) == "app.route"]
        if not route_calls:
            continue
        names = {ast.unparse(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list}
        paths = [ast.literal_eval(d.args[0]) for d in route_calls]
        methods = set()
        for d in route_calls:
            given = [k for k in d.keywords if k.arg == "methods"]
            methods.update(ast.literal_eval(given[0].value) if given else ["GET"])
        routes.append((node.name, paths, names, methods))
    return routes


ROUTES = load_routes()
API_ROUTES = [r for r in ROUTES if any(p.startswith("/api/") for p in r[1])]
WEB_ROUTES = [r for r in ROUTES if r not in API_ROUTES]


def test_routes_were_found():
    assert len(WEB_ROUTES) > 50
    assert len(API_ROUTES) >= 10


@pytest.mark.parametrize("name, decorators", [(n, d) for n, _, d, _ in WEB_ROUTES if n not in PUBLIC_ROUTES])
def test_route_needs_login(name, decorators):
    assert "login_required" in decorators


@pytest.mark.parametrize("name, decorators", [(n, d) for n, _, d, m in WEB_ROUTES if "POST" in m and n not in POST_WITHOUT_ROLE])
def test_post_route_checks_role(name, decorators):
    assert "role_required" in decorators


@pytest.mark.parametrize("name, paths, decorators", [(n, p, d) for n, p, d, _ in API_ROUTES])
def test_api_route_needs_token(name, paths, decorators):
    assert "api_token_required" in decorators
    # Tokens replace the session, so the CSRF check (for browser forms) is off; nothing may rely on a login
    assert "csrf.exempt" in decorators and "login_required" not in decorators


@pytest.mark.parametrize("name, paths", [(n, p) for n, p, _, _ in API_ROUTES])
def test_api_only_touches_hosts_and_groups(name, paths):
    assert all(p.startswith(API_PATH_PREFIXES) for p in paths)
