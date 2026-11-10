"""Static checks on app/netpac.py: every route is protected unless it is meant to be public."""

import ast
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parent.parent / "app" / "netpac.py"

# Routes without login: login steps and icons
PUBLIC_ROUTES = {"login", "totp_setup", "totp_verify", "totp_abort", "favicon", "apple_touch_icon"}

# POST routes every logged-in user may use (own password, own settings, logout)
POST_WITHOUT_ROLE = {"login", "totp_setup", "totp_verify", "totp_abort", "settings", "change_password", "logout"}


def load_routes():
    """Returns (name, decorator names, accepts POST) for every Flask route."""

    routes = []
    for node in ast.parse(SOURCE.read_text()).body:
        if not isinstance(node, ast.FunctionDef):
            continue
        calls = [d for d in node.decorator_list if isinstance(d, ast.Call)]
        route_calls = [d for d in calls if ast.unparse(d.func) == "app.route"]
        if not route_calls:
            continue
        names = {ast.unparse(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list}
        post = any(k.arg == "methods" and "POST" in ast.unparse(k.value) for d in route_calls for k in d.keywords)
        routes.append((node.name, names, post))
    return routes


ROUTES = load_routes()


def test_routes_were_found():
    assert len(ROUTES) > 50


@pytest.mark.parametrize("name, decorators", [(n, d) for n, d, _ in ROUTES if n not in PUBLIC_ROUTES])
def test_route_needs_login(name, decorators):
    assert "login_required" in decorators


@pytest.mark.parametrize("name, decorators", [(n, d) for n, d, post in ROUTES if post and n not in POST_WITHOUT_ROLE])
def test_post_route_checks_role(name, decorators):
    assert "role_required" in decorators
