"""Uses the REST API against a real database (runs on GitHub Actions together with test_pages.py)."""

import os

import pytest

if os.environ.get("NETPAC_TEST_PAGES") != "1":
    pytest.skip("needs a database and config/secret.env (runs on GitHub Actions)", allow_module_level=True)

import netpac
from api_rules import new_token


def execute(sql, params=None):
    """Runs one statement in the NetPAC database and returns the affected rows."""

    conn = netpac.get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()


def add_user(name, role):
    execute("INSERT IGNORE INTO user (name, password, method, role) VALUES (%s, NULL, 'local', %s)", (name, role))


def add_token(username, days_valid=30):
    """Stores a token for a user and returns the Authorization header."""

    token, token_hash, prefix = new_token()
    execute("""INSERT INTO api_tokens (username, name, token_hash, prefix, created_by, expires_at)
               VALUES (%s, 'test', %s, %s, 'admin', NOW() + INTERVAL %s DAY)""", (username, token_hash, prefix, days_valid))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def client():
    netpac.app.config.update(TESTING=True)
    netpac.limiter.enabled = False
    add_user("otto", "operator")
    add_user("vera_api", "viewer")
    add_user("boss", "admin")
    return netpac.app.test_client()


@pytest.fixture(scope="module")
def operator(client):
    return add_token("otto")


def test_without_token(client):
    response = client.get("/api/v1/hosts")
    assert response.status_code == 401 and "error" in response.get_json()


def test_unknown_token(client):
    assert client.get("/api/v1/hosts", headers={"Authorization": "Bearer nppat-doesnotexist"}).status_code == 401


def test_expired_token(client):
    add_user("olga", "operator")
    assert client.get("/api/v1/hosts", headers=add_token("olga", days_valid=-1)).status_code == 401


@pytest.mark.parametrize("username", ["vera_api", "admin"])
def test_viewer_and_local_admin_are_refused(client, username):
    assert client.get("/api/v1/hosts", headers=add_token(username)).status_code == 403


def test_admin_group_may_use_the_api(client):
    assert client.get("/api/v1/hosts", headers=add_token("boss")).status_code == 200


def test_downgraded_operator_loses_access(client):
    add_user("paul", "operator")
    headers = add_token("paul")
    assert client.get("/api/v1/hosts", headers=headers).status_code == 200
    execute("UPDATE user SET role = 'viewer' WHERE name = 'paul'")
    assert client.get("/api/v1/hosts", headers=headers).status_code == 403


def test_session_login_is_not_enough(client):
    # A browser session without a token must not reach the API
    with client.session_transaction() as session:
        session["_user_id"] = "otto"
    assert client.get("/api/v1/hosts").status_code == 401


def test_group_and_host_lifecycle(client, operator):
    response = client.post("/api/v1/groups", json={"name": "api_core", "ansible_vars": {"ntp_server": "10.0.0.1"}},
                           headers=operator)
    assert response.status_code == 201
    assert response.get_json()["ansible_vars"] == {"ntp_server": "10.0.0.1"}
    assert client.post("/api/v1/groups", json={"name": "api_core"}, headers=operator).status_code == 409

    response = client.post("/api/v1/hosts", json={"hostname": "api-r1", "description": "Router", "groups": ["api_core"]},
                           headers=operator)
    assert response.status_code == 201
    host = response.get_json()
    assert host["groups"] == ["api_core"] and host["is_active"] is True
    assert response.headers["Location"].endswith("/api/v1/hosts/api-r1")

    assert client.post("/api/v1/hosts", json={"hostname": "api-r1"}, headers=operator).status_code == 409
    assert client.post("/api/v1/hosts", json={"hostname": "api-r2", "groups": ["nope"]}, headers=operator).status_code == 400
    assert client.post("/api/v1/hosts", data="not json", headers=operator).status_code == 400

    assert [h["hostname"] for h in client.get("/api/v1/hosts?group=api_core", headers=operator).get_json()] == ["api-r1"]
    assert client.get("/api/v1/hosts?group=nope", headers=operator).status_code == 404
    assert client.get("/api/v1/groups/api_core", headers=operator).get_json()["hosts"] == ["api-r1"]

    response = client.patch("/api/v1/hosts/api-r1", json={"hostname": "api-r1b", "is_active": False, "groups": []},
                            headers=operator)
    assert response.status_code == 200
    assert response.get_json() | {"id": 0} == {"id": 0, "hostname": "api-r1b", "description": "Router",
                                               "is_active": False, "groups": []}
    assert client.get("/api/v1/hosts/api-r1", headers=operator).status_code == 404

    response = client.patch("/api/v1/groups/api_core", json={"ansible_vars": {"a": "1"}}, headers=operator)
    assert response.get_json()["ansible_vars"] == {"a": "1"}
    assert client.patch("/api/v1/groups/api_core", json={"name": "x"}, headers=operator).status_code == 400

    assert client.delete("/api/v1/hosts/api-r1b", headers=operator).status_code == 204
    assert client.delete("/api/v1/hosts/api-r1b", headers=operator).status_code == 404
    assert client.delete("/api/v1/groups/api_core", headers=operator).status_code == 204
    assert client.get("/api/v1/groups/api_core", headers=operator).status_code == 404


def test_changes_are_in_the_audit_log(client, operator):
    client.post("/api/v1/groups", json={"name": "api_audit"}, headers=operator)
    rows = execute("SELECT username, details FROM audit_log WHERE action = 'group.create' AND target = 'api_audit'")
    assert rows and rows[-1][0] == "otto" and "API token" in rows[-1][1]


def test_no_other_endpoints(client, operator):
    for path in ("/api/v1/schedules", "/api/v1/secrets", "/api/v1/jobs", "/api/v1/users"):
        response = client.get(path, headers=operator)
        assert response.status_code == 404 and response.is_json


def test_wrong_method_is_json(client, operator):
    response = client.put("/api/v1/hosts", json={}, headers=operator)
    assert response.status_code == 405 and response.is_json
