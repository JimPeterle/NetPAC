"""Opens every page once against a real database (runs on GitHub Actions, see tests.yml).

Importing netpac reads config/secret.env, connects to the database and runs the migrations, so
these tests only run with NETPAC_TEST_PAGES=1.
"""

import os
import urllib.parse
from pathlib import Path

import pytest

if os.environ.get("NETPAC_TEST_PAGES") != "1":
    pytest.skip("needs a database and config/secret.env (runs on GitHub Actions)", allow_module_level=True)

import netpac

LOG_FILE = Path("/var/log/netpac/netpac.log")

# Endpoints that are no page of the logged-in area
NOT_A_PAGE = {"static", "login", "totp_setup", "totp_verify", "favicon", "apple_touch_icon"}

# Every GET page without URL parameters, so new pages are tested automatically
PAGES = sorted(rule.rule for rule in netpac.app.url_map.iter_rules()
               if "GET" in rule.methods and not rule.arguments and rule.endpoint not in NOT_A_PAGE
               and not rule.rule.startswith("/api/"))

VIEWER_ALLOWED = ["/dashboard", "/hosts", "/groups", "/scripts", "/playbooks/", "/playbook_templates",
                  "/history", "/schedule", "/secrets", "/settings"]
VIEWER_DENIED = ["/health", "/audit", "/secrets/create"]

ANSIBLE_OUTPUT = """PLAY [all] *********************************************************************

TASK [Ping] ********************************************************************
ok: [r1]

PLAY RECAP *********************************************************************
r1                         : ok=1    changed=0    unreachable=0    failed=0    skipped=0
"""


def execute(sql, params=None):
    """Runs one statement in the NetPAC database and returns the new row id."""

    conn = netpac.get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.lastrowid
    finally:
        conn.close()


@pytest.fixture(scope="module")
def data():
    """Fills the database with one of everything, so the pages render real rows and not only empty lists."""

    Path(netpac.SCRIPTS_DIR, "hello.py").write_text('import os\nprint("Hello", os.environ.get("NETPAC_VAR_NAME"))\n')
    Path(netpac.PLAYBOOKS_DIR, "site.yml").write_text(
        "- hosts: all\n  gather_facts: false\n  tasks:\n    - name: Ping\n      ansible.builtin.ping:\n")

    group = execute("INSERT INTO host_groups (name, ansible_vars) VALUES ('core', 'ntp_server=10.0.0.1')")
    host = execute("INSERT INTO hosts (hostname, description) VALUES ('r1', 'Core router')")
    execute("INSERT INTO host_group_membership (host_id, group_id) VALUES (%s, %s)", (host, group))
    execute("INSERT INTO user (name, password, method, role) VALUES ('vera', NULL, 'local', 'viewer')")

    ansible_job = execute("""
        INSERT INTO history_jobs (script_name, user_id, target, variables, status, output, started_at,
                                  finished_at, duration, job_type, resolved_hosts)
        VALUES ('site.yml', 'admin', 'core', %s, 'completed', %s, NOW(), NOW(), 5, 'ansible', 'r1')
    """, ('{"extra_vars": {"vlan": "10", "password": "********"}, "redacted_fields": ["password"]}', ANSIBLE_OUTPUT))
    python_job = execute("""
        INSERT INTO history_jobs (script_name, user_id, target, variables, status, output, started_at,
                                  finished_at, duration, job_type, resolved_hosts)
        VALUES ('hello.py', 'admin', 'r1', '{"varCount": 1, "variable1": "core"}', 'failed', 'Traceback (most recent call last):\nValueError\n',
                NOW(), NOW(), 2, 'python', 'r1')
    """)

    execute("""
        INSERT INTO playbook_templates (name, description, playbook_path, job_type, target, extra_vars, created_by)
        VALUES ('Ping core', 'Pings all routers', 'site.yml', 'ansible', 'core', 'vlan=10', 'admin')
    """)
    execute("""
        INSERT INTO playbook_templates (name, description, playbook_path, job_type, target, script_args, use_venv, created_by)
        VALUES ('Hello', '', 'hello.py', 'python', 'r1', '--verbose', 1, 'admin')
    """)
    execute("""
        INSERT INTO schedule_jobs (script_name, user_id, target, variables, is_active, schedule_expression, job_type)
        VALUES ('site.yml', 'admin', 'core', '{"extra_vars": {"vlan": "10"}}', 0, '0 3 * * *', 'ansible')
    """)

    return {"group": group, "ansible_job": ansible_job, "python_job": python_job}


@pytest.fixture
def client(data):
    netpac.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
    netpac.limiter.enabled = False
    return netpac.app.test_client()


def log_in(client, username):
    """Logs a user in by writing the session like the login (password + TOTP) does."""

    conn = netpac.get_db()
    try:
        with conn.cursor() as cur:
            password_hash, totp_secret, _ = netpac.load_auth_row(cur, username)
    finally:
        conn.close()
    with client.session_transaction() as session:
        session["_user_id"] = username
        session["_fresh"] = True
        session["auth_fp"] = netpac.auth_fingerprint(password_hash, totp_secret)
    return client


def location_path(response):
    return urllib.parse.urlparse(response.headers.get("Location", "")).path


def assert_opens(response, path):
    """The page loads (or redirects inside NetPAC, not to the login page)."""

    if response.status_code >= 500:
        log = LOG_FILE.read_text()[-3000:] if LOG_FILE.exists() else "(no log file)"
        pytest.fail(f"{path} returned {response.status_code}. End of netpac.log:\n{log}")
    assert response.status_code in (200, 302), f"{path} returned {response.status_code}"
    if response.status_code == 302:
        assert location_path(response) != "/", f"{path} redirected to the login page"


def test_pages_were_found():
    assert "/dashboard" in PAGES and "/settings" in PAGES


def test_login_page_opens(client):
    assert client.get("/").status_code == 200


def test_pages_need_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302 and location_path(response) == "/"


def test_admin_is_logged_in(client):
    response = log_in(client, "admin").get("/dashboard")
    assert response.status_code == 200
    assert b"admin" in response.data


@pytest.mark.parametrize("path", PAGES)
def test_page_opens_as_admin(client, path):
    assert_opens(log_in(client, "admin").get(path), path)


@pytest.mark.parametrize("page", ["hosts/{group}", "history/{ansible_job}", "history/{python_job}",
                                  "history/{ansible_job}/status", "export_history_txt/{ansible_job}",
                                  "scripts/hello.py", "playbooks/site.yml"])
def test_detail_page_opens_as_admin(client, data, page):
    path = "/" + page.format(**data)
    assert_opens(log_in(client, "admin").get(path), path)


@pytest.mark.parametrize("path", VIEWER_ALLOWED)
def test_viewer_can_view(client, path):
    response = log_in(client, "vera").get(path)
    assert_opens(response, path)
    assert response.status_code == 200


@pytest.mark.parametrize("path", VIEWER_DENIED)
def test_viewer_is_sent_back(client, path):
    response = log_in(client, "vera").get(path)
    assert response.status_code == 302, f"{path} returned {response.status_code} for a viewer"


def test_template_passes_forks_to_the_job(data):
    template_id = execute("""
        INSERT INTO playbook_templates (name, playbook_path, job_type, target, forks, created_by)
        VALUES ('Forks', 'site.yml', 'ansible', 'core', 20, 'admin')
    """)
    conn = netpac.get_db()
    try:
        with conn.cursor() as cur:
            job, error = netpac.build_template_job(cur, template_id)
    finally:
        conn.close()
    assert error is None
    assert job["payload"]["forks"] == 20
    assert '"forks": 20' in job["variables"]
