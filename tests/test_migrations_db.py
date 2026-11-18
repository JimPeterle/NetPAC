"""Applies the database migrations to a real MariaDB (runs on GitHub Actions, see tests.yml).

Needs NETPAC_TEST_DB_HOST (and NETPAC_TEST_DB_PORT, _USER, _PASSWORD) of a user that may create and
drop databases; without it the tests are skipped.
"""

import logging
import os
import re
import uuid
from pathlib import Path

import pytest

if not os.environ.get("NETPAC_TEST_DB_HOST"):
    pytest.skip("needs a MariaDB server (runs on GitHub Actions)", allow_module_level=True)

import pymysql

import db_migrations
from db_migrations import available_migrations, run_migrations, split_statements

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NETPAC_SOURCE = Path(__file__).resolve().parent.parent / "app" / "netpac.py"
ALL_MIGRATIONS = [name for _, name, _ in available_migrations()]
LOGGER = logging.getLogger("test_migrations")

# Releases before the migration system: schema file of the tag and the migrations it already contains
OLD_RELEASES = {"v5.0.0": 1, "v6.0.0": 2}


def connect(database=None):
    """Opens a connection to the test server."""

    return pymysql.connect(host=os.environ["NETPAC_TEST_DB_HOST"], port=int(os.environ.get("NETPAC_TEST_DB_PORT", 3306)),
                           user=os.environ.get("NETPAC_TEST_DB_USER", "root"),
                           password=os.environ.get("NETPAC_TEST_DB_PASSWORD", ""),
                           database=database, autocommit=True)


def query(get_db, sql, params=None):
    """Runs one statement and returns all rows."""

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()


def create_database():
    """Creates an empty database and returns (name, get_db)."""

    name = f"netpac_test_{uuid.uuid4().hex[:12]}"
    query(connect, f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    return name, lambda: connect(name)


def drop_database(name):
    query(connect, f"DROP DATABASE IF EXISTS `{name}`")


def migrate(get_db, tmp_path):
    """Runs all pending migrations like NetPAC does at startup."""

    return run_migrations(get_db, LOGGER, str(tmp_path / "db_secrets.cnf"), str(tmp_path / "backups"), "netpac_db")


def schema(get_db):
    """Returns {table: {columns}} of the database."""

    result = {}
    for table, column in query(get_db, "SELECT table_name, column_name FROM information_schema.columns "
                                       "WHERE table_schema = DATABASE()"):
        result.setdefault(table, set()).add(column)
    return result


@pytest.fixture
def database():
    name, get_db = create_database()
    yield get_db
    drop_database(name)


@pytest.fixture(scope="module")
def fresh_schema(tmp_path_factory):
    """Schema of a new installation (all migrations on an empty database)."""

    name, get_db = create_database()
    try:
        migrate(get_db, tmp_path_factory.mktemp("fresh"))
        return schema(get_db)
    finally:
        drop_database(name)


def test_fresh_install(database, tmp_path):
    assert migrate(database, tmp_path) == ALL_MIGRATIONS
    assert [row[0] for row in query(database, "SELECT name FROM schema_migrations ORDER BY version")] == ALL_MIGRATIONS
    # A second start has nothing to do
    assert migrate(database, tmp_path) == []
    # The default admin exists and has the admin role
    assert query(database, "SELECT role FROM user WHERE name = 'admin'") == (("admin",),)


def test_fresh_install_has_every_table_netpac_uses(fresh_schema):
    used = set(re.findall(r"(?<!KEY )(?<!FOR )\b(?:FROM|JOIN|INTO|UPDATE)\s+`?([A-Za-z_][\w.]*)", NETPAC_SOURCE.read_text()))
    used = {name for name in used if "." not in name}
    assert used - set(fresh_schema) == set()


def load_old_schema(get_db, release):
    """Creates the tables of an old release from its schema dump."""

    sql = (FIXTURES / f"schema_{release}.sql").read_text()
    sql = "\n".join(line for line in sql.splitlines() if not line.startswith("/*M!999999"))
    version = query(get_db, "SELECT VERSION()")[0][0]
    if int(version.split(".")[0]) < 11:
        # The dumps come from MariaDB 11.8; this collation doesn't exist in 10.x
        sql = sql.replace("utf8mb4_uca1400_ai_ci", "utf8mb4_unicode_ci")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for statement in split_statements(sql):
                cur.execute(statement)
    finally:
        conn.close()


@pytest.mark.parametrize("release", OLD_RELEASES)
def test_upgrade_from_old_release(release, database, tmp_path, monkeypatch, fresh_schema):
    load_old_schema(database, release)
    for name, method in (("admin", "local"), ("anna", "local"), ("rudi", "radius")):
        query(database, "INSERT INTO user (name, password, method) VALUES (%s, 'hash', %s)", (name, method))

    backups = []
    monkeypatch.setattr(db_migrations, "backup_database", lambda cnf, folder, db: backups.append(db) or "backup.sql")

    baseline = OLD_RELEASES[release]
    assert migrate(database, tmp_path) == ALL_MIGRATIONS[baseline:]
    assert backups, "an existing database must be backed up before migrating"

    # Existing users keep working: admin stays admin, everyone else becomes operator
    roles = dict(query(database, "SELECT name, role FROM user"))
    assert roles == {"admin": "admin", "anna": "operator", "rudi": "operator"}

    # Everything a new installation has also exists after the update
    upgraded = schema(database)
    missing = {table: sorted(columns - upgraded.get(table, set()))
               for table, columns in fresh_schema.items() if columns - upgraded.get(table, set())}
    assert missing == {}
