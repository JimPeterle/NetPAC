#!/usr/bin/env python3
import argparse
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
import pymysql
from dotenv import dotenv_values

BASE_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
MIGRATIONS_DIR = os.path.join(BASE_DIR, "database", "migrations")
MIGRATION_FILE_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
LOCK_NAME = "netpac_migrations"
LOCK_TIMEOUT = 120


class MigrationError(Exception):
    """Raised when the database could not be brought up to date."""


def available_migrations():
    """Returns all migration files as sorted (version, name, path) tuples."""

    migrations = []
    for name in sorted(os.listdir(MIGRATIONS_DIR)):
        match = MIGRATION_FILE_RE.match(name)
        if match:
            migrations.append((int(match.group(1)), name, os.path.join(MIGRATIONS_DIR, name)))
    versions = [version for version, _, _ in migrations]
    if len(versions) != len(set(versions)):
        raise MigrationError("Two migration files share the same version number")
    return migrations


def split_statements(sql):
    """Splits a migration file into single SQL statements (one per ';' at line end)."""

    lines = [line for line in sql.splitlines() if not line.lstrip().startswith("--")]
    return [stmt.strip() for stmt in re.split(r";\s*$", "\n".join(lines), flags=re.M) if stmt.strip()]


def table_exists(cur, table):
    """Returns True if the table exists in the current database."""

    cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s", (table,))
    return cur.fetchone()[0] > 0


def column_exists(cur, table, column):
    """Returns True if the column exists in the table."""

    cur.execute("""
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s
    """, (table, column))
    return cur.fetchone()[0] > 0


def detect_baseline(cur):
    """Returns the migration version an existing database without migration tracking already has."""

    if not table_exists(cur, "user"):
        return 0
    if column_exists(cur, "user", "totp_last_counter"):
        return 2
    return 1


def applied_versions(cur):
    """Returns the set of migration versions already applied."""

    cur.execute("SELECT version FROM schema_migrations")
    return {row[0] for row in cur.fetchall()}


def backup_database(cnf_file, backup_dir, database):
    """Dumps the database to the backup folder (0600) and returns the file path."""

    if not os.path.exists(cnf_file):
        raise MigrationError(f"{cnf_file} not found — can't create a backup before migrating")

    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    path = os.path.join(backup_dir, f"netpac_pre_migration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql")

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        result = subprocess.run(
            ["mysqldump", f"--defaults-extra-file={cnf_file}", "--single-transaction", "--routines", database],
            stdout=f, stderr=subprocess.PIPE, text=True, timeout=600
        )
    if result.returncode != 0:
        os.remove(path)
        raise MigrationError(f"Backup before migrating failed: {result.stderr.strip()}")
    return path


def run_migrations(get_db, logger, cnf_file, backup_dir, database):
    """Applies all pending migrations (with a backup first) and returns their names."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT GET_LOCK(%s, %s)", (LOCK_NAME, LOCK_TIMEOUT))
        if cur.fetchone()[0] != 1:
            raise MigrationError("Another process is migrating the database — timed out waiting for it")

        try:
            migrations = available_migrations()
            tracking_is_new = not table_exists(cur, "schema_migrations")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version int(11) NOT NULL,
                    name varchar(255) NOT NULL,
                    applied_at datetime NOT NULL DEFAULT current_timestamp(),
                    PRIMARY KEY (version)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            if tracking_is_new:
                baseline = detect_baseline(cur)
                for version, name, _ in migrations:
                    if version <= baseline:
                        cur.execute("INSERT IGNORE INTO schema_migrations (version, name) VALUES (%s, %s)", (version, name))
                conn.commit()
                if baseline:
                    logger.info(f"Existing database detected — migrations up to {baseline:04d} marked as applied")

            done = applied_versions(cur)
            pending = [m for m in migrations if m[0] not in done]
            if not pending:
                return []

            backup = None
            if table_exists(cur, "user"):
                backup = backup_database(cnf_file, backup_dir, database)
                logger.info(f"Database backup before migrating: {backup}")

            applied = []
            for version, name, path in pending:
                logger.info(f"Applying database migration {name}")
                try:
                    with open(path, encoding="utf-8") as f:
                        for statement in split_statements(f.read()):
                            cur.execute(statement)
                    cur.execute("INSERT INTO schema_migrations (version, name) VALUES (%s, %s)", (version, name))
                    conn.commit()
                except Exception as e:
                    hint = f" Restore {backup} if the database is in a broken state." if backup else ""
                    raise MigrationError(f"Migration {name} failed: {e}.{hint}") from e
                applied.append(name)

            logger.info(f"Database migrated: {', '.join(applied)}")
            return applied
        finally:
            cur.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))
    except MigrationError:
        raise
    except Exception as e:
        raise MigrationError(f"{type(e).__name__}: {e}") from e
    finally:
        cur.close()
        conn.close()


def migration_status(get_db):
    """Returns (applied, pending) migration names."""

    conn = get_db()
    cur = conn.cursor()
    try:
        done = applied_versions(cur) if table_exists(cur, "schema_migrations") else set()
    finally:
        cur.close()
        conn.close()
    migrations = available_migrations()
    return [n for v, n, _ in migrations if v in done], [n for v, n, _ in migrations if v not in done]


def config_path(name):
    """Returns the path of a local config file; falls back to its old place in the main folder (before 7.0.0)."""

    path = os.path.join(CONFIG_DIR, name)
    legacy = os.path.join(BASE_DIR, name)
    return legacy if not os.path.exists(path) and os.path.exists(legacy) else path


def main():
    """Command line: show the migration status or apply pending migrations."""

    parser = argparse.ArgumentParser(description="NetPAC database migrations")
    parser.add_argument("--apply", action="store_true", help="apply pending migrations (with backup)")
    args = parser.parse_args()

    config = dotenv_values(config_path("secret.env"))

    def get_db():
        """Opens a database connection with the values from secret.env."""

        return pymysql.connect(user=config.get("DB_USER"), password=config.get("DB_PW"), host=config.get("DB_IP"),
                               port=int(config.get("DB_PORT") or 3306), database="netpac_db", autocommit=True)

    if args.apply:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        try:
            applied = run_migrations(get_db, logging.getLogger("netpac_migrations"),
                                     config_path("db_secrets.cnf"),
                                     os.path.join(os.path.dirname(BASE_DIR), "netpac_backups"), "netpac_db")
        except MigrationError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print("Nothing to do — database is up to date." if not applied else "Done.")
        return

    applied, pending = migration_status(get_db)
    for name in applied:
        print(f"  applied   {name}")
    for name in pending:
        print(f"  pending   {name}")
    print("\nDatabase is up to date." if not pending else "\nPending migrations are applied on the next NetPAC start "
                                                         "(or now with: netpac db --apply).")


if __name__ == "__main__":
    main()
