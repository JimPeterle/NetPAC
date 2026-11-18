"""Checks the migration files themselves; no database needed."""

import re
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "database" / "migrations"
FILE_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


def test_every_file_has_a_valid_name():
    # db_migrations.py ignores files with other names, so a typo would silently skip a migration
    bad = [p.name for p in MIGRATIONS_DIR.iterdir() if not FILE_RE.match(p.name)]
    assert not bad, f"Invalid migration file names (expected 0001_name.sql): {bad}"


def test_versions_are_consecutive():
    versions = sorted(int(FILE_RE.match(p.name).group(1)) for p in MIGRATIONS_DIR.glob("*.sql"))
    assert versions == list(range(1, len(versions) + 1))


def test_every_statement_ends_with_semicolon_at_line_end():
    # db_migrations.py splits statements at ';' at the end of a line
    for path in MIGRATIONS_DIR.glob("*.sql"):
        lines = [line for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("--")]
        assert lines and lines[-1].rstrip().endswith(";"), f"{path.name}: last statement doesn't end with ';'"
