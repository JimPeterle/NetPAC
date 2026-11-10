import pytest

from roles import PROTECTED_ADMIN, ROLE_DENIED_MESSAGES, ROLE_LEVELS, effective_role, role_at_least


@pytest.mark.parametrize("have, need, allowed", [
    ("admin", "admin", True), ("admin", "operator", True), ("admin", "viewer", True),
    ("operator", "admin", False), ("operator", "operator", True), ("operator", "viewer", True),
    ("viewer", "admin", False), ("viewer", "operator", False), ("viewer", "viewer", True),
])
def test_role_order(have, need, allowed):
    assert role_at_least(have, need) is allowed


def test_unknown_role_has_no_rights():
    assert not role_at_least("superuser", "viewer")
    assert not role_at_least(None, "viewer")


def test_protected_admin_is_always_admin():
    assert effective_role(PROTECTED_ADMIN, "viewer") == "admin"
    assert effective_role(PROTECTED_ADMIN, None) == "admin"


def test_unknown_role_becomes_viewer():
    assert effective_role("anna", "root") == "viewer"
    assert effective_role("anna", None) == "viewer"
    assert effective_role("anna", "operator") == "operator"


def test_every_checked_role_has_a_message():
    assert set(ROLE_DENIED_MESSAGES) == set(ROLE_LEVELS) - {"viewer"}
