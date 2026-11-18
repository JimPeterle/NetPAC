from datetime import datetime

import pytest

from api_rules import (TOKEN_PREFIX, bearer_token, clean_group, clean_host, clean_vars, hash_token, may_create_token,
                       may_use_api, new_token, token_expiry, validate_token_name, vars_to_dict)


def test_new_token_is_random_and_only_hash_is_stored():
    token, token_hash, prefix = new_token()
    other, _, _ = new_token()
    assert token.startswith(TOKEN_PREFIX) and len(token) > 40
    assert token != other
    assert token_hash == hash_token(token) and token not in token_hash and len(token_hash) == 64
    assert token.startswith(prefix) and len(prefix) == len(TOKEN_PREFIX) + 6


@pytest.mark.parametrize("header, token", [
    ("Bearer nppat-abc", "nppat-abc"), ("bearer nppat-abc", "nppat-abc"), ("Bearer  nppat-abc ", "nppat-abc"),
    (None, None), ("", None), ("nppat-abc", None), ("Basic nppat-abc", None), ("Bearer abc", None),
    ("Bearer nppat-" + "x" * 300, None),
])
def test_bearer_token(header, token):
    assert bearer_token(header) == token


def test_token_expiry():
    now = datetime(2026, 1, 1)
    assert token_expiry("90", now) == datetime(2026, 4, 1)
    assert token_expiry(365, now) == datetime(2027, 1, 1)
    for days in ("0", "7", "366", "abc", None, "-30"):
        assert token_expiry(days, now) is None


@pytest.mark.parametrize("username, role, allowed", [
    ("anna", "operator", True), ("anna", "viewer", False), ("anna", "admin", False),
    ("admin", "operator", False),  # the user 'admin' is always admin
    ("anna", None, False),         # deleted user
])
def test_only_operators_use_the_api(username, role, allowed):
    assert may_use_api(username, role) is allowed


@pytest.mark.parametrize("creator, creator_role, owner, owner_role, allowed", [
    ("admin", "admin", "anna", "operator", True),   # admin for any operator
    ("boss", "admin", "anna", "operator", True),
    ("anna", "operator", "anna", "operator", True),  # operator for themselves
    ("anna", "operator", "otto", "operator", False),  # not for others
    ("admin", "admin", "admin", "admin", False),     # no tokens for admins
    ("admin", "admin", "vera", "viewer", False),     # no tokens for viewers
    ("vera", "viewer", "vera", "viewer", False),
])
def test_who_may_create_tokens(creator, creator_role, owner, owner_role, allowed):
    assert may_create_token(creator, creator_role, owner, owner_role) is allowed


def test_token_name():
    assert validate_token_name("inventory sync") is None
    assert validate_token_name("")
    assert validate_token_name("x" * 101)


def test_host_create_defaults():
    assert clean_host({"hostname": " r1 "}) == (
        {"hostname": "r1", "description": "", "groups": [], "is_active": True}, None)


def test_host_create_with_all_fields():
    values, error = clean_host({"hostname": "r1", "description": "Core", "groups": ["core", "core", "edge"],
                                "is_active": False})
    assert error is None
    assert values == {"hostname": "r1", "description": "Core", "groups": ["core", "edge"], "is_active": False}


@pytest.mark.parametrize("data", [
    None, [], "r1", {}, {"hostname": ""}, {"hostname": "r1 r2"}, {"hostname": 5},
    {"hostname": "r1", "groups": "core"}, {"hostname": "r1", "groups": [1]},
    {"hostname": "r1", "is_active": "yes"}, {"hostname": "r1", "description": 5},
    {"hostname": "r1", "password": "x"},
])
def test_host_create_errors(data):
    assert clean_host(data)[1]


def test_host_patch_only_checks_given_fields():
    assert clean_host({"is_active": False}, partial=True) == ({"is_active": False}, None)
    assert clean_host({"groups": []}, partial=True) == ({"groups": []}, None)
    assert clean_host({}, partial=True)[1] == "Nothing to change"
    assert clean_host({"hostname": "bad name"}, partial=True)[1]


def test_group_create():
    assert clean_group({"name": "core", "ansible_vars": {"ntp_server": "10.0.0.1", "port": 22, "check": True}}) == (
        {"name": "core", "ansible_vars": "ntp_server=10.0.0.1\nport=22\ncheck=true"}, None)
    assert clean_group({"name": "edge"}) == ({"name": "edge", "ansible_vars": ""}, None)


@pytest.mark.parametrize("data", [
    {}, {"name": ""}, {"name": "core net"}, {"name": "core-net"}, {"name": 1},
    {"name": "core", "ansible_vars": "a=1"}, {"name": "core", "ansible_vars": {"1a": "x"}},
    {"name": "core", "ansible_vars": {"a": "x\ny=2"}}, {"name": "core", "ansible_vars": {"a": [1]}},
    {"name": "core", "hosts": []},
])
def test_group_create_errors(data):
    assert clean_group(data)[1]


def test_group_patch():
    assert clean_group({"ansible_vars": {"a": "1"}}, partial=True) == ({"ansible_vars": "a=1"}, None)
    assert clean_group({"ansible_vars": None}, partial=True) == ({"ansible_vars": ""}, None)
    assert clean_group({"name": "other"}, partial=True)[1] == "Groups can't be renamed"
    assert clean_group({}, partial=True)[1] == "Nothing to change"


def test_vars_round_trip():
    text, error = clean_vars({"ntp_server": "10.0.0.1", "url": "http://x/?a=b"})
    assert error is None
    assert vars_to_dict(text) == {"ntp_server": "10.0.0.1", "url": "http://x/?a=b"}
