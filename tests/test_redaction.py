import json

import pytest

from redaction import REDACTED_VALUE, csv_safe, hide_sensitive, history_variables


@pytest.mark.parametrize("key", ["password", "ansible_become_pass", "pass", "api_key", "API-TOKEN", "client_secret"])
def test_sensitive_values_are_hidden(key):
    stored = json.loads(history_variables({key: "s3cret", "vlan": "10"}))
    assert stored["extra_vars"] == {key: REDACTED_VALUE, "vlan": "10"}
    assert stored["redacted_fields"] == [key]


@pytest.mark.parametrize("key", ["vlan", "passenger", "bypass_mode", "hostname"])
def test_normal_values_stay_visible(key):
    stored = json.loads(history_variables({key: "x"}))
    assert stored["extra_vars"] == {key: "x"}
    assert "redacted_fields" not in stored


def test_hidden_survey_fields_and_info():
    stored = json.loads(history_variables({"pin": "1234"}, hidden_fields=("pin",), template="Backup"))
    assert stored == {"extra_vars": {"pin": REDACTED_VALUE}, "template": "Backup", "redacted_fields": ["pin"]}


def test_hide_sensitive_filter():
    assert hide_sensitive({"vlan": 10, "token": "abc"}) == f"vlan=10, token={REDACTED_VALUE}"


@pytest.mark.parametrize("value, result", [
    ("=SUM(A1)", "'=SUM(A1)"), ("+1", "'+1"), ("-1", "'-1"), ("@cmd", "'@cmd"), ("\tx", "'\tx"),
    ("normal", "normal"), (None, ""), (42, "42"),
])
def test_csv_safe(value, result):
    assert csv_safe(value) == result
