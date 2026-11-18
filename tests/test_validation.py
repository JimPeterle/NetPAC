import pytest

from validation import (MAX_FORKS, MAX_HOSTNAME_LENGTH, MAX_SCRIPT_VARS, forks_args, forks_info, parse_extra_vars, parse_forks,
                        parse_var_count, validate_hostname, validate_password)


@pytest.mark.parametrize("hostname", ["r1", "core-sw01.example.com", "10.0.0.1", "fe80::1", "host_a"])
def test_valid_hostnames(hostname):
    assert validate_hostname(hostname) is None


@pytest.mark.parametrize("hostname", ["", "-r1", "r1 r2", "r1;reboot", "r1\n", "a" * (MAX_HOSTNAME_LENGTH + 1)])
def test_invalid_hostnames(hostname):
    assert validate_hostname(hostname)


@pytest.mark.parametrize("value, count", [("3", 3), ("", 0), (None, 0), ("abc", 0), ("-5", 0), ("999", MAX_SCRIPT_VARS)])
def test_var_count(value, count):
    assert parse_var_count(value) == count


def test_strong_password():
    assert validate_password("Netpac!2026") is None


@pytest.mark.parametrize("password", ["Ab1!", "netpac!2026", "NETPAC!2026", "Netpac!abcd", "Netpac2026"])
def test_weak_passwords(password):
    assert validate_password(password)


def test_extra_vars():
    raw = "vlan = 10\n\nname=core=1\n=ignored\nno equals sign\n"
    assert parse_extra_vars(raw) == {"vlan": "10", "name": "core=1"}
    assert parse_extra_vars(None) == {}


@pytest.mark.parametrize("value, forks", [("", None), (None, None), ("  ", None), ("1", 1), (" 20 ", 20), (MAX_FORKS, MAX_FORKS)])
def test_valid_forks(value, forks):
    assert parse_forks(value) == (forks, None)


@pytest.mark.parametrize("value", ["0", "-5", "2.5", "abc", "1e3", str(MAX_FORKS + 1), "9" * 5000, "5 --check"])
def test_invalid_forks(value):
    forks, error = parse_forks(value)
    assert forks is None and error


def test_forks_are_only_passed_when_set():
    assert forks_args(20) == ["--forks", "20"]
    assert forks_args(None) == []
    assert forks_info(20) == {"forks": 20}
    assert forks_info(None) == {}

