import re


MAX_SCRIPT_VARS = 10

MAX_HOSTNAME_LENGTH = 255

HOSTNAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]*\Z')


def validate_hostname(hostname):
    """Returns an error message if the hostname is invalid, else None."""

    if not hostname:
        return "Hostname is required"
    if len(hostname) > MAX_HOSTNAME_LENGTH:
        return f"Hostname is too long (max. {MAX_HOSTNAME_LENGTH} characters)"
    if not HOSTNAME_RE.match(hostname):
        return "Hostname may only contain letters, numbers, dots, colons, dashes and underscores (no spaces)"
    return None


def parse_var_count(value) -> int:
    """Returns the number of script variables, limited to MAX_SCRIPT_VARS."""

    try:
        count = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(count, MAX_SCRIPT_VARS))


def validate_password(password: str) -> str | None:
    """Returns an error message if the password is too weak, else None."""

    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return "Password must contain at least one special character"
    return None


def parse_extra_vars(raw):
    """Parses 'Key=Value' lines into a dict."""

    extra_vars = {}
    for line in (raw or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if key:
                extra_vars[key] = value
    return extra_vars
