import hashlib
import re
import secrets
from datetime import datetime, timedelta

from roles import effective_role
from validation import parse_extra_vars, validate_hostname


TOKEN_PREFIX = "nppat-"

TOKEN_DAYS = (30, 90, 365)

MAX_TOKEN_NAME_LENGTH = 100

MAX_GROUP_NAME_LENGTH = 255

MAX_DESCRIPTION_LENGTH = 2000

GROUP_NAME_RE = re.compile(r"^[a-zA-Z0-9_]+\Z")

VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")

HOST_FIELDS = {"hostname", "description", "groups", "is_active"}

GROUP_FIELDS = {"name", "ansible_vars"}


def new_token():
    """Returns (token, token_hash, prefix) for a new API token; only the hash and prefix are stored."""

    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token), token[:len(TOKEN_PREFIX) + 6]


def hash_token(token):
    """Returns the SHA-256 hash under which a token is stored."""

    return hashlib.sha256(token.encode()).hexdigest()


def bearer_token(header):
    """Returns the token from an 'Authorization: Bearer nppat-…' header, else None."""

    scheme, _, token = (header or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token.startswith(TOKEN_PREFIX) or len(token) > 200:
        return None
    return token


def token_expiry(days, now=None):
    """Returns the expiry date for a validity in days, or None if that validity is not offered."""

    try:
        days = int(days)
    except (TypeError, ValueError):
        return None
    if days not in TOKEN_DAYS:
        return None
    return (now or datetime.now()) + timedelta(days=days)


def may_use_api(username, role):
    """True if the user may use API tokens: only operators (not admins, not viewers)."""

    return role is not None and effective_role(username, role) == "operator"


def may_create_token(creator, creator_role, owner, owner_role):
    """Admins create tokens for every operator, operators only for themselves."""

    if not may_use_api(owner, owner_role):
        return False
    return effective_role(creator, creator_role) == "admin" or creator == owner


def validate_token_name(name):
    """Returns an error message if the token name is invalid, else None."""

    if not name:
        return "Token name is required"
    if len(name) > MAX_TOKEN_NAME_LENGTH:
        return f"Token name is too long (max. {MAX_TOKEN_NAME_LENGTH} characters)"
    return None


def vars_to_dict(text):
    """Returns the stored group variables ('key=value' lines) as a dict."""

    return parse_extra_vars(text)


def clean_vars(value):
    """Returns (text, error) for group variables sent as a JSON object."""

    if not isinstance(value, dict):
        return None, "ansible_vars must be an object, e.g. {\"ntp_server\": \"10.0.0.1\"}"
    lines = []
    for key, val in value.items():
        if not VAR_NAME_RE.match(key):
            return None, f"Invalid variable name '{key}' (letters, digits and _ only, not starting with a digit)"
        if isinstance(val, bool):
            val = "true" if val else "false"
        elif isinstance(val, (int, float)):
            val = str(val)
        elif not isinstance(val, str):
            return None, f"Value of '{key}' must be a string, number or boolean"
        if "\n" in val or "\r" in val:
            return None, f"Value of '{key}' must be a single line"
        lines.append(f"{key}={val.strip()}")
    return "\n".join(lines), None


def unknown_fields(data, allowed):
    """Returns an error message for fields the API doesn't know, else None."""

    unknown = sorted(set(data) - allowed)
    return f"Unknown field(s): {', '.join(unknown)}" if unknown else None


def clean_host(data, partial=False):
    """Returns (values, error) for a host sent to the API; with partial (PATCH) only the given fields are checked."""

    if not isinstance(data, dict):
        return None, "Request body must be a JSON object"
    error = unknown_fields(data, HOST_FIELDS)
    if error:
        return None, error

    values = {}
    if "hostname" in data or not partial:
        hostname = data.get("hostname")
        if not isinstance(hostname, str):
            return None, "hostname is required and must be a string"
        hostname = hostname.strip()
        error = validate_hostname(hostname)
        if error:
            return None, error
        values["hostname"] = hostname

    if "description" in data:
        description = data["description"] if data["description"] is not None else ""
        if not isinstance(description, str):
            return None, "description must be a string"
        if len(description) > MAX_DESCRIPTION_LENGTH:
            return None, f"description is too long (max. {MAX_DESCRIPTION_LENGTH} characters)"
        values["description"] = description.strip()
    elif not partial:
        values["description"] = ""

    if "groups" in data:
        groups = data["groups"]
        if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
            return None, "groups must be a list of group names"
        values["groups"] = list(dict.fromkeys(g.strip() for g in groups if g.strip()))
    elif not partial:
        values["groups"] = []

    if "is_active" in data:
        if not isinstance(data["is_active"], bool):
            return None, "is_active must be true or false"
        values["is_active"] = data["is_active"]
    elif not partial:
        values["is_active"] = True

    if partial and not values:
        return None, "Nothing to change"
    return values, None


def clean_group(data, partial=False):
    """Returns (values, error) for a group sent to the API; groups can't be renamed (PATCH only changes ansible_vars)."""

    if not isinstance(data, dict):
        return None, "Request body must be a JSON object"
    error = unknown_fields(data, GROUP_FIELDS)
    if error:
        return None, error

    values = {}
    if partial:
        if "name" in data:
            return None, "Groups can't be renamed"
    else:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            return None, "name is required and must be a string"
        name = name.strip()
        if len(name) > MAX_GROUP_NAME_LENGTH or not GROUP_NAME_RE.match(name):
            return None, "Group name can only contain letters, numbers, and underscores"
        values["name"] = name

    if "ansible_vars" in data:
        text, error = clean_vars(data["ansible_vars"] if data["ansible_vars"] is not None else {})
        if error:
            return None, error
        values["ansible_vars"] = text
    elif not partial:
        values["ansible_vars"] = ""

    if partial and not values:
        return None, "Nothing to change"
    return values, None
