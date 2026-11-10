import json
import re


REDACTED_VALUE = "********"

SENSITIVE_VAR_RE = re.compile(r"passw|passwd|_pass$|^pass$|secret|token|api_?key|private_?key|credential", re.IGNORECASE)


def history_variables(extra_vars, hidden_fields=(), **info):
    """Returns the extra vars as stored in the job history, with sensitive values hidden."""

    hidden = [k for k in extra_vars if k in hidden_fields or SENSITIVE_VAR_RE.search(k)]
    stored = {k: (REDACTED_VALUE if k in hidden else v) for k, v in extra_vars.items()}
    return json.dumps({"extra_vars": stored, **info, **({"redacted_fields": hidden} if hidden else {})})


CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Prevents spreadsheet programs from running cell values as formulas."""

    text = "" if value is None else str(value)
    return "'" + text if text.startswith(CSV_FORMULA_PREFIXES) else text


def hide_sensitive(extra_vars):
    """Formats extra vars as 'key=value, …' with sensitive values hidden (e.g. on the schedule page)."""

    return ", ".join(f"{k}={REDACTED_VALUE if SENSITIVE_VAR_RE.search(str(k)) else v}" for k, v in extra_vars.items())
