import json
import math
import re

from werkzeug.datastructures import MultiDict


FIELD_TYPES = ("text", "textarea", "number", "select", "multiselect", "boolean", "password")

FIELD_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}\Z")

MAX_TEMPLATE_FIELDS = 30

TRUTHY_VALUES = ("true", "1", "yes", "on")


def parse_template_fields(raw):
    """Returns (fields, error) from the JSON sent by the survey field editor."""

    try:
        items = json.loads(raw or "[]")
    except ValueError:
        return None, "Survey fields could not be read"
    if not isinstance(items, list) or len(items) > MAX_TEMPLATE_FIELDS:
        return None, f"At most {MAX_TEMPLATE_FIELDS} survey fields are allowed"

    fields, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            return None, "Survey fields could not be read"
        var_name = str(item.get("var_name", "")).strip()
        field_type = str(item.get("field_type", "text"))
        label = str(item.get("label", "")).strip()[:255] or var_name
        options = [o.strip() for o in str(item.get("options", "")).splitlines() if o.strip()]
        default = str(item.get("default_value", "")).strip()

        if not FIELD_VAR_RE.match(var_name):
            return None, f"Invalid variable name '{var_name}' (letters, digits and _ only, not starting with a digit)"
        if var_name in seen:
            return None, f"Variable '{var_name}' is used twice"
        if field_type not in FIELD_TYPES:
            return None, f"Invalid field type for '{var_name}'"
        if field_type in ("select", "multiselect") and not options:
            return None, f"Field '{var_name}' needs at least one option (one per line)"
        if field_type == "number" and default:
            try:
                if not math.isfinite(float(default)):
                    raise ValueError
            except ValueError:
                return None, f"Default value of '{var_name}' must be a number"
        if field_type == "select" and default and default not in options:
            return None, f"Default value of '{var_name}' must be one of its options"
        if field_type == "password":
            default = ""

        seen.add(var_name)
        fields.append({"var_name": var_name, "label": label, "field_type": field_type,
                       "required": bool(item.get("required")), "default_value": default,
                       "options": options})
    return fields, None


def collect_survey_values(fields, form):
    """Returns (values, error) for the survey fields submitted when launching a template."""

    values = {}
    for field in fields:
        name, field_type = field["var_name"], field["field_type"]
        key = f"field_{name}"

        if field_type == "boolean":
            values[name] = form.get(key) == "on"
            continue
        if field_type == "multiselect":
            chosen = form.getlist(key)
            if any(choice not in field["options"] for choice in chosen):
                return None, f"Invalid choice for '{field['label']}'"
            if field["required"] and not chosen:
                return None, f"'{field['label']}' is required"
            values[name] = chosen
            continue

        raw = form.get(key, "")
        value = raw if field_type in ("textarea", "password") else raw.strip()
        if not value:
            if field["required"]:
                return None, f"'{field['label']}' is required"
            continue
        if field_type == "number":
            try:
                number = float(value)
                if not math.isfinite(number):
                    raise ValueError
            except ValueError:
                return None, f"'{field['label']}' must be a number"
            values[name] = int(number) if number.is_integer() else number
        elif field_type == "select":
            if value not in field["options"]:
                return None, f"Invalid choice for '{field['label']}'"
            values[name] = value
        else:
            values[name] = value
    return values, None


def survey_defaults_form(fields):
    """Builds form values from the default values of survey fields (scheduled runs have nobody to fill them in)."""

    form = MultiDict()
    for field in fields:
        key = f"field_{field['var_name']}"
        default = (field["default_value"] or "").strip()
        if field["field_type"] == "boolean":
            if default.lower() in TRUTHY_VALUES:
                form.add(key, "on")
        elif field["field_type"] == "multiselect":
            for value in [v.strip() for v in default.split(",") if v.strip()]:
                form.add(key, value)
        elif field["field_type"] == "select":
            value = default or (field["options"][0] if field["required"] and field["options"] else "")
            if value:
                form.add(key, value)
        elif field["field_type"] != "password" and default:
            form.add(key, default)
    return form


def survey_env_value(value):
    """Formats a survey value for an environment variable (lists comma-separated, booleans true/false)."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)
