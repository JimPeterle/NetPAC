import json

from werkzeug.datastructures import MultiDict

from survey import MAX_TEMPLATE_FIELDS, collect_survey_values, parse_template_fields, survey_defaults_form, survey_env_value


def field(var_name, field_type="text", **extra):
    return {"var_name": var_name, "field_type": field_type, **extra}


def parse(*items):
    return parse_template_fields(json.dumps(list(items)))


def test_parse_valid_fields():
    fields, error = parse(field("version", label="Version", required=True, default_value=" 1.2 "),
                          field("mode", "select", options="fast\nsafe\n", default_value="safe"))
    assert error is None
    assert fields[0] == {"var_name": "version", "label": "Version", "field_type": "text", "required": True,
                         "default_value": "1.2", "options": []}
    assert fields[1]["options"] == ["fast", "safe"]


def test_parse_errors():
    assert parse(field("1abc"))[1]
    assert parse(field("a"), field("a"))[1]
    assert parse(field("a", "unknown"))[1]
    assert parse(field("a", "select"))[1]
    assert parse(field("a", "number", default_value="ten"))[1]
    assert parse(field("a", "number", default_value="nan"))[1]
    assert parse(field("a", "select", options="x", default_value="y"))[1]
    assert parse(*[field(f"f{i}") for i in range(MAX_TEMPLATE_FIELDS + 1)])[1]
    assert parse_template_fields("not json")[1]


def test_password_default_is_dropped():
    fields, _ = parse(field("pw", "password", default_value="secret"))
    assert fields[0]["default_value"] == ""


FIELDS = parse(
    field("name", required=True),
    field("count", "number"),
    field("mode", "select", options="fast\nsafe"),
    field("tags", "multiselect", options="a\nb"),
    field("force", "boolean"),
)[0]


def test_collect_values():
    form = MultiDict([("field_name", " core "), ("field_count", "3"), ("field_mode", "safe"),
                      ("field_tags", "a"), ("field_tags", "b"), ("field_force", "on")])
    values, error = collect_survey_values(FIELDS, form)
    assert error is None
    assert values == {"name": "core", "count": 3, "mode": "safe", "tags": ["a", "b"], "force": True}


def test_collect_errors():
    assert collect_survey_values(FIELDS, MultiDict())[1]
    assert collect_survey_values(FIELDS, MultiDict({"field_name": "x", "field_count": "inf"}))[1]
    assert collect_survey_values(FIELDS, MultiDict({"field_name": "x", "field_mode": "other"}))[1]
    assert collect_survey_values(FIELDS, MultiDict([("field_name", "x"), ("field_tags", "c")]))[1]


def test_defaults_form_runs_through_collect():
    fields = [dict(f) for f in FIELDS]
    fields[0]["default_value"] = "core"
    fields[3]["default_value"] = "a, b"
    fields[4]["default_value"] = "yes"
    values, error = collect_survey_values(fields, survey_defaults_form(fields))
    assert error is None
    assert values == {"name": "core", "tags": ["a", "b"], "force": True}


def test_env_values():
    assert survey_env_value(True) == "true"
    assert survey_env_value(False) == "false"
    assert survey_env_value(["a", "b"]) == "a,b"
    assert survey_env_value(3) == "3"
