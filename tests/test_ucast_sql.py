import pytest

from vengtoo import ucast_to_sql


def test_regex_not_or_guardrail_example():
    # The live guardrail example:
    # NOT( sql ~ '(?i)(drop|...)' OR question ~ '(?i)(secret|...)' ).
    filter = {
        "type": "logical",
        "operator": "not",
        "conditions": [
            {
                "type": "logical",
                "operator": "or",
                "conditions": [
                    {"type": "field", "field": "sql", "operator": "regex", "value": "(?i)(drop|delete|truncate)"},
                    {"type": "field", "field": "question", "operator": "regex", "value": "(?i)(secret|password)"},
                ],
            }
        ],
    }
    where, params = ucast_to_sql(filter)
    assert where == "NOT ((sql ~ $1) OR (question ~ $2))"
    assert params == ["(?i)(drop|delete|truncate)", "(?i)(secret|password)"]


def test_and_eq_with_field_map():
    filter = {
        "type": "logical",
        "operator": "and",
        "conditions": [
            {"type": "field", "field": "owner", "operator": "eq", "value": "alice"},
            {"type": "field", "field": "status", "operator": "ne", "value": "archived"},
        ],
    }
    where, params = ucast_to_sql(filter, {"owner": "owner_id"})
    assert where == "(owner_id = $1) AND (status != $2)"
    assert params == ["alice", "archived"]


def test_const_true():
    where, params = ucast_to_sql({"type": "const", "value": True})
    assert where == "TRUE"
    assert params == []


def test_in_expands_placeholders():
    where, params = ucast_to_sql(
        {"type": "field", "field": "team", "operator": "in", "value": ["a", "b", "c"]}
    )
    assert where == "team IN ($1, $2, $3)"
    assert params == ["a", "b", "c"]


def test_rejects_injecting_field_name():
    with pytest.raises(ValueError):
        ucast_to_sql(
            {"type": "field", "field": "owner; DROP TABLE documents;--", "operator": "eq", "value": "x"}
        )
