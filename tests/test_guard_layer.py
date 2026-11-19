import json

import pytest

from guardagent.guard import AuditLog, GuardLayer


@pytest.fixture()
def guard(tmp_path):
    return GuardLayer(audit=AuditLog(tmp_path / "audit.jsonl"))


@pytest.mark.parametrize("tool,args,rule", [
    ("sql_query", {}, "schema.missing_field"),
    ("sql_query", {"query": "SELECT 1", "mode": "rw"}, "schema.extra_field"),
    ("sql_query", {"query": 5}, "schema.wrong_type"),
    ("sql_query", {"query": ["SELECT 1"]}, "schema.wrong_type"),
    ("sql_query", {"query": ""}, "schema.too_short"),
    ("sql_query", {"query": "SELECT 1 " + "x" * 3000}, "schema.too_long"),
    ("search_docs", {"query": "returns", "top_k": 9}, "schema.out_of_range"),
    ("search_docs", {"query": "returns", "top_k": "3"}, "schema.wrong_type"),   # strict: no coercion
    ("search_docs", {"query": "returns", "top_k": True}, "schema.wrong_type"),
    ("calculator", {"expression": 12}, "schema.wrong_type"),
    ("calculator", "{not json", "schema.invalid_json"),
    ("calculator", "[1]", "schema.wrong_type"),
    ("shell", {"cmd": "ls"}, "protocol.unknown_tool"),
])
def test_schema_rules(guard, tool, args, rule):
    d = guard.handle(tool, args)
    assert not d.allowed and d.is_error and d.verdict == "blocked"
    assert d.rule == rule
    assert d.result_text().startswith(f"BLOCKED by guard rule {rule}")


def test_json_string_input_is_parsed(guard):
    d = guard.handle("calculator", json.dumps({"expression": "2+2"}))
    assert d.allowed and d.result == {"value": 4}


def test_audit_log_records_every_decision(guard, tmp_path):
    guard.handle("sql_query", {"query": "SELECT count(*) FROM orders LIMIT 1"}, {"run": "t", "step": 1})
    guard.handle("sql_query", {"query": "DROP TABLE orders"}, {"run": "t", "step": 2})
    guard.handle("sql_query", {"query": "SELECT * FROM products"}, {"run": "t", "step": 3})
    lines = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [(e["verdict"], e["rule"]) for e in lines] == [
        ("allowed", "sql.ok"), ("blocked", "sql.forbidden_keyword"), ("modified", "sql.limit_added")]
    assert lines[1]["layer"] == "sql" and lines[1]["step"] == 2
    assert guard.audit.entries == lines


def test_search_result_carries_injection_flag(guard):
    d = guard.handle("search_docs", {"query": "partner integration notes", "top_k": 1})
    assert d.allowed and d.result["hits"][0]["doc"] == "partner-integration-notes.md"
    assert d.flags  # flagged in the audit log, passed through unchanged
    assert guard.audit.entries[-1]["flags"] == d.flags


def test_run_row_budget_stops_paged_export(guard):
    from guardagent.guard import MAX_RUN_ROWS
    got, rules = 0, []
    for off in range(0, 400, 50):
        d = guard.handle("sql_query", {"query": f"SELECT * FROM order_items LIMIT 50 OFFSET {off}"}, {"run": "dump"})
        rules.append(d.rule)
        if d.allowed:
            got += d.result["row_count"]
    assert got == MAX_RUN_ROWS
    assert rules[:3] == ["sql.ok"] * 3 and set(rules[3:]) == {"budget.rows"}
    # a different run has its own budget
    assert guard.handle("sql_query", {"query": "SELECT 1"}, {"run": "other"}).allowed
