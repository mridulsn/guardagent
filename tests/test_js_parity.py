"""The browser demo re-implements the guard in JavaScript (web/app.js).
This test runs that file under Node on every guard test case and checks it
gives the same verdict and rule as the Python guard. Skipped without Node."""
import json
import math
import os
import shutil
import subprocess

import pytest

from guardagent.calcguard import check_and_eval
from guardagent.guard import check_schema
import test_guard_layer
import test_qc_regressions
from guardagent.paths import ROOT
from guardagent.search import BM25, check_search, load_docs
from guardagent.sqlguard import check_sql

import test_calcguard
import test_search
import test_sqlguard

NODE = os.environ.get("NODE") or shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")

RUNNER = """
const fs = require("fs");
const g = require(process.argv[2]);
const cases = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const out = cases.map((c) => {
  if (c.kind === "schema") return g.checkSchema(c.tool, c.args);
  if (c.kind === "sql") return g.checkSql(c.input);
  if (c.kind === "calc") return g.checkCalc(c.input);
  if (c.kind === "search") return g.checkSearch(c.query, c.doc, c.names);
  if (c.kind === "bm25") return new g.BM25(c.docs).search(c.query, 5, null).map((h) => [h.doc, h.score]);
  if (c.kind === "flags") return g.injectionFlags(c.text);
});
process.stdout.write(JSON.stringify(out));
"""

EXTRA_SQL = ["SELECT 1", "select * from orders limit 5 offset 2", "SELECT 'it''s' FROM products", "SELECT x'0A'",
             "SELECT 1 || 2", "SELECT [order] FROM (SELECT 1 AS [order])", "SELECT 1e5, .5, 0x1F"]
EXTRA_CALC = ["(max)(1, 2)", "2(3)", "abs x", "1 .real", "1.5.3", "max((1, 2))"]


def run_node(tmp_path, cases):
    script = tmp_path / "runner.js"
    script.write_text(RUNNER)
    data = tmp_path / "cases.json"
    data.write_text(json.dumps(cases))
    out = subprocess.run([NODE, str(script), str(ROOT / "web" / "app.js"), str(data)],
                         capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


def test_sql_parity(tmp_path):
    inputs = ([s for s in test_sqlguard.ALLOWED_SQL] + [s for s, _ in test_sqlguard.LIMIT_SQL]
              + [s for s, _ in test_sqlguard.BLOCKED_SQL] + EXTRA_SQL)
    js = run_node(tmp_path, [{"kind": "sql", "input": s} for s in inputs])
    for s, j in zip(inputs, js):
        py = check_sql(s)
        assert (py.allowed, py.rule, py.sql) == (j["allowed"], j["rule"], j["sql"]), s


def test_calc_parity(tmp_path):
    inputs = [e for e, _ in test_calcguard.CALC_VALUES] + [e for e, _ in test_calcguard.CALC_BLOCKED]
    js = run_node(tmp_path, [{"kind": "calc", "input": e} for e in inputs])
    for e, j in zip(inputs, js):
        py = check_and_eval(e)
        assert (py.allowed, py.rule) == (j["allowed"], j["rule"]), e
        if py.allowed:
            assert j["value"] == pytest.approx(py.value, rel=1e-12), e


def test_calc_verdict_parity_on_odd_inputs(tmp_path):
    js = run_node(tmp_path, [{"kind": "calc", "input": e} for e in EXTRA_CALC])
    for e, j in zip(EXTRA_CALC, js):
        assert check_and_eval(e).allowed == j["allowed"], e


def test_search_parity(tmp_path):
    docs = load_docs()
    names = sorted(d.name for d in docs)
    cases = [(q, d) for q, d, _ in test_search.SEARCH_BLOCKED] + [("free shipping", None), ("fees", "shipping")]
    js = run_node(tmp_path, [{"kind": "search", "query": q, "doc": d, "names": names} for q, d in cases])
    for (q, d), j in zip(cases, js):
        py = check_search(q, d, set(names))
        assert (py.allowed, py.rule) == (j["allowed"], j["rule"]), (q, d)


def test_bm25_and_flags_parity(tmp_path):
    docs = load_docs()
    dd = [{"name": d.name, "title": d.title, "text": d.text} for d in docs]
    queries = ["return window opened items", "silver tier discount", "support hours saturday",
               "partner integration notes", "bulk discount", "warranty tents", "nothing matches zzz"]
    cases = [{"kind": "bm25", "docs": dd, "query": q} for q in queries]
    cases += [{"kind": "flags", "text": d.text} for d in docs]
    js = run_node(tmp_path, cases)
    idx = BM25(docs)
    for q, j in zip(queries, js[: len(queries)]):
        py = [[h["doc"], h["score"]] for h in idx.search(q, top_k=5)]
        assert [x[0] for x in py] == [x[0] for x in j], q
        for a, b in zip(py, j):
            assert a[1] == pytest.approx(b[1], abs=1e-3)
    from guardagent.search import injection_flags
    for d, j in zip(docs, js[len(queries):]):
        assert injection_flags(d.text) == j, d.name


# QC 4, 5, 11: every quoted-function and object-position regression in both ports.
def test_qc_sql_parity(tmp_path):
    inputs = test_qc_regressions.QUOTED_CALLS + test_qc_regressions.QUOTED_TABLE_PROBES + [
        "WITH x AS (SELECT 1) REPLACE INTO customers SELECT * FROM customers",
        "SELECT replace(name, 'a', 'b') FROM products",
        "SELECT '" + "\U0001f600" * 1000 + "'",
    ]
    js = run_node(tmp_path, [{"kind": "sql", "input": s} for s in inputs])
    for s, j in zip(inputs, js):
        py = check_sql(s)
        assert (py.allowed, py.rule, py.sql) == (j["allowed"], j["rule"], j["sql"]), s


# QC 6, 7: numeric boundary differential tests, including both signs.
def test_qc_calculator_boundaries(tmp_path):
    inputs = ["01", "00", "0x_f", "0b_1", "0o_7", "log(1e15, 1.0000000000000002)",
              "abs(log(1e15, 1.0000000000000002))", "round(2.675, 2)", "1 // 0.1", "1 % 0.1"]
    for x in (0.1, 0.5, 1.005, 2.675, 1234.565, 999999999999999.5):
        for v in (math.nextafter(x, -math.inf), x, math.nextafter(x, math.inf)):
            for sign in (1, -1):
                inputs += [f"round({sign * v!r}, {nd})" for nd in (-10, -2, 0, 2, 10)]
                inputs += [f"{sign * v!r} {op} {b!r}" for op in ("//", "%") for b in (0.1, -0.1, 3.0)]
    js = run_node(tmp_path, [{"kind": "calc", "input": e} for e in inputs])
    for e, j in zip(inputs, js):
        py = check_and_eval(e)
        assert (py.allowed, py.rule) == (j["allowed"], j["rule"]), e
        if py.allowed:
            assert j["value"] == py.value, (e, py.value, j)


# QC 8: include the complete existing Python schema fixture set, not just tool guards.
def test_schema_parity(tmp_path):
    cases = list(test_guard_layer.test_schema_rules.pytestmark[0].args[1])
    cases += [(name, {}, "protocol.unknown_tool") for name in ("__proto__", "constructor", "toString")]
    cases += [("sql_query", {"query": "SELECT '" + "\U0001f600" * 1000 + "'"}, "schema.ok"),
              ("calculator", '{"expression": "2+2"}', "schema.ok"),
              ("search_docs", {"query": "q", "doc": None}, "schema.ok"),
              ("search_docs", {"query": "q", "doc": "\U0001f600" * 64}, "schema.ok"),
              ("search_docs", {"query": "q", "doc": "\U0001f600" * 65}, "schema.too_long"),
              ("sql_query", {"extra": 1}, "schema.missing_field")]
    js = run_node(tmp_path, [{"kind": "schema", "tool": t, "args": a} for t, a, _ in cases])
    for (t, a, rule), j in zip(cases, js):
        parsed, py_rule, _, _ = check_schema(t, a)
        assert py_rule == rule
        assert (parsed is not None, py_rule) == (j["allowed"], j["rule"]), (t, a)
