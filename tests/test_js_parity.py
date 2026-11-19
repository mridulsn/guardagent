"""The browser demo re-implements the guard in JavaScript (web/app.js).
This test runs that file under Node on every guard test case and checks it
gives the same verdict and rule as the Python guard. Skipped without Node."""
import json
import os
import shutil
import subprocess

import pytest

from guardagent.calcguard import check_and_eval
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
