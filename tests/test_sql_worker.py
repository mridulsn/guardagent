"""QC 2/3/14: execute the worker policy with a real SQLite engine, offline.

Node's built-in SQLite supplies a sql.js-shaped adapter; child processes supply
Web Worker messages/termination (native SQLite calls cannot be interrupted by
Node worker_threads; browser WASM workers can be terminated). No CDN, browser, or model access is required.
"""
import json
import subprocess

from guardagent.paths import ROOT
from guardagent.tools import ALLOWED_FUNCTIONS
from test_js_parity import NODE, pytestmark


def test_worker_cancels_recursive_aggregate_and_recovers(tmp_path):
    harness = tmp_path / "worker-test.cjs"
    harness.write_text(r'''
const {fork} = require("node:child_process");
const isMainThread = process.argv[3] !== "child";
const parentPort = {on: (event, cb) => process.on(event, cb), postMessage: x => process.send(x)};
const path = require("node:path");
const root = process.argv[2];
if (!isMainThread) {
  const {DatabaseSync} = require("node:sqlite");
  const policy = require(path.join(root, "web/sql-worker.js"));
  parentPort.on("message", ({sql}) => {
    const native = new DatabaseSync(path.join(root, "web/data/shop.db"), {readOnly: true});
    const db = {
      exec(sql) {
        const s = native.prepare(sql); s.setReturnArrays(true);
        return [{columns: s.columns().map(c => c.name), values: s.all()}];
      },
      prepare(sql) {
        const s = native.prepare(sql); s.setReturnArrays(true);
        const it = s.iterate(); let row;
        return {step() {const n = it.next(); row = n.value; return !n.done;},
          get() {return row;}, getColumnNames() {return s.columns().map(c => c.name);},
          free() {it.return();}};
      }
    };
    try {parentPort.postMessage({result: policy.execute(db, sql)});}
    catch(e) {parentPort.postMessage({error: {rule: e.rule || "db.error", detail: String(e.message || e)}});}
    finally {native.close();}
  });
  parentPort.postMessage({ready: true});
} else {
  const g = require(path.join(root, "web/app.js"));
  const policy = require(path.join(root, "web/sql-worker.js"));
  const assert = require("node:assert/strict");
  let terminations = 0, ticks = 0;
  function factory() {
    const w = fork(__filename, [root, "child"], {silent: true});
    const a = {postMessage(x) {w.send(x);}, terminate() {terminations++; w.kill("SIGKILL");}};
    w.on("message", data => a.onmessage && a.onmessage({data}));
    w.on("error", e => a.onerror && a.onerror(e));
    return a;
  }
  (async () => {
    const timer = setInterval(() => ticks++, 5);
    const run = g.createSqlRunner(factory, 100, 5000);
    const bad = await run("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c", new Uint8Array());
    assert.equal(bad.error.rule, "db.too_slow");
    assert.ok(ticks > 3, "main event loop must remain responsive");
    const ok = await run("SELECT count(*) FROM orders", new Uint8Array());
    assert.deepEqual(ok.result.rows, [[200]]);
    for (const sql of ["SELECT group_concat(name) FROM products", "SELECT json_group_array(order_id) FROM order_items"]) {
      assert.equal((await run(sql, new Uint8Array())).error.rule, "db.function_refused");
    }
    for (const sql of ["SELECT * FROM sqlite_master", "SELECT * FROM 'sqlite_schema'", "SELECT * FROM json_each('[1]')"]) {
      assert.ok((await run(sql, new Uint8Array())).error);
    }
    assert.ok((await run("WITH x AS (SELECT 1) REPLACE INTO customers SELECT * FROM customers", new Uint8Array())).error);
    const allocation = await run("SELECT printf('%200000s','x')", new Uint8Array());
    assert.ok(allocation.error || allocation.result.rows[0][0] === null);
    // Starting another query terminates the previous worker too.
    const pending = run("SELECT 1", new Uint8Array());
    const next = run("SELECT 2", new Uint8Array());
    assert.equal((await pending).error.rule, "db.cancelled");
    assert.deepEqual((await next).result.rows, [[2]]);
    clearInterval(timer);
    assert.ok(terminations >= 10);
    console.log(JSON.stringify(policy.ALLOWED_FUNCTIONS));
  })().catch(e => {console.error(e); process.exit(1);});
}
''')
    proc = subprocess.run([NODE, str(harness), str(ROOT)], capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    assert set(json.loads(proc.stdout)) == ALLOWED_FUNCTIONS
