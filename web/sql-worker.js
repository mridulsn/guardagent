/* Disposable SQL worker. No model access. ASCII-only source. */
(function () {
  "use strict";
  var ALLOWED_FUNCTIONS = ["abs", "avg", "ceil", "ceiling", "char", "coalesce", "concat", "concat_ws", "count", "cume_dist", "date", "datetime", "dense_rank", "exp", "first_value", "floor", "format", "glob", "hex", "if", "ifnull", "iif", "instr", "julianday", "lag", "last_value", "lead", "length", "like", "likelihood", "likely", "ln", "log", "log10", "log2", "lower", "ltrim", "max", "min", "mod", "nth_value", "ntile", "nullif", "octet_length", "percent_rank", "pi", "pow", "power", "printf", "quote", "rank", "replace", "round", "row_number", "rtrim", "sign", "sqrt", "strftime", "substr", "substring", "sum", "time", "timediff", "total", "trim", "trunc", "typeof", "unicode", "unixepoch", "unlikely", "upper"];
  var TABLES = ["customers", "products", "orders", "order_items"];
  var HEAP_BYTES = 128 * 1024 * 1024;
  function deny(rule, detail) { var e = new Error(detail); e.rule = rule; throw e; }

  function execute(db, sql, heapBytes) {
    var guard = typeof module !== "undefined" && module.exports ? require("./app.js") : globalThis.GuardAgent;
    var verdict = guard.checkSql(sql);
    if (!verdict.allowed) deny(verdict.rule, verdict.detail);
    sql = verdict.sql;
    db.exec("PRAGMA query_only = ON");
    var heap = db.exec("PRAGMA hard_heap_limit = " + (heapBytes || HEAP_BYTES));
    if (!heap.length || !heap[0].values.length || heap[0].values[0][0] > (heapBytes || HEAP_BYTES)) {
      deny("db.error", "SQLite heap limit is unavailable; execution disabled");
    }
    // sql.js 1.13 does not export sqlite3_set_authorizer or sqlite3_limit.
    // Inspect SQLite's resolved bytecode before stepping the user's statement.
    // Root-page checks cover tables AND indexes (including covering indexes);
    // function opcodes resolve quoted names. Virtual-table access is refused.
    var roots = db.exec("SELECT rootpage, tbl_name FROM sqlite_master WHERE type IN ('table','index')")[0];
    var allowedRoots = new Set();
    (roots ? roots.values : []).forEach(function (r) { if (TABLES.indexOf(r[1]) >= 0) allowedRoots.add(r[0]); });
    var plan = db.exec("EXPLAIN " + sql)[0];
    if (!plan) deny("db.error", "could not inspect query plan");
    plan.values.forEach(function (r) {
      var op = r[1], p2 = r[3], p3 = r[4], p4 = r[5];
      if (op === "OpenRead" || op === "ReopenIdx") {
        if (p3 !== 0 || !allowedRoots.has(p2)) deny("db.table_refused", "table is not on the shop allowlist");
      }
      if (/^V(?:Open|Filter|Column|Next|Update|Create|Destroy|Rename|Begin)$/.test(op)) {
        deny("db.table_refused", "virtual tables are not allowed");
      }
      if (/^(?:Function|PureFunc|AggStep|AggStep1|AggInverse|AggValue|AggFinal)$/.test(op)) {
        var name = String(p4 || "").replace(/\(.*$/, "").toLowerCase();
        if (ALLOWED_FUNCTIONS.indexOf(name) < 0) deny("db.function_refused", "function " + name + "() is not on the database allowlist");
      }
    });
    var stmt = db.prepare(sql), rows = [], columns, bytes = 0, truncated = false;
    try {
      columns = stmt.getColumnNames();
      while (stmt.step()) {
        if (rows.length === guard.MAX_ROWS) { truncated = true; break; }
        var row = stmt.get();
        row.forEach(function (v) {
          var length = typeof v === "string" ? new TextEncoder().encode(v).length : (v && v.byteLength) || 8;
          if (length > 100000) deny("db.too_large", "returned value exceeds 100000 bytes");
          bytes += length;
        });
        if (bytes > 1000000) deny("db.too_large", "returned data exceeds 1000000 bytes");
        rows.push(row);
      }
    } finally { stmt.free(); }
    return {columns: columns, rows: rows, row_count: rows.length, truncated: truncated};
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {execute: execute, ALLOWED_FUNCTIONS: ALLOWED_FUNCTIONS};
    return;
  }
  var BASE = "https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.13.0/";
  importScripts("app.js", BASE + "sql-wasm.js");
  initSqlJs({locateFile: function (f) { return BASE + f; }}).then(function (SQL) {
    self.onmessage = function (event) {
      var db;
      try {
        db = new SQL.Database(event.data.bytes);
        self.postMessage({result: execute(db, event.data.sql)});
      } catch (e) {
        var msg = String(e.message || e);
        self.postMessage({error: {rule: e.rule || (/memory|too big/i.test(msg) ? "db.too_large" : "db.error"), detail: msg}});
      } finally { if (db) db.close(); }
    };
    self.postMessage({ready: true});
  }).catch(function (e) { self.postMessage({error: {rule: "db.error", detail: String(e)}}); });
})();
