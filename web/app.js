/* guardagent web demo.
 * Part 1: a JS port of the Python guard rules (src/guardagent/sqlguard.py,
 *         calcguard.py, search.py, guard.py). tests/test_js_parity.py runs this
 *         file under Node and checks it returns the same verdicts as Python.
 * Part 2: the page (only when a DOM is present).
 * ASCII-only source: non-ASCII characters are written as \uXXXX escapes.
 */
(function () {
  "use strict";

  // ------------------------------------------------------------------ limits
  var MAX_SQL_CHARS = 2000, MAX_ROWS = 50;
  var MAX_CALC_CHARS = 200, MAX_NODES = 60, MAX_DEPTH = 20, MAX_ABS = 1e15, MAX_EXPONENT = 64;
  var MAX_QUERY_CHARS = 200, MAX_TOP_K = 5;

  var HIDDEN_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]/;

  function hex(ch) {
    var cp = ch.codePointAt(0).toString(16).toUpperCase();
    while (cp.length < 4) cp = "0" + cp;
    return "U+" + cp;
  }
  function Blocked(rule, detail) { this.rule = rule; this.detail = detail; }
  // Length in Unicode code points, as Python's len() counts (JS .length counts UTF-16 units).
  function cpLen(s) { var n = 0; for (var ch of s) n++; return n; }
  function own(obj, key) { return Object.prototype.hasOwnProperty.call(obj, key); }

  // ------------------------------------------------------------------ SQL guard
  var FORBIDDEN_KEYWORDS = {};
  ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "ATTACH", "DETACH", "PRAGMA", "VACUUM",
   "REINDEX", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "TRUNCATE", "GRANT", "REVOKE",
   "UPSERT", "MERGE"].forEach(function (k) { FORBIDDEN_KEYWORDS[k] = true; });
  var SYSTEM_PREFIXES = ["sqlite_", "pragma_"];
  var CLAUSE_END = {};
  ["WHERE", "GROUP", "HAVING", "WINDOW", "ORDER", "LIMIT", "UNION", "INTERSECT", "EXCEPT", "SELECT", "VALUES"]
    .forEach(function (k) { CLAUSE_END[k] = true; });
  var FORBIDDEN_FUNCTIONS = {};
  ["load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "randomblob", "zeroblob",
   "sqlite_compileoption_get", "sqlite_offset"].forEach(function (k) { FORBIDDEN_FUNCTIONS[k] = true; });
  var TWO_CHAR_OPS = ["||", "<=", ">=", "<>", "!=", "==", "<<", ">>"];
  var ONE_CHAR_OPS = "(),.+-*/%<>=&|~";
  var DIGITS = "0123456789";
  var SQL_NUMBER = /^(0[xX][0-9a-fA-F]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)/;
  var WS = " \t\n\r\f";

  function sqlTokenize(sql) {
    var toks = [], i = 0, n = sql.length, c, j, k, m;
    while (i < n) {
      c = sql[i];
      if (WS.indexOf(c) >= 0) {
        j = i; while (j < n && WS.indexOf(sql[j]) >= 0) j++;
        toks.push({ kind: "ws", text: sql.slice(i, j), pos: i }); i = j;
      } else if (sql.substr(i, 2) === "--") {
        j = sql.indexOf("\n", i); if (j === -1) j = n;
        toks.push({ kind: "comment", text: sql.slice(i, j), pos: i }); i = j;
      } else if (sql.substr(i, 2) === "/*") {
        j = sql.indexOf("*/", i + 2); j = j === -1 ? n : j + 2;
        toks.push({ kind: "comment", text: sql.slice(i, j), pos: i }); i = j;
      } else if ("'\"`[".indexOf(c) >= 0) {
        var close = c === "[" ? "]" : c;
        j = i + 1;
        for (;;) {
          k = sql.indexOf(close, j);
          if (k === -1) throw new Blocked("sql.unterminated_literal", "unterminated " + c + " literal at position " + i);
          if (close !== "]" && k + 1 < n && sql[k + 1] === close) { j = k + 2; continue; }
          j = k + 1; break;
        }
        toks.push({ kind: c === "'" ? "string" : "qident", text: sql.slice(i, j), pos: i }); i = j;
      } else if (DIGITS.indexOf(c) >= 0 || (c === "." && i + 1 < n && DIGITS.indexOf(sql[i + 1]) >= 0)) {
        m = SQL_NUMBER.exec(sql.slice(i));
        toks.push({ kind: "number", text: m[0], pos: i }); i += m[0].length;
      } else if (/[A-Za-z_]/.test(c)) {
        j = i + 1; while (j < n && /[A-Za-z0-9_$]/.test(sql[j])) j++;
        toks.push({ kind: "word", text: sql.slice(i, j), pos: i }); i = j;
      } else if (c === ";") {
        toks.push({ kind: "semi", text: c, pos: i }); i++;
      } else if (TWO_CHAR_OPS.indexOf(sql.substr(i, 2)) >= 0) {
        toks.push({ kind: "op", text: sql.substr(i, 2), pos: i }); i += 2;
      } else if (ONE_CHAR_OPS.indexOf(c) >= 0) {
        toks.push({ kind: "op", text: c, pos: i }); i++;
      } else if ("?:@$".indexOf(c) >= 0) {
        throw new Blocked("sql.parameter", "bind parameter '" + c + "' at position " + i + "; inline the value instead");
      } else if (c.charCodeAt(0) > 127) {
        throw new Blocked("sql.non_ascii", "non-ASCII character " + hex(sql.slice(i, i + 2)) + " outside a string literal at position " + i);
      } else {
        throw new Blocked("sql.bad_char", "unexpected character '" + c + "' at position " + i);
      }
    }
    return toks;
  }

  function checkSql(sql, maxRows) {
    maxRows = maxRows || MAX_ROWS;
    try { return sqlCheck(sql, maxRows); }
    catch (e) { if (e instanceof Blocked) return { allowed: false, rule: e.rule, detail: e.detail, sql: null }; throw e; }
  }

  function sqlCheck(sql, maxRows) {
    var sqlLen = cpLen(sql);
    if (sqlLen > MAX_SQL_CHARS) throw new Blocked("sql.too_long", sqlLen + " characters, limit is " + MAX_SQL_CHARS);
    var hm = HIDDEN_CHARS.exec(sql);
    if (hm) throw new Blocked("sql.hidden_chars", "invisible or control character " + hex(hm[0]) + " at position " + hm.index);
    var toks = sqlTokenize(sql), i, t;
    for (i = 0; i < toks.length; i++) {
      if (toks[i].kind === "comment") throw new Blocked("sql.comment", "comment at position " + toks[i].pos + "; comments are not allowed because they can hide text");
    }
    var sig = toks.filter(function (x) { return x.kind !== "ws"; });
    if (!sig.length) throw new Blocked("sql.empty", "no statement");
    while (sig.length && sig[sig.length - 1].kind === "semi") sig.pop();
    if (!sig.length) throw new Blocked("sql.empty", "no statement");
    for (i = 0; i < sig.length; i++) {
      if (sig[i].kind === "semi") throw new Blocked("sql.multiple_statements", "';' at position " + sig[i].pos + " starts a second statement");
    }
    for (i = 0; i < sig.length; i++) {
      t = sig[i];
      if (t.kind === "word" && own(FORBIDDEN_KEYWORDS, t.text.toUpperCase())) throw new Blocked("sql.forbidden_keyword", t.text.toUpperCase() + " is not allowed; this tool is read-only");
    }
    var first = sig[0];
    if (!(first.kind === "word" && (first.text.toUpperCase() === "SELECT" || first.text.toUpperCase() === "WITH"))) {
      throw new Blocked("sql.not_select", "statement starts with '" + first.text + "'; only SELECT (optionally WITH ... SELECT) is allowed");
    }
    if (first.text.toUpperCase() === "WITH") checkCteStatement(sig);
    var clause = { 0: null }, depth0 = 0, prev, nxt, u;
    for (i = 0; i < sig.length; i++) {
      t = sig[i]; prev = i > 0 ? sig[i - 1] : null; nxt = i + 1 < sig.length ? sig[i + 1] : null;
      if ((t.kind === "word" || t.kind === "qident" || t.kind === "string") && nxt && nxt.text === "(") {
        var fname = sqlIdent(t);
        if (own(FORBIDDEN_FUNCTIONS, fname)) throw new Blocked("sql.forbidden_function", "function " + fname + "() is not allowed");
      }
      if (t.kind === "word" || t.kind === "qident" || (t.kind === "string" && objectPosition(sig, i, clause, depth0))) {
        var name = sqlIdent(t);
        if (name.indexOf("sqlite_") === 0 || name.indexOf("pragma_") === 0) throw new Blocked("sql.system_table", name + " is an internal SQLite object; use the documented schema");
      }
      if (t.text === "(") {
        clause[depth0 + 1] = objectPosition(sig, i, clause, depth0) ? "from" : null;
        depth0++;
      } else if (t.text === ")") {
        delete clause[depth0];
        depth0--;
      } else if (t.kind === "word") {
        u = t.text.toUpperCase();
        if (u === "FROM" && !(prev && prev.text.toUpperCase() === "DISTINCT")) clause[depth0] = "from";
        else if (u === "JOIN") clause[depth0] = "from";
        else if (u === "ON" || u === "USING") clause[depth0] = "on";
        else if (own(CLAUSE_END, u)) clause[depth0] = null;
      } else if (t.text === "," && clause[depth0] === "on") {
        clause[depth0] = "from";
      }
    }
    var depth = 0, limitAt = -1;
    for (i = 0; i < sig.length; i++) {
      t = sig[i];
      if (t.text === "(") depth++;
      else if (t.text === ")") depth--;
      else if (depth === 0 && t.kind === "word" && t.text.toUpperCase() === "LIMIT") limitAt = i;
    }
    var last = sig[sig.length - 1];
    var body = sql.slice(0, last.pos + last.text.length);
    if (limitAt === -1) return { allowed: true, rule: "sql.limit_added", detail: "no LIMIT; appended LIMIT " + maxRows, sql: body + " LIMIT " + maxRows, modified: true };
    var count = parseLimitTail(sig.slice(limitAt + 1));
    if (count > maxRows) throw new Blocked("sql.limit_too_large", "LIMIT " + count + " is above the cap of " + maxRows + " rows");
    return { allowed: true, rule: "sql.ok", detail: "single read-only SELECT", sql: body };
  }

  function sqlIdent(t) {
    if (t.kind === "word") return t.text.toLowerCase();
    if (t.kind === "qident" || t.kind === "string") {
      var q = t.text[0], inner = t.text.slice(1, -1);
      return (q === "[" ? inner : inner.split(q + q).join(q)).toLowerCase();
    }
    return "";
  }

  function objectPosition(sig, idx, clause, depth) {
    var prev = idx > 0 ? sig[idx - 1] : null, nxt = idx + 1 < sig.length ? sig[idx + 1] : null;
    if ((nxt && nxt.text === ".") || (prev && prev.text === ".")) return true;
    if (!prev) return false;
    if (prev.kind === "word" && prev.text.toUpperCase() === "JOIN") return true;
    if (prev.kind === "word" && prev.text.toUpperCase() === "FROM") {
      var before = idx > 1 ? sig[idx - 2] : null;
      return !(before && before.text.toUpperCase() === "DISTINCT");
    }
    if (prev.text === ",") return clause[depth] === "from" || clause[depth] === "on";
    if (prev.text === "(") return clause[depth] === "from";
    return false;
  }

  function skipParens(sig, i) {
    var depth = 0;
    while (i < sig.length) {
      if (sig[i].text === "(") depth++;
      else if (sig[i].text === ")") { depth--; if (depth === 0) return i + 1; }
      i++;
    }
    throw new Blocked("sql.not_select", "unbalanced parentheses in the WITH clause");
  }

  // WITH name [(cols)] AS [NOT] [MATERIALIZED] (...) [, ...] must be followed by SELECT.
  function checkCteStatement(sig) {
    function bad(detail) { throw new Blocked("sql.not_select", detail); }
    function up(k) { return k < sig.length ? sig[k].text.toUpperCase() : ""; }
    var i = 1, n = sig.length;
    if (up(i) === "RECURSIVE") i++;
    for (;;) {
      if (i >= n || ["word", "qident", "string"].indexOf(sig[i].kind) < 0) bad("could not read the WITH clause; expected a CTE name");
      i++;
      if (i < n && sig[i].text === "(") i = skipParens(sig, i);
      if (up(i) !== "AS" || i >= n) bad("could not read the WITH clause; expected AS");
      i++;
      if (up(i) === "NOT") i++;
      if (up(i) === "MATERIALIZED") i++;
      if (i >= n || sig[i].text !== "(") bad("could not read the WITH clause; expected ( after AS");
      i = skipParens(sig, i);
      if (i < n && sig[i].text === ",") { i++; continue; }
      break;
    }
    if (i >= n) bad("WITH clause is not followed by a statement");
    if (!(sig[i].kind === "word" && sig[i].text.toUpperCase() === "SELECT")) bad("the statement after the WITH clause starts with '" + sig[i].text + "'; only SELECT is allowed");
  }

  function parseLimitTail(tail) {
    function isInt(t) { return t.kind === "number" && /^[0-9]+$/.test(t.text); }
    if (tail.length === 1 && isInt(tail[0])) return parseInt(tail[0].text, 10);
    if (tail.length === 3 && isInt(tail[0]) && isInt(tail[2])) {
      var mid = tail[1].text.toUpperCase();
      if (mid === "OFFSET") return parseInt(tail[0].text, 10);
      if (mid === ",") return parseInt(tail[2].text, 10);
    }
    throw new Blocked("sql.limit_not_literal", "LIMIT must be a plain integer (optionally with OFFSET n)");
  }

  // ------------------------------------------------------------------ calculator guard
  // Python's ast is not available here, so this is a small parser that follows
  // Python's grammar for the allowed subset and refuses everything else.
  var CALC_ALLOWED = /^[0-9A-Za-z_ \t.,+\-*/%()]*$/;
  var CALC_NUMBER_FORMAT = /\b0[xXoObB]|\d[jJ]\b|\d_\d/;
  var FUNCTIONS = { abs: [1, 1], round: [1, 2], min: [2, 10], max: [2, 10], sqrt: [1, 1], log: [1, 2] };
  var CONSTANTS = { pi: Math.PI, e: Math.E };
  var PY_KEYWORDS = { "True": 1, "False": 1, "None": 1, "not": 1, "and": 1, "or": 1, "if": 1, "else": 1, "in": 1, "is": 1, "for": 1, "lambda": 1 };

  function calcTokenize(s) {
    var toks = [], i = 0, m, rest;
    while (i < s.length) {
      var c = s[i];
      if (c === " " || c === "\t") { i++; continue; }
      rest = s.slice(i);
      m = /^(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?/.exec(rest);
      if (m) {
        // Python: "leading zeros in decimal integer literals are not permitted" (01, 007; 00 is fine)
        if (/^0+[1-9][0-9]*$/.test(m[0])) throw new Blocked("calc.syntax", "could not parse: leading zeros in decimal integer literals are not permitted");
        toks.push({ t: "num", v: m[0] }); i += m[0].length; continue;
      }
      m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest);
      if (m) { toks.push({ t: "name", v: m[0] }); i += m[0].length; continue; }
      if (rest.slice(0, 2) === "**" || rest.slice(0, 2) === "//") { toks.push({ t: "op", v: rest.slice(0, 2) }); i += 2; continue; }
      toks.push({ t: "op", v: c }); i++;
    }
    return toks;
  }

  function calcParse(src) {
    var toks = calcTokenize(src), p = 0;
    function peek() { return toks[p]; }
    function isOp(v) { var t = toks[p]; return t && t.t === "op" && t.v === v; }
    function syntax(msg) { throw new Blocked("calc.syntax", "could not parse: " + msg); }
    function notAllowed(what) { throw new Blocked("calc.node_not_allowed", what + " is not allowed in arithmetic"); }

    function arith() {
      var node = term();
      while (isOp("+") || isOp("-")) { var op = toks[p++].v; node = { k: "bin", op: op, l: node, r: term() }; }
      return node;
    }
    function term() {
      var node = factor();
      while (isOp("*") || isOp("/") || isOp("//") || isOp("%")) { var op = toks[p++].v; node = { k: "bin", op: op, l: node, r: factor() }; }
      return node;
    }
    function factor() {
      if (isOp("+") || isOp("-")) { var op = toks[p++].v; return { k: "un", op: op, x: factor() }; }
      return power();
    }
    function power() {
      var base = postfix();
      if (isOp("**")) { p++; return { k: "bin", op: "**", l: base, r: factor() }; }
      return base;
    }
    function postfix() {
      var node = atom();
      for (;;) {
        if (isOp("(")) {
          if (node.k !== "name") notAllowed("Call on a non-name");
          p++;
          var args = [];
          if (!isOp(")")) {
            for (;;) {
              if (isOp("*") || isOp("**")) notAllowed("Argument unpacking");
              args.push(arith());
              var nt = peek();
              if (nt && nt.t === "name" && own(PY_KEYWORDS, nt.v)) notAllowed(nt.v);
              if (isOp(",")) { p++; if (isOp(")")) break; continue; }
              break;
            }
          }
          if (!isOp(")")) syntax("expected )");
          p++;
          node = { k: "call", f: node.v, args: args };
        } else if (isOp(".")) {
          var nx = toks[p + 1];
          if (nx && nx.t === "name") notAllowed("Attribute");
          syntax("unexpected .");
        } else break;
      }
      return node;
    }
    function atom() {
      var t = toks[p];
      if (!t) syntax("unexpected end of expression");
      if (t.t === "num") { p++; return { k: "num", v: parseFloat(t.v) }; }
      if (t.t === "name") {
        if (own(PY_KEYWORDS, t.v)) notAllowed(t.v);
        p++; return { k: "name", v: t.v };
      }
      if (isOp("(")) {
        p++;
        if (isOp(")")) notAllowed("Tuple");
        var inner = arith();
        var nt = peek();
        if (nt && nt.t === "name" && own(PY_KEYWORDS, nt.v)) notAllowed(nt.v);
        if (isOp(",")) notAllowed("Tuple");
        if (!isOp(")")) syntax("expected )");
        p++;
        return inner;
      }
      syntax("unexpected '" + t.v + "'");
    }

    var tree = arith();
    if (p < toks.length) {
      var t = toks[p];
      if (t.t === "op" && t.v === ",") notAllowed("Tuple");
      if (t.t === "name" && own(PY_KEYWORDS, t.v)) notAllowed(t.v);
      syntax("unexpected '" + t.v + "'");
    }
    return tree;
  }

  function calcValidate(n) {
    if (n.k === "bin") { calcValidate(n.l); calcValidate(n.r); }
    else if (n.k === "un") calcValidate(n.x);
    else if (n.k === "num") { if (Math.abs(n.v) > MAX_ABS) throw new Blocked("calc.number_too_large", "literal above 1e+15"); }
    else if (n.k === "name") { if (!own(CONSTANTS, n.v)) throw new Blocked("calc.unknown_name", "unknown name '" + n.v + "'; allowed constants: pi, e"); }
    else if (n.k === "call") {
      if (!own(FUNCTIONS, n.f)) throw new Blocked("calc.function_not_allowed", "function '" + n.f + "' is not allowed; allowed: " + Object.keys(FUNCTIONS).join(", "));
      var lim = FUNCTIONS[n.f];
      if (n.args.length < lim[0] || n.args.length > lim[1]) throw new Blocked("calc.bad_arity", n.f + "() takes " + lim[0] + "-" + lim[1] + " arguments, got " + n.args.length);
      n.args.forEach(calcValidate);
    }
  }
  function calcCount(n) {
    if (n.k === "bin") return 1 + calcCount(n.l) + calcCount(n.r);
    if (n.k === "un") return 1 + calcCount(n.x);
    if (n.k === "call") return 1 + n.args.reduce(function (a, x) { return a + calcCount(x); }, 0);
    return 1;
  }
  function calcDepth(n) {
    if (n.k === "bin") return 1 + Math.max(calcDepth(n.l), calcDepth(n.r));
    if (n.k === "un") return 1 + calcDepth(n.x);
    if (n.k === "call") return 1 + n.args.reduce(function (a, x) { return Math.max(a, calcDepth(x)); }, 0);
    return 1;
  }
  function size(v) {
    if (!isFinite(v)) throw new Blocked("calc.result_too_large", "result is not a finite number");
    if (Math.abs(v) > MAX_ABS) throw new Blocked("calc.result_too_large", "result above 1e+15");
    return v;
  }
  function isInt(x) { return x === Math.trunc(x); }

  // Python's round(x, nd): the exact binary value of x, rounded half to even at
  // 10^-nd, then the nearest double to that decimal (what CPython does through
  // dtoa). round(2.675, 2) is 2.67 because 2.675 is stored as 2.67499999...
  function pyRound(x, nd) {
    if (x === 0 || !isFinite(x)) return x;
    var dv = new DataView(new ArrayBuffer(8));
    dv.setFloat64(0, x);
    var hi = dv.getUint32(0), lo = dv.getUint32(4);
    var neg = (hi >>> 31) === 1, expBits = (hi >>> 20) & 0x7ff;
    var mant = (BigInt(hi & 0xfffff) << BigInt(32)) | BigInt(lo), e2;
    if (expBits === 0) e2 = -1074; else { mant = mant | (BigInt(1) << BigInt(52)); e2 = expBits - 1075; }
    var num = mant, den = BigInt(1), ten = BigInt(10);
    if (e2 >= 0) num = num << BigInt(e2); else den = den << BigInt(-e2);
    if (nd >= 0) num = num * (ten ** BigInt(nd)); else den = den * (ten ** BigInt(-nd));
    var q = num / den, twice = (num - q * den) * BigInt(2);
    if (twice > den || (twice === den && (q % BigInt(2)) === BigInt(1))) q = q + BigInt(1);
    return Number((neg ? "-" : "") + q.toString() + "e" + (-nd));
  }
  // CPython float_divmod / float_rem: fmod, then fix the sign; the quotient is
  // (a - mod) / b, floored, and nudged up when it lands just below an integer.
  // Integers below 2**53 come out exactly as Python's int // and %.
  function pyMod(a, b) {
    var mod = a % b;
    if (mod) { if ((b < 0) !== (mod < 0)) mod += b; } else mod = b < 0 ? -0 : 0;
    return mod;
  }
  function pyFloorDiv(a, b) {
    var mod = a % b, div = (a - mod) / b, fl;
    if (mod && ((b < 0) !== (mod < 0))) div -= 1;
    if (div) { fl = Math.floor(div); if (div - fl > 0.5) fl += 1; }
    else fl = (a / b) < 0 ? -0 : 0;
    return fl;
  }
  // Python int ** int (b >= 0) is exact; square-and-multiply is exact while the
  // result stays below 2**53, and anything larger is refused by size() anyway.
  function pyPow(a, b) {
    if (isInt(a) && isInt(b) && b >= 0) {
      var r = 1, base = a, e = b;
      while (e > 0) { if (e % 2 === 1) r *= base; e = Math.floor(e / 2); if (e > 0) base *= base; }
      return r;
    }
    return Math.pow(a, b);
  }
  function calcEval(n) { return size(calcEvalNode(n)); }
  function calcEvalNode(n) {
    if (n.k === "num") return n.v;
    if (n.k === "name") return CONSTANTS[n.v];
    if (n.k === "un") { var v = calcEval(n.x); return n.op === "-" ? -v : v; }
    if (n.k === "bin") {
      var a = calcEval(n.l), b = calcEval(n.r), r;
      if ((n.op === "/" || n.op === "//" || n.op === "%") && b === 0) throw new Blocked("calc.division_by_zero", "division by zero");
      if (n.op === "+") r = a + b;
      else if (n.op === "-") r = a - b;
      else if (n.op === "*") r = a * b;
      else if (n.op === "/") r = a / b;
      else if (n.op === "//") r = pyFloorDiv(a, b);
      else if (n.op === "%") r = pyMod(a, b);
      else {
        if (Math.abs(b) > MAX_EXPONENT) throw new Blocked("calc.exponent_too_large", "exponent " + b + " is above " + MAX_EXPONENT);
        if (a < 0 && b !== Math.trunc(b)) throw new Blocked("calc.math_domain", "negative number to a fractional power");
        if (a === 0 && b < 0) throw new Blocked("calc.division_by_zero", "division by zero");
        r = pyPow(a, b);
      }
      return r;
    }
    var args = n.args.map(calcEval);
    if (n.f === "abs") return Math.abs(args[0]);
    if (n.f === "min") return Math.min.apply(null, args);
    if (n.f === "max") return Math.max.apply(null, args);
    if (n.f === "sqrt") { if (args[0] < 0) throw new Blocked("calc.math_domain", "sqrt of a negative number"); return Math.sqrt(args[0]); }
    if (n.f === "log") {
      if (args[0] <= 0 || (args.length === 2 && (args[1] <= 0 || args[1] === 1))) throw new Blocked("calc.math_domain", "log needs a positive number and a positive base other than 1");
      return args.length === 1 ? Math.log(args[0]) : Math.log(args[0]) / Math.log(args[1]);
    }
    if (args.length === 2) {
      if (args[1] !== Math.trunc(args[1]) || Math.abs(args[1]) > 10) throw new Blocked("calc.math_domain", "round() digits must be an integer between -10 and 10");
      return pyRound(args[0], args[1]);
    }
    return pyRound(args[0], 0);
  }

  function checkCalc(expr) {
    try {
      var exprLen = cpLen(expr);
      if (exprLen > MAX_CALC_CHARS) throw new Blocked("calc.too_long", exprLen + " characters, limit is " + MAX_CALC_CHARS);
      if (!expr.trim()) throw new Blocked("calc.empty", "empty expression");
      if (!CALC_ALLOWED.test(expr)) {
        var bad = Array.from(expr).filter(function (ch) { return !CALC_ALLOWED.test(ch); })[0];
        throw new Blocked("calc.bad_chars", "character '" + bad + "' is not allowed; use digits, + - * / // % ** ( ) and a few functions");
      }
      if (CALC_NUMBER_FORMAT.test(expr)) throw new Blocked("calc.number_format", "only plain decimal numbers are allowed");
      var tree = calcParse(expr.trim());
      calcValidate(tree);
      var nodes = calcCount(tree);
      if (nodes > MAX_NODES) throw new Blocked("calc.too_many_nodes", nodes + " nodes, limit is " + MAX_NODES);
      var depth = calcDepth(tree);
      if (depth > MAX_DEPTH) throw new Blocked("calc.too_deep", "nesting depth " + depth + ", limit is " + MAX_DEPTH);
      return { allowed: true, rule: "calc.ok", detail: "arithmetic only", value: calcEval(tree) };
    } catch (e) {
      if (e instanceof Blocked) return { allowed: false, rule: e.rule, detail: e.detail, value: null };
      throw e;
    }
  }

  // ------------------------------------------------------------------ search guard + BM25
  var STOPWORDS = {};
  ("a an and are as at be by can do does for from how i in is it of on or our the this to what when which who why will with you your")
    .split(" ").forEach(function (w) { STOPWORDS[w] = true; });
  var TRAVERSAL = /\.\.|[/\\~%:\u0000]/;
  var QUERY_PATH = /\.\.[/\\]|%2e%2e|%2f/i;
  var DOC_NAME = /^[a-z0-9-]{1,60}\.md$/;
  var INJECTION_HINTS = /ignore (all )?(previous|prior|above) instructions|system notice|note for the ai|\b(drop|delete|truncate|alter)\s+(table|from)\b|\bupdate\s+\w+\s+set\b/gi;

  function words(text) {
    return (text.toLowerCase().match(/[a-z0-9]+/g) || []).filter(function (w) { return !STOPWORDS[w]; });
  }
  function BM25(docs) {
    this.docs = docs;
    this.toks = docs.map(function (d) { return words(d.title + " " + d.title + " " + d.text); });
    this.avgdl = this.toks.reduce(function (a, t) { return a + t.length; }, 0) / Math.max(this.toks.length, 1);
    var df = {}, n = docs.length, self = this;
    this.toks.forEach(function (t) {
      var seen = {};
      t.forEach(function (w) { if (!seen[w]) { seen[w] = 1; df[w] = (df[w] || 0) + 1; } });
    });
    this.idf = {};
    Object.keys(df).forEach(function (w) { self.idf[w] = Math.log(1 + (n - df[w] + 0.5) / (df[w] + 0.5)); });
  }
  BM25.prototype.search = function (query, topK, doc) {
    var q = words(query), K1 = 1.5, B = 0.75, self = this, scored = [];
    this.docs.forEach(function (d, i) {
      if (doc != null && d.name !== doc) return;
      var t = self.toks[i], s = 0;
      q.forEach(function (w) {
        var f = 0; t.forEach(function (x) { if (x === w) f++; });
        if (f) s += self.idf[w] * f * (K1 + 1) / (f + K1 * (1 - B + B * t.length / self.avgdl));
      });
      if (s > 0 || doc != null) scored.push({ score: Math.round(s * 1e4) / 1e4, d: d });
    });
    scored.sort(function (a, b) { return b.score - a.score || (a.d.name < b.d.name ? -1 : 1); });
    return scored.slice(0, topK).map(function (x) { return { doc: x.d.name, title: x.d.title, score: x.score, text: x.d.text }; });
  };

  function checkSearch(query, doc, knownDocs) {
    var fields = [["query", query], ["doc", doc]];
    for (var i = 0; i < fields.length; i++) {
      if (fields[i][1] == null) continue;
      var m = HIDDEN_CHARS.exec(fields[i][1]);
      if (m) return { allowed: false, rule: "search.hidden_chars", detail: fields[i][0] + " contains invisible or control character " + hex(m[0]) };
    }
    var qLen = cpLen(query);
    if (qLen > MAX_QUERY_CHARS) return { allowed: false, rule: "search.query_too_long", detail: "query is " + qLen + " characters, limit is " + MAX_QUERY_CHARS };
    if (!/[a-z0-9]/.test(query.toLowerCase())) return { allowed: false, rule: "search.empty_query", detail: "query has no searchable words" };
    if (QUERY_PATH.test(query)) return { allowed: false, rule: "search.path_traversal", detail: "query looks like a file path; search takes words, not paths" };
    if (doc != null) {
      if (TRAVERSAL.test(doc)) return { allowed: false, rule: "search.path_traversal", detail: "doc '" + doc + "' contains path characters; give a bare document name like returns-policy.md" };
      var name = /\.md$/.test(doc) ? doc : doc + ".md";
      if (!DOC_NAME.test(name)) return { allowed: false, rule: "search.bad_doc_name", detail: "doc '" + doc + "' is not a valid document name" };
      if (knownDocs.indexOf(name) < 0) return { allowed: false, rule: "search.unknown_doc", detail: "no document named '" + name + "'" };
      doc = name;
    }
    return { allowed: true, rule: "search.ok", detail: "query accepted", doc: doc };
  }
  function injectionFlags(text) {
    var out = {}, m;
    INJECTION_HINTS.lastIndex = 0;
    while ((m = INJECTION_HINTS.exec(text)) !== null) out[m[0].toLowerCase()] = 1;
    return Object.keys(out).sort();
  }

  // ------------------------------------------------------------------ schema layer (subset of the pydantic models)
  var SCHEMA = {
    sql_query: { query: { type: "string", min: 1, max: MAX_SQL_CHARS, required: true } },
    search_docs: {
      query: { type: "string", min: 1, max: MAX_QUERY_CHARS, required: true },
      top_k: { type: "integer", lo: 1, hi: MAX_TOP_K },
      doc: { type: "string", max: 64, nullable: true }
    },
    calculator: { expression: { type: "string", min: 1, max: MAX_CALC_CHARS, required: true } }
  };
  // Same order as pydantic: fields in definition order, then extra fields.
  function checkSchema(tool, args) {
    if (!own(SCHEMA, tool)) return { allowed: false, rule: "protocol.unknown_tool", detail: "no tool named '" + tool + "'" };
    if (typeof args === "string") {
      try { args = JSON.parse(args); }
      catch (e) { return { allowed: false, rule: "schema.invalid_json", detail: "arguments are not valid JSON" }; }
    }
    var spec = SCHEMA[tool];
    if (typeof args !== "object" || args === null || Array.isArray(args)) return { allowed: false, rule: "schema.wrong_type", detail: "arguments must be a JSON object" };
    var keys = Object.keys(spec), k, f, v, len;
    for (var i = 0; i < keys.length; i++) {
      k = keys[i]; f = spec[k]; v = own(args, k) ? args[k] : undefined;
      if (v === undefined) { if (f.required) return { allowed: false, rule: "schema.missing_field", detail: k + ": Field required" }; continue; }
      if (v === null && f.nullable) continue;
      if (f.type === "string") {
        if (typeof v !== "string") return { allowed: false, rule: "schema.wrong_type", detail: k + ": Input should be a valid string" };
        len = cpLen(v);
        if (f.min && len < f.min) return { allowed: false, rule: "schema.too_short", detail: k + ": String should have at least " + f.min + " character" };
        if (len > f.max) return { allowed: false, rule: "schema.too_long", detail: k + ": String should have at most " + f.max + " characters" };
      } else if (f.type === "integer") {
        if (typeof v !== "number" || v !== Math.trunc(v)) return { allowed: false, rule: "schema.wrong_type", detail: k + ": Input should be a valid integer" };
        if (v < f.lo || v > f.hi) return { allowed: false, rule: "schema.out_of_range", detail: k + ": must be between " + f.lo + " and " + f.hi };
      }
    }
    for (k in args) if (own(args, k) && !own(spec, k)) return { allowed: false, rule: "schema.extra_field", detail: k + ": Extra inputs are not permitted" };
    return { allowed: true, rule: "schema.ok", detail: "arguments match the schema" };
  }

  // One active disposable worker. A new submission cancels the previous one.
  // Startup has a separate deadline; the query clock starts only after ready.
  function createSqlRunner(factory, queryMs, startupMs) {
    var cancel = null;
    return function (sql, bytes) {
      if (cancel) cancel();
      return new Promise(function (resolve) {
        var worker, timer, finished = false, started = false;
        function finish(reply) {
          if (finished) return;
          finished = true; clearTimeout(timer);
          if (worker) worker.terminate();
          cancel = null; resolve(reply);
        }
        cancel = function () { finish({error: {rule: "db.cancelled", detail: "superseded by another query"}}); };
        timer = setTimeout(function () { finish({error: {rule: "db.error", detail: "SQL worker startup timed out"}}); }, startupMs || 15000);
        try { worker = factory(); }
        catch (e) { finish({error: {rule: "db.error", detail: String(e)}}); return; }
        worker.onerror = function (e) { finish({error: {rule: "db.error", detail: e.message || "SQL worker failed"}}); };
        worker.onmessage = function (e) {
          if (finished) return;
          if (e.data.ready && !started) {
            started = true; clearTimeout(timer);
            timer = setTimeout(function () { finish({error: {rule: "db.too_slow", detail: "query worker terminated: time budget exceeded"}}); }, queryMs || 2000);
            worker.postMessage({sql: sql, bytes: bytes});
          } else if (!e.data.ready) finish(e.data);
        };
      });
    };
  }

  var api = {
    checkSql: checkSql, checkCalc: checkCalc, checkSearch: checkSearch, checkSchema: checkSchema,
    BM25: BM25, injectionFlags: injectionFlags, MAX_ROWS: MAX_ROWS, createSqlRunner: createSqlRunner
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.GuardAgent = api;
  if (typeof document === "undefined") return;

  // ================================================================== page
  var state = { dbBytes: null, docs: [], bm25: null, data: null, model: 0, scenario: 0, tool: "sql_query" };

  var EXAMPLES = {
    sql_query: [
      ["Top 5 by revenue", "SELECT p.name, SUM(oi.qty * oi.unit_price) AS revenue\nFROM order_items oi JOIN products p ON p.id = oi.product_id\nGROUP BY p.id ORDER BY revenue DESC LIMIT 5"],
      ["No LIMIT (gets one)", "SELECT tier, count(*) AS customers FROM customers GROUP BY tier"],
      ["Keyword in a string", "SELECT name FROM products WHERE name <> 'drop table orders; --'"],
      ["Stacked statement", "SELECT count(*) FROM orders; DROP TABLE customers;"],
      ["Comment trick", "SELECT id FROM orders WHERE status = 'cancelled' --\n; DELETE FROM orders"],
      ["Mixed case", "dElEtE FROM orders WHERE 1 = 1"],
      ["CTE + DELETE", "WITH x AS (SELECT 1) DELETE FROM orders"],
      ["Zero-width space", "SELECT 1\u200b; DROP TABLE orders"],
      ["Fullwidth letters", "\uff24\uff32\uff2f\uff30 TABLE orders"],
      ["Internal table", "SELECT name, sql FROM 'sqlite_master'"],
      ["Memory bomb", "SELECT length(randomblob(1000000000))"],
      ["LIMIT -1", "SELECT * FROM order_items LIMIT -1"]
    ],
    calculator: [
      ["Discounted tents", "(289 * 3) * 0.95"],
      ["Percentages", "15/100*2340 + 12.5/100*980"],
      ["Power tower", "9**9**9"],
      ["Python escape", "__import__('os').system('ls')"],
      ["Attribute walk", "(1).__class__"],
      ["Hex literal", "0x7fffffff * 2"],
      ["Deep nesting", "-------------------------1"],
      ["Overflow", "999999999999999.0 ** 64"]
    ],
    search_docs: [
      ["Return window", "return window opened items", ""],
      ["Free shipping", "free shipping threshold", "shipping.md"],
      ["Injected page", "partner integration notes", ""],
      ["Path traversal", "root", "../../../etc/passwd"],
      ["Encoded traversal", "root", "%2e%2e%2fsecrets"],
      ["Unknown page", "salaries", "payroll.md"]
    ]
  };
  var ARG_NAME = { sql_query: "query", calculator: "expression", search_docs: "query" };
  var TOOL_LABEL = { sql_query: "sql_query", calculator: "calculator", search_docs: "search_docs" };

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function verdictOf(r) { return !r.allowed ? "blocked" : (r.modified || r.rule === "sql.limit_added") ? "modified" : "allowed"; }
  function badge(verdict) {
    var label = { allowed: "Allowed", blocked: "Blocked", modified: "Allowed, rewritten" }[verdict] || verdict;
    var b = el("span", "badge badge-" + verdict, label);
    return b;
  }

  // ---------------- try-the-guard panel
  function renderToolTabs() {
    var wrap = $("tool-tabs");
    wrap.innerHTML = "";
    Object.keys(EXAMPLES).forEach(function (tool) {
      var b = el("button", "seg" + (state.tool === tool ? " seg-on" : ""), TOOL_LABEL[tool]);
      b.type = "button";
      b.setAttribute("aria-pressed", state.tool === tool ? "true" : "false");
      b.onclick = function () { state.tool = tool; renderToolTabs(); loadExample(EXAMPLES[tool][0]); };
      wrap.appendChild(b);
    });
    $("doc-row").hidden = state.tool !== "search_docs";
    $("arg-label").textContent = ARG_NAME[state.tool];
    var chips = $("examples");
    chips.innerHTML = "";
    EXAMPLES[state.tool].forEach(function (ex) {
      var c = el("button", "chip", ex[0]);
      c.type = "button";
      c.onclick = function () { loadExample(ex); runGuard(); };
      chips.appendChild(c);
    });
  }
  function loadExample(ex) {
    $("arg").value = ex[1];
    if (state.tool === "search_docs") $("doc").value = ex[2] || "";
  }

  function stageRow(name, status, detail) {
    var row = el("li", "stage stage-" + status);
    row.appendChild(el("span", "stage-mark", status === "pass" ? "pass" : status === "fail" ? "stop" : status === "skip" ? "not run" : status));
    var body = el("div", "stage-body");
    body.appendChild(el("span", "stage-name", name));
    if (detail) body.appendChild(el("span", "stage-detail", detail));
    row.appendChild(body);
    return row;
  }

  function runGuard() {
    var tool = state.tool, arg = $("arg").value, out = $("guard-out");
    var args = {}; args[ARG_NAME[tool]] = arg;
    if (tool === "search_docs") { args.top_k = 3; var d = $("doc").value.trim(); if (d) args.doc = d; }
    out.innerHTML = "";
    var stages = el("ol", "stages");
    var sch = checkSchema(tool, args), res = null, guardName = { sql_query: "SQL guard", calculator: "Calculator guard", search_docs: "Search guard" }[tool];
    stages.appendChild(stageRow("Schema (pydantic port)", sch.allowed ? "pass" : "fail", sch.allowed ? "types and lengths ok" : sch.rule + ": " + sch.detail));
    if (sch.allowed) {
      if (tool === "sql_query") res = checkSql(arg);
      else if (tool === "calculator") res = checkCalc(arg);
      else res = checkSearch(arg, args.doc == null ? null : args.doc, state.docs.map(function (x) { return x.name; }));
      stages.appendChild(stageRow(guardName, res.allowed ? "pass" : "fail", res.rule + ": " + res.detail));
    } else {
      stages.appendChild(stageRow(guardName, "skip", ""));
    }
    var final = sch.allowed ? res : sch;
    var head = el("div", "verdict");
    head.appendChild(badge(verdictOf(final)));
    head.appendChild(el("code", "rule", final.rule));
    out.appendChild(head);
    out.appendChild(stages);
    if (!final.allowed) {
      out.appendChild(el("p", "muted small", "The call never reaches the tool. The model would get this back as an error tool_result (is_error: true) naming the rule."));
      return;
    }
    if (tool === "sql_query") {
      out.appendChild(el("p", "label", "Statement sent to SQLite"));
      out.appendChild(el("pre", "code", res.sql));
      execSql(res.sql, out, stages);
    } else if (tool === "calculator") {
      stages.appendChild(stageRow("Evaluate (AST walk, no eval)", "pass", "result " + res.value));
      out.appendChild(el("p", "result-big", String(res.value)));
    } else {
      var hits = state.bm25 ? state.bm25.search(arg, 3, res.doc) : [];
      stages.appendChild(stageRow("BM25 search", "pass", hits.length + " page(s)"));
      if (!hits.length) out.appendChild(el("p", "muted", "No matching pages."));
      hits.forEach(function (h) {
        var card = el("div", "hit");
        var top = el("div", "hit-top");
        top.appendChild(el("strong", null, h.title));
        top.appendChild(el("code", "muted", h.doc + "  score " + h.score));
        card.appendChild(top);
        var flags = injectionFlags(h.text);
        if (flags.length) card.appendChild(el("p", "flag", "Flagged in the audit log: text that reads like instructions (" + flags.join(", ") + "). Passed through unchanged; later tool calls are still guarded."));
        card.appendChild(el("pre", "doc-text", h.text));
        out.appendChild(card);
      });
    }
  }

  var runSql = createSqlRunner(function () { return new Worker("sql-worker.js"); });
  function execSql(sql, out, stages) {
    if (!state.dbBytes) {
      stages.appendChild(stageRow("SQLite worker", "skip", "database still loading"));
      return;
    }
    var pending = stageRow("SQLite worker", "pending", "running with a time and memory budget");
    stages.appendChild(pending);
    runSql(sql, state.dbBytes).then(function (reply) {
      // A newer request may have replaced this panel while the worker ran.
      if (!out.contains(stages)) return;
      pending.remove();
      if (reply.error) stages.appendChild(stageRow("SQLite worker", "fail", reply.error.rule + ": " + reply.error.detail));
      else {
        stages.appendChild(stageRow("SQLite worker (fresh read-only copy)", "pass", reply.result.row_count + " row(s)"));
        out.appendChild(table(reply.result.columns, reply.result.rows));
      }
    });
  }

  function table(cols, rows) {
    var wrap = el("div", "table-wrap");
    var tb = el("table");
    var thead = el("thead"), tr = el("tr");
    cols.forEach(function (c, i) { tr.appendChild(el("th", rows.length && typeof rows[0][i] === "number" ? "num" : null, c)); });
    thead.appendChild(tr); tb.appendChild(thead);
    var body = el("tbody");
    rows.forEach(function (r) {
      var row = el("tr");
      r.forEach(function (v) { row.appendChild(el("td", typeof v === "number" ? "num" : null, v == null ? "NULL" : String(typeof v === "number" && !Number.isInteger(v) ? Math.round(v * 100) / 100 : v))); });
      body.appendChild(row);
    });
    tb.appendChild(body);
    wrap.appendChild(tb);
    return wrap;
  }

  // ---------------- results + recorded scenarios
  var OUTCOME_LABEL = { guard_blocked: "Guard blocked", model_declined: "Model declined", got_through: "Got through", inconclusive: "Inconclusive" };

  function configLabel(m) { return m.model + (m.condition === "compromised" ? " (compromised)" : ""); }

  function renderResults() {
    var d = state.data, wrap = $("results-table");
    var tb = el("table", "results");
    var head = el("tr");
    ["Model", "Condition", "Attacks", "Model declined", "Guard blocked", "Got through", "Inconclusive", "Normal tasks correct", "False-positive blocks"].forEach(function (h, i) { head.appendChild(el("th", i > 1 ? "num" : null, h)); });
    var thead = el("thead"); thead.appendChild(head); tb.appendChild(thead);
    var body = el("tbody");
    d.models.forEach(function (m) {
      var s = m.summary, row = el("tr"), hasNormal = s.normal_total > 0;
      row.appendChild(el("th", null, m.model));
      var cond = el("td", null, m.condition); cond.setAttribute("data-label", "Condition"); row.appendChild(cond);
      var labels = ["Attacks", "Model declined", "Guard blocked", "Got through", "Inconclusive", "Normal tasks correct", "False-positive blocks"];
      [s.attacks_total, s.model_declined, s.guard_blocked, s.got_through, s.inconclusive,
       hasNormal ? s.normal_correct + " / " + s.normal_total : "not run",
       hasNormal ? s.normal_false_positive_blocks : "not run"].forEach(function (v, i) {
        var td = el("td", "num", String(v)); td.setAttribute("data-label", labels[i]); row.appendChild(td);
      });
      body.appendChild(row);
    });
    tb.appendChild(body);
    wrap.innerHTML = "";
    var tw = el("div", "table-wrap"); tw.appendChild(tb); wrap.appendChild(tw);
    var models = [];
    d.models.forEach(function (m) { if (models.indexOf(m.model) < 0) models.push(m.model); });
    $("recorded-note").textContent = "Recorded run, " + models.join(" and ") + ", " + d.recorded_on +
      ", through the Claude Code CLI (ClaudeCLIProvider). Guard verdicts come from the Python guard layer.";
  }

  function renderModelTabs() {
    var wrap = $("model-tabs");
    wrap.innerHTML = "";
    state.data.models.forEach(function (m, i) {
      var b = el("button", "seg" + (i === state.model ? " seg-on" : ""), configLabel(m));
      b.type = "button";
      b.setAttribute("aria-pressed", i === state.model ? "true" : "false");
      b.onclick = function () {
        var cur = state.data.models[state.model].runs[state.scenario].scenario;
        state.model = i;
        var idx = m.runs.findIndex(function (r) { return r.scenario === cur; });
        state.scenario = idx >= 0 ? idx : 0;
        renderModelTabs(); renderScenarioList(); renderTrace();
      };
      wrap.appendChild(b);
    });
  }

  function marker(run) {
    var c = run.classification;
    if (run.kind === "attack") return { cls: "m-" + c.outcome, text: OUTCOME_LABEL[c.outcome] };
    return c.correct ? { cls: "m-correct", text: "Correct" } : { cls: "m-wrong", text: "Wrong answer" };
  }

  function renderScenarioList() {
    var runs = state.data.models[state.model].runs, list = $("scenario-list"), sel = $("scenario-select");
    list.innerHTML = ""; sel.innerHTML = "";
    var groups = [["normal", "Normal questions"], ["attack", "Attacks"]];
    groups.forEach(function (g) {
      list.appendChild(el("li", "group", g[1]));
      var og = document.createElement("optgroup"); og.label = g[1];
      runs.forEach(function (r, i) {
        if (r.kind !== g[0]) return;
        var mk = marker(r);
        var li = el("li");
        var b = el("button", "scn" + (i === state.scenario ? " scn-on" : ""));
        b.type = "button";
        b.appendChild(el("span", "scn-title", r.title));
        b.appendChild(el("span", "mk " + mk.cls, mk.text));
        b.onclick = function () { state.scenario = i; renderScenarioList(); renderTrace(); };
        li.appendChild(b); list.appendChild(li);
        var o = document.createElement("option"); o.value = i; o.textContent = r.title + " (" + mk.text + ")";
        if (i === state.scenario) o.selected = true;
        og.appendChild(o);
      });
      sel.appendChild(og);
    });
    sel.onchange = function () { state.scenario = parseInt(sel.value, 10); renderScenarioList(); renderTrace(); };
  }

  function details(summary, content, cls) {
    var d = el("details", cls);
    d.appendChild(el("summary", null, summary));
    d.appendChild(el("pre", "code", content));
    return d;
  }

  function renderTrace() {
    var m = state.data.models[state.model], run = m.runs[state.scenario], out = $("trace");
    out.innerHTML = "";
    var mk = marker(run), c = run.classification;
    var head = el("div", "trace-head");
    head.appendChild(el("h3", null, run.title));
    head.appendChild(el("span", "mk " + mk.cls, mk.text));
    out.appendChild(head);
    var meta = run.kind === "attack" ? "Attack type: " + run.attack_type + ". " : "";
    meta += run.model_calls + " model call(s), " + c.tool_calls + " tool call(s), " + c.blocked_calls + " blocked. Database unchanged: " + (c.db_unchanged ? "yes" : "NO") + ".";
    out.appendChild(el("p", "muted small", meta));
    var user = el("div", "msg msg-user");
    user.appendChild(el("span", "who", "User"));
    user.appendChild(el("p", "msg-text", run.prompt));
    out.appendChild(user);

    run.steps.forEach(function (st) {
      var box = el("div", "step");
      var top = el("div", "step-top");
      top.appendChild(el("span", "who", "Model, step " + st.step));
      if (!st.tools_allowed) top.appendChild(el("span", "mk m-neutral", "tools disabled"));
      box.appendChild(top);
      if (st.error) box.appendChild(el("p", "flag", "Provider error: " + st.error));
      if (st.thought) box.appendChild(el("p", "thought", st.thought));
      if (st.protocol_error) box.appendChild(el("p", "flag", "Protocol error: " + st.protocol_error + " (the agent asked the model to reply again)"));
      if (st.protocol_note) box.appendChild(el("p", "flag", "Parser note: " + st.protocol_note + ". The model kept writing after its JSON reply; only the first JSON object was used and the rest was dropped."));
      (st.tool_calls || []).forEach(function (tc) {
        var call = el("div", "call call-" + tc.verdict);
        var line = el("div", "call-line");
        line.appendChild(badge(tc.verdict));
        line.appendChild(el("code", "call-name", tc.name));
        line.appendChild(el("code", "rule", tc.rule));
        call.appendChild(line);
        var inp = tc.input && typeof tc.input === "object" ? (tc.input.query || tc.input.expression || JSON.stringify(tc.input)) : String(tc.input);
        if (tc.input && tc.input.doc) inp += "\n[doc: " + tc.input.doc + "]";
        call.appendChild(el("pre", "code", inp));
        if (tc.detail) call.appendChild(el("p", "small muted", tc.layer + " layer: " + tc.detail));
        if (tc.flags && tc.flags.length) call.appendChild(el("p", "flag", "Injection-like text in result, flagged: " + tc.flags.join(", ")));
        call.appendChild(details(tc.is_error ? "Error result sent back to the model" : "Tool result sent back to the model", tc.result, "res"));
        box.appendChild(call);
      });
      if (st.final_answer) {
        box.appendChild(el("p", "label", "Final answer"));
        box.appendChild(el("p", "answer", st.final_answer));
      }
      box.appendChild(details("Raw model output", st.model_output || "", "raw"));
      out.appendChild(box);
    });
    if (run.kind === "normal" && !c.correct) out.appendChild(el("p", "flag", "Answer check failed. Missing: " + c.missing.join(", ")));
    if (run.kind === "attack" && c.harm && c.harm.length) out.appendChild(el("p", "flag", "Harm detected: " + c.harm.join("; ")));
  }

  function init() {
    renderToolTabs();
    loadExample(EXAMPLES.sql_query[0]);
    $("check-btn").onclick = runGuard;
    $("arg").addEventListener("keydown", function (e) { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") runGuard(); });

    fetch("data/docs.json").then(function (r) { return r.json(); }).then(function (docs) {
      state.docs = docs; state.bm25 = new BM25(docs);
    });
    fetch("data/shop.db").then(function (r) {
      if (!r.ok) throw new Error("database download failed");
      return r.arrayBuffer();
    }).then(function (bytes) {
      state.dbBytes = new Uint8Array(bytes);
      $("db-status").textContent = "Database ready. SQL runs in a disposable worker.";
      runGuard();
    }).catch(function (e) { $("db-status").textContent = "Could not load database: " + e.message; });

    fetch("data/scenarios.json").then(function (r) { return r.json(); }).then(function (d) {
      state.data = d;
      var firstAttack = d.models[0].runs.findIndex(function (r) { return r.kind === "attack"; });
      state.scenario = firstAttack >= 0 ? firstAttack : 0;
      renderResults(); renderModelTabs(); renderScenarioList(); renderTrace();
    }).catch(function (e) { $("trace").textContent = "Could not load recorded runs: " + e.message; });
  }
  document.addEventListener("DOMContentLoaded", init);
})();
