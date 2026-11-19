"""SQL guard: allow exactly one read-only SELECT, nothing else.

The guard works on a small SQLite-aware tokenizer instead of regexes over the
raw string, so keywords inside string literals ('drop me a line') are not
mistaken for statements, and comments or stacked statements cannot hide behind
quotes. The same tokenizer is ported line for line to web/app.js, which is why
it is hand-written rather than built on a parser library that only exists in
Python (sqlglot is still used, independently, as an after-the-fact auditor in
report.py).

Rules are checked in a fixed order and the first failure wins. Every rule has a
stable name that ends up in the audit log.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_SQL_CHARS = 2000
MAX_ROWS = 50

# Control characters (except tab/newline/carriage return) and invisible Unicode
# format characters: zero-width spaces/joiners, bidi overrides, BOM, soft hyphen.
HIDDEN_CHARS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u061c\u180e\u200b-\u200f"
    "\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]"
)

# Statement keywords that can change data, schema, connection state or
# transactions. Matched as whole words outside literals, case-insensitively.
FORBIDDEN_KEYWORDS = frozenset({
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "ATTACH", "DETACH",
    "PRAGMA", "VACUUM", "REINDEX", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT",
    "RELEASE", "TRUNCATE", "GRANT", "REVOKE", "UPSERT", "MERGE",
})

# Functions that touch the file system, load code, or exist mainly to burn
# memory (randomblob(1e9)).
FORBIDDEN_FUNCTIONS = frozenset({
    "load_extension", "readfile", "writefile", "edit", "fts3_tokenizer",
    "randomblob", "zeroblob", "sqlite_compileoption_get", "sqlite_offset",
})

ALLOWED_START = frozenset({"SELECT", "WITH"})
SYSTEM_PREFIXES = ("sqlite_", "pragma_")
# Keywords that end a FROM clause at the same parenthesis depth.
CLAUSE_END = frozenset({"WHERE", "GROUP", "HAVING", "WINDOW", "ORDER", "LIMIT", "UNION", "INTERSECT",
                        "EXCEPT", "SELECT", "VALUES"})

TWO_CHAR_OPS = ("||", "<=", ">=", "<>", "!=", "==", "<<", ">>")
ONE_CHAR_OPS = set("(),.+-*/%<>=&|~")
WORD_START = re.compile(r"[A-Za-z_]")
WORD_CHARS = re.compile(r"[A-Za-z0-9_$]*")
NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
INTEGER = re.compile(r"[0-9]+")
DIGITS = "0123456789"


@dataclass
class Token:
    kind: str  # ws, comment, string, qident, number, word, op, semi
    text: str
    pos: int

    @property
    def upper(self) -> str:
        return self.text.upper()


@dataclass
class SqlVerdict:
    allowed: bool
    rule: str
    detail: str
    sql: str | None = None  # the statement to execute (may be rewritten)
    notes: list[str] = field(default_factory=list)


class SqlBlocked(Exception):
    def __init__(self, rule: str, detail: str):
        super().__init__(detail)
        self.rule = rule
        self.detail = detail


def tokenize(sql: str) -> list[Token]:
    toks: list[Token] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c in " \t\n\r\f":
            j = i
            while j < n and sql[j] in " \t\n\r\f":
                j += 1
            toks.append(Token("ws", sql[i:j], i))
            i = j
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j == -1 else j
            toks.append(Token("comment", sql[i:j], i))
            i = j
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            toks.append(Token("comment", sql[i:j], i))
            i = j
        elif c in "'\"`[":
            close = {"'": "'", '"': '"', "`": "`", "[": "]"}[c]
            j = i + 1
            while True:
                k = sql.find(close, j)
                if k == -1:
                    raise SqlBlocked("sql.unterminated_literal", f"unterminated {c} literal at position {i}")
                # A doubled quote is an escaped quote (not for [brackets]).
                if close != "]" and k + 1 < n and sql[k + 1] == close:
                    j = k + 2
                    continue
                j = k + 1
                break
            toks.append(Token("string" if c == "'" else "qident", sql[i:j], i))
            i = j
        elif c in DIGITS or (c == "." and i + 1 < n and sql[i + 1] in DIGITS):
            m = NUMBER.match(sql, i)
            toks.append(Token("number", m.group(0), i))
            i = m.end()
        elif WORD_START.match(c):
            m = WORD_CHARS.match(sql, i + 1)
            toks.append(Token("word", sql[i:m.end()], i))
            i = m.end()
        elif c == ";":
            toks.append(Token("semi", c, i))
            i += 1
        elif sql[i:i + 2] in TWO_CHAR_OPS:
            toks.append(Token("op", sql[i:i + 2], i))
            i += 2
        elif c in ONE_CHAR_OPS:
            toks.append(Token("op", c, i))
            i += 1
        elif c in "?:@$":
            raise SqlBlocked("sql.parameter", f"bind parameter '{c}' at position {i}; inline the value instead")
        elif not c.isascii():
            raise SqlBlocked("sql.non_ascii", f"non-ASCII character U+{ord(c):04X} outside a string literal at position {i}")
        else:
            raise SqlBlocked("sql.bad_char", f"unexpected character {c!r} at position {i}")
    return toks


def _unquote(tok: Token) -> str:
    return tok.text[1:-1]


def _ident(tok: Token) -> str:
    """Lower-case name of a word or quoted token, with doubled quotes collapsed."""
    if tok.kind == "word":
        return tok.text.lower()
    if tok.kind in ("qident", "string"):
        q = tok.text[0]
        inner = _unquote(tok)
        return (inner if q == "[" else inner.replace(q + q, q)).lower()
    return ""


def _object_position(sig: list[Token], idx: int, clause: dict, depth: int) -> bool:
    """True when the token at idx sits where SQLite expects a table name."""
    prev = sig[idx - 1] if idx > 0 else None
    nxt = sig[idx + 1] if idx + 1 < len(sig) else None
    if (nxt is not None and nxt.text == ".") or (prev is not None and prev.text == "."):
        return True
    if prev is None:
        return False
    if prev.kind == "word" and prev.upper == "JOIN":
        return True
    if prev.kind == "word" and prev.upper == "FROM":
        before = sig[idx - 2] if idx > 1 else None
        return not (before is not None and before.upper == "DISTINCT")
    if prev.text == ",":
        return clause.get(depth) in ("from", "on")
    if prev.text == "(":
        return clause.get(depth) == "from"
    return False


def _skip_parens(sig: list[Token], i: int) -> int:
    """sig[i] is '('; return the index just after its matching ')'."""
    depth = 0
    while i < len(sig):
        if sig[i].text == "(":
            depth += 1
        elif sig[i].text == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise SqlBlocked("sql.not_select", "unbalanced parentheses in the WITH clause")


def _check_cte_statement(sig: list[Token]) -> None:
    """WITH name [(cols)] AS [NOT] [MATERIALIZED] (...) [, ...] must be followed by SELECT.

    SQLite also accepts INSERT, REPLACE, UPDATE and DELETE after a CTE, and
    REPLACE cannot go on the keyword denylist because replace() is a function.
    """
    def bad(detail: str):
        raise SqlBlocked("sql.not_select", detail)

    i, n = 1, len(sig)
    if i < n and sig[i].upper == "RECURSIVE":
        i += 1
    while True:
        if i >= n or sig[i].kind not in ("word", "qident", "string"):
            bad("could not read the WITH clause; expected a CTE name")
        i += 1
        if i < n and sig[i].text == "(":
            i = _skip_parens(sig, i)
        if i >= n or sig[i].upper != "AS":
            bad("could not read the WITH clause; expected AS")
        i += 1
        if i < n and sig[i].upper == "NOT":
            i += 1
        if i < n and sig[i].upper == "MATERIALIZED":
            i += 1
        if i >= n or sig[i].text != "(":
            bad("could not read the WITH clause; expected ( after AS")
        i = _skip_parens(sig, i)
        if i < n and sig[i].text == ",":
            i += 1
            continue
        break
    if i >= n:
        bad("WITH clause is not followed by a statement")
    if not (sig[i].kind == "word" and sig[i].upper == "SELECT"):
        bad(f"the statement after the WITH clause starts with {sig[i].text!r}; only SELECT is allowed")


def check_sql(sql: str, max_rows: int = MAX_ROWS) -> SqlVerdict:
    try:
        return _check(sql, max_rows)
    except SqlBlocked as e:
        return SqlVerdict(False, e.rule, e.detail)


def _check(sql: str, max_rows: int) -> SqlVerdict:
    if len(sql) > MAX_SQL_CHARS:
        raise SqlBlocked("sql.too_long", f"{len(sql)} characters, limit is {MAX_SQL_CHARS}")
    m = HIDDEN_CHARS.search(sql)
    if m:
        raise SqlBlocked("sql.hidden_chars", f"invisible or control character U+{ord(m.group(0)):04X} at position {m.start()}")

    toks = tokenize(sql)
    for t in toks:
        if t.kind == "comment":
            raise SqlBlocked("sql.comment", f"comment at position {t.pos}; comments are not allowed because they can hide text")

    sig = [t for t in toks if t.kind != "ws"]
    if not sig:
        raise SqlBlocked("sql.empty", "no statement")

    # One statement only. Trailing semicolons are tolerated and stripped.
    while sig and sig[-1].kind == "semi":
        sig.pop()
    if not sig:
        raise SqlBlocked("sql.empty", "no statement")
    for t in sig:
        if t.kind == "semi":
            raise SqlBlocked("sql.multiple_statements", f"';' at position {t.pos} starts a second statement")

    for t in sig:
        if t.kind == "word" and t.upper in FORBIDDEN_KEYWORDS:
            raise SqlBlocked("sql.forbidden_keyword", f"{t.upper} is not allowed; this tool is read-only")

    if not (sig[0].kind == "word" and sig[0].upper in ALLOWED_START):
        raise SqlBlocked("sql.not_select", f"statement starts with {sig[0].text!r}; only SELECT (optionally WITH ... SELECT) is allowed")

    if sig[0].upper == "WITH":
        _check_cte_statement(sig)

    clause: dict[int, str | None] = {0: None}  # per paren depth: "from", "on" or None
    depth = 0
    for idx, t in enumerate(sig):
        prev = sig[idx - 1] if idx > 0 else None
        nxt = sig[idx + 1] if idx + 1 < len(sig) else None
        if t.kind in ("word", "qident", "string") and nxt is not None and nxt.text == "(":
            # A quoted name ("randomblob", [randomblob], `randomblob`) calls the same function.
            fname = _ident(t)
            if fname in FORBIDDEN_FUNCTIONS:
                raise SqlBlocked("sql.forbidden_function", f"function {fname}() is not allowed")
        if t.kind in ("word", "qident") or (t.kind == "string" and _object_position(sig, idx, clause, depth)):
            # Identifiers always name objects. A 'string' only does where SQLite reads it as a
            # table name (FROM 'sqlite_master'); elsewhere it is a harmless literal value.
            name = _ident(t)
            if name.startswith(SYSTEM_PREFIXES):
                raise SqlBlocked("sql.system_table", f"{name} is an internal SQLite object; use the documented schema")
        if t.text == "(":
            clause[depth + 1] = "from" if _object_position(sig, idx, clause, depth) else None
            depth += 1
        elif t.text == ")":
            clause.pop(depth, None)
            depth -= 1
        elif t.kind == "word":
            u = t.upper
            if u == "FROM" and not (prev is not None and prev.upper == "DISTINCT"):
                clause[depth] = "from"
            elif u == "JOIN":
                clause[depth] = "from"
            elif u in ("ON", "USING"):
                clause[depth] = "on"
            elif u in CLAUSE_END:
                clause[depth] = None
        elif t.text == "," and clause.get(depth) == "on":
            clause[depth] = "from"  # a comma after a join constraint starts another table

    # Row limit: find LIMIT at parenthesis depth 0.
    depth, limit_at = 0, None
    for idx, t in enumerate(sig):
        if t.text == "(":
            depth += 1
        elif t.text == ")":
            depth -= 1
        elif depth == 0 and t.kind == "word" and t.upper == "LIMIT":
            limit_at = idx
    body = sql[: sig[-1].pos + len(sig[-1].text)]  # without trailing ; and whitespace
    if limit_at is None:
        return SqlVerdict(True, "sql.limit_added", f"no LIMIT; appended LIMIT {max_rows}",
                          sql=f"{body} LIMIT {max_rows}", notes=["rewritten"])
    tail = sig[limit_at + 1:]
    count = _parse_limit_tail(tail)
    if count > max_rows:
        raise SqlBlocked("sql.limit_too_large", f"LIMIT {count} is above the cap of {max_rows} rows")
    return SqlVerdict(True, "sql.ok", "single read-only SELECT", sql=body)


def _parse_limit_tail(tail: list[Token]) -> int:
    """Accept `LIMIT n`, `LIMIT n OFFSET m` and `LIMIT m, n`. Return the row count."""
    def is_int(t: Token) -> bool:
        return t.kind == "number" and INTEGER.fullmatch(t.text) is not None

    texts = [t.upper for t in tail]
    if len(tail) == 1 and is_int(tail[0]):
        return int(tail[0].text)
    if len(tail) == 3 and is_int(tail[0]) and is_int(tail[2]):
        if texts[1] == "OFFSET":
            return int(tail[0].text)
        if texts[1] == ",":
            return int(tail[2].text)  # LIMIT offset, count
    raise SqlBlocked("sql.limit_not_literal", "LIMIT must be a plain integer (optionally with OFFSET n)")
