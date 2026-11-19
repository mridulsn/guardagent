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
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f­؜᠎​-‏"
    "‪-‮⁠-⁤⁦-⁯﻿]"
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

TWO_CHAR_OPS = ("||", "<=", ">=", "<>", "!=", "==", "<<", ">>")
ONE_CHAR_OPS = set("(),.+-*/%<>=&|~")
WORD_START = re.compile(r"[A-Za-z_]")
WORD_CHARS = re.compile(r"[A-Za-z0-9_$]*")
NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
INTEGER = re.compile(r"\d+")


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
        elif c.isascii() and (c.isdigit() or (c == "." and i + 1 < n and sql[i + 1].isdigit())):
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

    for idx, t in enumerate(sig):
        if t.kind == "word" and t.text.lower() in FORBIDDEN_FUNCTIONS:
            nxt = sig[idx + 1] if idx + 1 < len(sig) else None
            if nxt is not None and nxt.text == "(":
                raise SqlBlocked("sql.forbidden_function", f"function {t.text.lower()}() is not allowed")
        # SQLite also accepts a quoted name, and even a 'string', as a table name.
        name = t.text.lower() if t.kind == "word" else _unquote(t).lower() if t.kind in ("qident", "string") else ""
        if name.startswith("sqlite_") or name.startswith("pragma_"):
            raise SqlBlocked("sql.system_table", f"{name} is an internal SQLite object; use the documented schema")

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
