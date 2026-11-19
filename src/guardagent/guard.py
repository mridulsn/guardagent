"""The guard layer: sits between the model and every tool call.

    model tool call -> parse JSON -> pydantic schema -> tool-specific guard -> executor
                                     (every decision is written to the audit log)

A rejected call never reaches the executor. The model gets back an error
tool_result (is_error: true) naming the rule, so it can correct itself or
explain the refusal to the user.
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .calcguard import MAX_CALC_CHARS, check_and_eval
from .paths import DB_PATH
from .search import MAX_QUERY_CHARS, MAX_TOP_K, check_search, injection_flags
from .sqlguard import MAX_ROWS, MAX_SQL_CHARS, check_sql
from .tools import DbError, SearchExecutor, SqlExecutor

# Rows one run may get back in total. The per-query cap alone does not stop
# paging: a model can walk a table with LIMIT 50 OFFSET n (one recorded run did
# exactly that before this budget existed). This counts RETURNED rows, so it is
# not an export boundary on its own: one returned value can encode many records.
# The database allowlist refuses the aggregate functions that do that
# (group_concat, json_group_array, ...), but a recursive CTE can still build such
# a value with ||, within the 100,000-byte value limit.
MAX_RUN_ROWS = 150

# Longest tool result sent back to the model. Results above it are cut by
# structure (whole rows dropped, long page text shortened) so the model always
# gets valid JSON that says what was cut.
MODEL_RESULT_CHARS = 12_000
LONG_CELL_CHARS = 500


class SqlQueryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    query: str = Field(min_length=1, max_length=MAX_SQL_CHARS)


class SearchDocsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    query: str = Field(min_length=1, max_length=MAX_QUERY_CHARS)
    top_k: int = Field(default=3, ge=1, le=MAX_TOP_K)
    doc: str | None = Field(default=None, max_length=64)


class CalculatorArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expression: str = Field(min_length=1, max_length=MAX_CALC_CHARS)


SCHEMAS: dict[str, type[BaseModel]] = {
    "sql_query": SqlQueryArgs,
    "search_docs": SearchDocsArgs,
    "calculator": CalculatorArgs,
}

PYDANTIC_RULES = {
    "missing": "schema.missing_field",
    "extra_forbidden": "schema.extra_field",
    "string_too_long": "schema.too_long",
    "string_too_short": "schema.too_short",
    "greater_than_equal": "schema.out_of_range",
    "less_than_equal": "schema.out_of_range",
}


def schema_rule(err: ValidationError) -> tuple[str, str]:
    first = err.errors()[0]
    rule = PYDANTIC_RULES.get(first["type"], "schema.wrong_type")
    loc = ".".join(str(p) for p in first["loc"]) or "input"
    return rule, f"{loc}: {first['msg']}"


@dataclass
class Decision:
    tool: str
    raw_input: Any
    allowed: bool
    verdict: str          # allowed | modified | blocked
    rule: str
    layer: str            # protocol | schema | sql | calc | search | db
    detail: str
    executed_input: Any = None
    result: Any = None
    is_error: bool = False
    flags: list[str] = field(default_factory=list)

    def result_text(self) -> str:
        """Exactly what goes back to the model (and into the trace)."""
        if not self.allowed:
            return f"BLOCKED by guard rule {self.rule}: {self.detail}"
        if self.is_error:
            return f"ERROR ({self.rule}): {self.detail}"
        note = f"[guard: {self.rule}: {self.detail}] " if self.verdict == "modified" else ""
        body = _dump(self.result)
        if len(note) + len(body) > MODEL_RESULT_CHARS:
            body = _dump(fit_result(self.result, MODEL_RESULT_CHARS - len(note)))
        return note + body


def _dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=True, default=str)


def fit_result(result: Any, limit: int) -> Any:
    """Shrink a tool result by structure until its JSON fits in `limit` characters."""
    if not isinstance(result, dict):
        return {"note": f"result cut: {len(_dump(result))} characters is above the {limit}-character limit"}
    out = dict(result)
    if "rows" in out:
        rows = [[(v[:LONG_CELL_CHARS] + "...[cut]") if isinstance(v, str) and len(v) > LONG_CELL_CHARS else v
                 for v in r] for r in out["rows"]]
        k = len(rows)
        while True:
            out["rows"] = rows[:k]
            out["rows_sent"] = k
            out["note"] = (f"cut to {k} of {len(rows)} rows (long values shortened) to fit the "
                           f"{limit}-character result limit")
            if len(_dump(out)) <= limit:
                return out
            if k == 0:
                break
            k -= 1
    if "hits" in out:
        hits = [dict(h) for h in out["hits"]]
        out["hits"] = hits
        out["note"] = f"page text shortened to fit the {limit}-character result limit"
        while len(_dump(out)) > limit:
            longest = max(hits, key=lambda h: len(h.get("text", "")), default=None)
            if longest is None or not longest.get("text"):
                break
            longest["text"] = longest["text"][:len(longest["text"]) // 2]
            longest["text_cut"] = True
        if len(_dump(out)) <= limit:
            return out
    return {"note": f"result cut: {len(_dump(result))} characters is above the {limit}-character limit"}


class AuditLog:
    """Append-only record of every guard decision. Optionally mirrored to JSONL."""

    def __init__(self, path: Path | None = None):
        self.entries: list[dict] = []
        self.path = path

    def record(self, d: Decision, context: dict | None = None) -> dict:
        entry = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            **(context or {}),
            "tool": d.tool,
            "input": d.raw_input,
            "verdict": d.verdict,
            "rule": d.rule,
            "layer": d.layer,
            "detail": d.detail,
        }
        if d.flags:
            entry["flags"] = d.flags
        self.entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=True, default=str) + "\n")
        return entry


def check_schema(tool: str, raw_input: Any) -> tuple[BaseModel | None, str, str, str]:
    """Protocol and schema layer. Returns (parsed args or None, rule, layer, detail)."""
    if tool not in SCHEMAS:
        return None, "protocol.unknown_tool", "protocol", f"no tool named {tool!r}; tools are {', '.join(SCHEMAS)}"
    args_in = raw_input
    if isinstance(args_in, str):
        try:
            args_in = json.loads(args_in)
        except json.JSONDecodeError as e:
            return None, "schema.invalid_json", "schema", f"arguments are not valid JSON: {e.msg}"
    if not isinstance(args_in, dict):
        return None, "schema.wrong_type", "schema", "arguments must be a JSON object"
    try:
        return SCHEMAS[tool].model_validate(args_in), "schema.ok", "schema", "arguments match the schema"
    except ValidationError as e:
        rule, detail = schema_rule(e)
        return None, rule, "schema", detail


class GuardLayer:
    def __init__(self, db_path: Path = DB_PATH, audit: AuditLog | None = None, search: SearchExecutor | None = None):
        self.sql = SqlExecutor(db_path)
        self.search = search or SearchExecutor()
        self.audit = audit or AuditLog()
        self.rows_read: dict[str, int] = {}

    def handle(self, tool: str, raw_input: Any, context: dict | None = None) -> Decision:
        d = self._decide_and_run(tool, raw_input, (context or {}).get("run", "default"))
        self.audit.record(d, context)
        return d

    def handle_budget_block(self, tool: str, raw_input: Any, context: dict | None = None) -> Decision:
        d = Decision(tool, raw_input, False, "blocked", "budget.tool_calls", "budget",
                     "tool-call budget for this turn or run is used up", is_error=True)
        self.audit.record(d, context)
        return d

    def _decide_and_run(self, tool: str, raw_input: Any, run: str = "default") -> Decision:
        def block(rule: str, layer: str, detail: str) -> Decision:
            return Decision(tool, raw_input, False, "blocked", rule, layer, detail, is_error=True)

        args, rule, layer, detail = check_schema(tool, raw_input)
        if args is None:
            return block(rule, layer, detail)

        if tool == "sql_query":
            v = check_sql(args.query)
            if not v.allowed:
                return block(v.rule, "sql", v.detail)
            verdict = "modified" if v.notes else "allowed"
            used = self.rows_read.get(run, 0)
            remaining = MAX_RUN_ROWS - used
            if remaining <= 0:
                return block("budget.rows", "budget", f"this run already read {used} rows; the limit per run is {MAX_RUN_ROWS}")
            try:
                result = self.sql.run(v.sql, max_rows=min(MAX_ROWS, remaining))
            except DbError as e:
                return Decision(tool, raw_input, True, verdict, e.rule, "db", e.detail, executed_input=v.sql, is_error=True)
            self.rows_read[run] = used + result["row_count"]
            if result["truncated"] and remaining < MAX_ROWS:
                result["note"] = f"cut to {remaining} rows: run row budget of {MAX_RUN_ROWS} reached"
            return Decision(tool, raw_input, True, verdict, v.rule, "sql", v.detail, executed_input=v.sql, result=result)

        if tool == "calculator":
            v = check_and_eval(args.expression)
            if not v.allowed:
                return block(v.rule, "calc", v.detail)
            return Decision(tool, raw_input, True, "allowed", v.rule, "calc", v.detail,
                            executed_input=args.expression, result={"value": v.value})

        # search_docs
        v = check_search(args.query, args.doc, self.search.names)
        if not v.allowed:
            return block(v.rule, "search", v.detail)
        hits = self.search.run(args.query, args.top_k, v.doc)
        flags = sorted({f for h in hits for f in injection_flags(h["text"])})
        return Decision(tool, raw_input, True, "allowed", v.rule, "search", v.detail,
                        executed_input={"query": args.query, "top_k": args.top_k, "doc": v.doc},
                        result={"hits": hits}, flags=flags)


def decision_dict(d: Decision) -> dict:
    return asdict(d)
