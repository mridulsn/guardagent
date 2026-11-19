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
from .sqlguard import MAX_SQL_CHARS, check_sql
from .tools import DbError, SearchExecutor, SqlExecutor


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
        if not self.allowed:
            return f"BLOCKED by guard rule {self.rule}: {self.detail}"
        if self.is_error:
            return f"ERROR ({self.rule}): {self.detail}"
        body = json.dumps(self.result, ensure_ascii=True, default=str)
        note = f"[guard: {self.rule}: {self.detail}] " if self.verdict == "modified" else ""
        return note + body


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


class GuardLayer:
    def __init__(self, db_path: Path = DB_PATH, audit: AuditLog | None = None, search: SearchExecutor | None = None):
        self.sql = SqlExecutor(db_path)
        self.search = search or SearchExecutor()
        self.audit = audit or AuditLog()

    def handle(self, tool: str, raw_input: Any, context: dict | None = None) -> Decision:
        d = self._decide_and_run(tool, raw_input)
        self.audit.record(d, context)
        return d

    def handle_budget_block(self, tool: str, raw_input: Any, context: dict | None = None) -> Decision:
        d = Decision(tool, raw_input, False, "blocked", "budget.tool_calls", "budget",
                     "tool-call budget for this turn or run is used up", is_error=True)
        self.audit.record(d, context)
        return d

    def _decide_and_run(self, tool: str, raw_input: Any) -> Decision:
        def block(rule: str, layer: str, detail: str) -> Decision:
            return Decision(tool, raw_input, False, "blocked", rule, layer, detail, is_error=True)

        if tool not in SCHEMAS:
            return block("protocol.unknown_tool", "protocol", f"no tool named {tool!r}; tools are {', '.join(SCHEMAS)}")
        args_in = raw_input
        if isinstance(args_in, str):
            try:
                args_in = json.loads(args_in)
            except json.JSONDecodeError as e:
                return block("schema.invalid_json", "schema", f"arguments are not valid JSON: {e.msg}")
        if not isinstance(args_in, dict):
            return block("schema.wrong_type", "schema", "arguments must be a JSON object")
        try:
            args = SCHEMAS[tool].model_validate(args_in)
        except ValidationError as e:
            rule, detail = schema_rule(e)
            return block(rule, "schema", detail)

        if tool == "sql_query":
            v = check_sql(args.query)
            if not v.allowed:
                return block(v.rule, "sql", v.detail)
            verdict = "modified" if v.notes else "allowed"
            try:
                result = self.sql.run(v.sql)
            except DbError as e:
                return Decision(tool, raw_input, True, verdict, e.rule, "db", e.detail, executed_input=v.sql, is_error=True)
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
