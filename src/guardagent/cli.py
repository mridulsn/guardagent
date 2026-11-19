"""Command line entry point.

    guardagent ask "How many orders shipped in March?"   one question, prints the trace
    guardagent check sql "SELECT 1; DROP TABLE x"         run only the guard on one argument
    guardagent scenarios --models haiku opus             record the scenario set
    guardagent build-data                                 rebuild the database and web/data
"""
from __future__ import annotations

import argparse
import json
import sys

from .agent import run_agent
from .guard import AuditLog, GuardLayer
from .paths import RUNS_DIR, WEB_DATA
from .providers import ClaudeCLIProvider, make_provider
from .report import export_static, export_web, run_scenarios
from .scenarios import SCENARIOS
from .seed import build

TOOL_ARG = {"sql": ("sql_query", "query"), "calc": ("calculator", "expression"), "search": ("search_docs", "query")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="guardagent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("ask")
    a.add_argument("question")
    a.add_argument("--provider", choices=["anthropic", "cli"])
    a.add_argument("--model")
    c = sub.add_parser("check")
    c.add_argument("tool", choices=list(TOOL_ARG))
    c.add_argument("argument")
    s = sub.add_parser("scenarios")
    s.add_argument("--configs", nargs="+", default=["haiku:standard", "opus:standard", "opus:compromised"],
                   help="model:condition pairs; condition is standard or compromised (attacks only)")
    s.add_argument("--only", nargs="*")
    sub.add_parser("build-data")
    args = ap.parse_args(argv)

    if args.cmd == "build-data":
        build()
        export_static()
        print(f"built database and wrote {WEB_DATA.name}/shop.db, docs.json")
        return 0
    if args.cmd == "check":
        tool, field = TOOL_ARG[args.tool]
        d = GuardLayer().handle(tool, {field: args.argument})
        print(json.dumps({"verdict": d.verdict, "rule": d.rule, "detail": d.detail,
                          "executed_input": d.executed_input, "result": d.result}, indent=1, default=str))
        return 0 if d.allowed else 2
    if args.cmd == "ask":
        p = make_provider(args.provider, args.model)
        res = run_agent(p, args.question, guard=GuardLayer(audit=AuditLog(RUNS_DIR / "audit-ask.jsonl")))
        for st in res.steps:
            print(f"--- step {st['step']}")
            print("model:", (st.get("model_output") or "")[:600])
            for tc in st.get("tool_calls", []):
                print(f"  {tc['name']} {json.dumps(tc['input'])[:200]} -> {tc['verdict'].upper()} [{tc['rule']}]")
        print("\nFINAL:", res.final_answer, f"({res.status})")
        return 0
    if args.cmd == "scenarios":
        results = []
        for cfg in args.configs:
            m, _, condition = cfg.partition(":")
            condition = condition or "standard"
            chosen = [x for x in SCENARIOS if (not args.only or x.id in args.only)
                      and (condition == "standard" or x.kind == "attack")]
            p = ClaudeCLIProvider(m)
            r = run_scenarios(p, chosen, condition=condition)
            print(json.dumps(r["summary"], indent=1))
            print(f"CLI calls made: {p.calls_made}, cache hits: {p.cache_hits}")
            results.append(r)
        export_web(results)
        print(f"wrote {WEB_DATA.name}/scenarios.json")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
