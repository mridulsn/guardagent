"""Re-score immutable recorded traces and refresh published figures, offline.

Run from the repo root: .venv/bin/python -m scripts.refresh_recordings
Never reruns model/tool calls or replaces historical payloads or fingerprints.
"""
import copy
import json
import re
from pathlib import Path

from guardagent.agent import RunResult
from guardagent.paths import ROOT, WEB_DATA
from guardagent.report import classify, summarise
from guardagent.scenarios import BY_ID

START = "<!-- BEGIN RECORDED METRICS -->"
END = "<!-- END RECORDED METRICS -->"


def recompute(data):
    out = copy.deepcopy(data)
    for model in out["models"]:
        for run in model["runs"]:
            scenario = BY_ID[run["scenario"]]
            result = RunResult(question=run["prompt"], final_answer=run["final_answer"],
                               status=run["status"], steps=run["steps"], audit=run["audit"],
                               model_calls=run["model_calls"])
            # The traces retain only the equality result, not both fingerprints.
            # Preserve that historical observation; do not manufacture a new run.
            unchanged = run["classification"]["db_unchanged"]
            run["classification"] = classify(scenario, result, "before", "before" if unchanged else "after",
                                              db_path=WEB_DATA / "shop.db")
        model["summary"] = summarise(model["runs"])
    return out


def measured_markdown(data):
    models = data["models"]
    runs = {r["scenario"]: r for m in models for r in m["runs"]}
    normals = sum(r["kind"] == "normal" for r in runs.values())
    calls = sum(m["summary"]["model_calls"] for m in models)
    lines = [START,
             f'Recorded on {data["recorded_on"]} through the Claude Code CLI (`ClaudeCLIProvider`, JSON protocol).',
             f'{len(runs)} scenarios: {normals} normal questions and {len(runs) - normals} attacks. '
             f'{calls} CLI calls in the committed recordings.', "",
             "| Model | Condition | Attacks | Model declined | Guard blocked | Got through | Inconclusive | Normal correct | False-positive blocks |",
             "|---|---|---|---|---|---|---|---|---|"]
    for model in models:
        s = model["summary"]
        normal = f'{s["normal_correct"]} / {s["normal_total"]}' if s["normal_total"] else "not run"
        fp = str(s["normal_false_positive_blocks"]) if s["normal_total"] else "not run"
        lines.append(f'| {model["model"]} | {model["condition"]} | {s["attacks_total"]} | {s["model_declined"]} | '
                     f'{s["guard_blocked"]} | {s["got_through"]} | {s["inconclusive"]} | {normal} | {fp} |')
    lines += ["", "CLI-reported cost and mean latency (including CLI prompt overhead):", ""]
    for model in models:
        s = model["summary"]
        lines.append(f'- {model["model"]} {model["condition"]}: ${s["cli_reported_cost_usd"]:.2f}, '
                     f'{s["model_calls"]} calls, {s["mean_call_ms"] / 1000:.1f} s per call.')
    lines += [END]
    return "\n".join(lines)


def main():
    path = WEB_DATA / "scenarios.json"
    data = recompute(json.loads(path.read_text()))
    path.write_text(json.dumps(data, indent=1, ensure_ascii=True))
    readme = ROOT / "README.md"
    text = readme.read_text()
    text, n = re.subn(re.escape(START) + r".*?" + re.escape(END), lambda _: measured_markdown(data), text, flags=re.S)
    if n != 1:
        raise SystemExit("README must contain exactly one recorded-metrics block")
    readme.write_text(text)
    for model in data["models"]:
        print(model["model"], model["condition"], json.dumps(model["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
