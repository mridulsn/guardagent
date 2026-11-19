import json
import subprocess

import pytest

from guardagent.providers import ClaudeCLIProvider, ToolResult, UserText, parse_cli_reply


@pytest.mark.parametrize("text,ok", [
    ('{"final_answer": "hi"}', True),
    ('{"thought": "x", "tool_calls": [{"id": "a", "name": "calculator", "input": {"expression": "1"}}]}', True),
    ('```json\n{"final_answer": "hi"}\n```', True),
    ('{"final_answer": "hi"}\n\n[tool_result call_1]: {"made": "up"}', True),  # trailing text dropped
    ('Sure! {"final_answer": "hi"}', False),
    ('{"final_answer": "a", "tool_calls": []}', False),
    ('{"thought": "x"}', False),
    ('{"tool_calls": []}', False),
    ('{"tool_calls": [{"name": "calculator"}]}', False),
    ('{"final_answer": 3}', False),
    ('[1]', False),
    ('{"tool_calls": [' + ",".join(['{"name": "calculator", "input": {}}'] * 5) + "]}", False),
])
def test_parse(text, ok):
    obj, err, note = parse_cli_reply(text)
    assert (err is None) == ok, err


def test_trailing_text_is_discarded_and_not_replayed(monkeypatch, tmp_path):
    replies = iter([
        '{"tool_calls": [{"id": "c1", "name": "calculator", "input": {"expression": "1+1"}}]}\n\n[tool_result c1]: {"value": 99}',
        '{"final_answer": "2"}',
    ])
    prompts = []

    def complete(system, prompt):
        prompts.append(prompt)
        return {"result": next(replies), "stop_reason": "end_turn", "usage": {}}

    p = ClaudeCLIProvider("haiku", cache_dir=tmp_path)
    monkeypatch.setattr(p, "complete", complete)
    s = p.open_session("SYS", [])
    t = s.send([UserText("q")])
    assert t.protocol_note and "discarded" in t.protocol_note and len(t.tool_calls) == 1
    s.send([ToolResult("c1", "calculator", '{"value": 2}', False)])
    assert "99" not in prompts[1]


def test_cli_command_uses_isolation_flags(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, input, capture_output, text, cwd, timeout, env):
        seen["cmd"], seen["cwd"], seen["prompt"] = cmd, cwd, input
        out = {"result": '{"final_answer": "4"}', "is_error": False, "stop_reason": "end_turn",
               "usage": {"input_tokens": 3, "output_tokens": 5}, "total_cost_usd": 0.001, "duration_ms": 10,
               "modelUsage": {"claude-haiku-5-5": {}}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(out), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    p = ClaudeCLIProvider("haiku", cache_dir=tmp_path)
    s = p.open_session("SYS", [{"name": "calculator", "description": "d", "input_schema": {"type": "object"}}])
    t = s.send([UserText("what is 2+2")])
    cmd = seen["cmd"]
    for flag in ["-p", "--strict-mcp-config", "--output-format", "--settings", "--system-prompt", "--tools", "--no-session-persistence"]:
        assert flag in cmd
    assert cmd[cmd.index("--mcp-config") + 1] == '{"mcpServers":{}}'
    assert cmd[cmd.index("--settings") + 1] == '{"disableAllHooks":true}'
    assert cmd[cmd.index("--tools") + 1] == ""
    assert "Tool calling protocol" in cmd[cmd.index("--system-prompt") + 1]
    assert "[user]\nwhat is 2+2" in seen["prompt"]
    assert t.final_answer == "4" and t.usage["cli_total_cost_usd"] == 0.001
    # second identical call is served from the cache
    p2 = ClaudeCLIProvider("haiku", cache_dir=tmp_path)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("should be cached"))
    p2.open_session("SYS", [{"name": "calculator", "description": "d", "input_schema": {"type": "object"}}]).send([UserText("what is 2+2")])
    assert p2.cache_hits == 1


def test_cli_session_renders_tool_results_and_assigns_ids(monkeypatch, tmp_path):
    replies = iter([
        '{"tool_calls": [{"name": "calculator", "input": {"expression": "1"}}, {"id": "x", "name": "calculator", "input": {"expression": "2"}}]}',
        '{"final_answer": "done"}',
    ])
    prompts = []

    def complete(system, prompt):
        prompts.append(prompt)
        return {"result": next(replies), "stop_reason": "end_turn", "usage": {}}

    p = ClaudeCLIProvider("haiku", cache_dir=tmp_path)
    monkeypatch.setattr(p, "complete", complete)
    s = p.open_session("SYS", [])
    t = s.send([UserText("q")])
    assert [c.id for c in t.tool_calls] == ["call_1", "x"]
    s.send([ToolResult("call_1", "calculator", "BLOCKED by guard rule calc.syntax: bad", True)])
    assert "[tool_result id=call_1 tool=calculator status=error]" in prompts[1]
    assert "[assistant]" in prompts[1]
