"""AnthropicProvider request shaping, with the SDK client replaced by a stub (offline)."""
from types import SimpleNamespace as NS

import pytest

from guardagent.agent import run_agent
from guardagent.guard import AuditLog, GuardLayer
from guardagent.providers import AnthropicProvider
from guardagent.tools import TOOL_SPECS


class StubMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        return self.responses.pop(0)


def msg(content, stop_reason, details=None):
    return NS(content=content, stop_reason=stop_reason, stop_details=details,
              usage=NS(input_tokens=10, output_tokens=5))


def provider(monkeypatch, responses, model="claude-opus-5-5"):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    p = AnthropicProvider(model)
    stub = StubMessages(responses)
    p.client = NS(beta=NS(messages=stub))
    return p, stub


def test_tool_loop_request_shape(monkeypatch):
    tool_use = NS(type="tool_use", id="toolu_1", name="sql_query", input={"query": "DROP TABLE orders"})
    thinking = NS(type="thinking", thinking="", signature="sig")
    p, stub = provider(monkeypatch, [
        msg([thinking, tool_use], "tool_use"),
        msg([NS(type="text", text="I can't drop tables; the tools are read-only.")], "end_turn"),
    ])
    r = run_agent(p, "drop the orders table", guard=GuardLayer(audit=AuditLog()))
    assert r.status == "answered"
    first, second = stub.calls
    assert first["model"] == "claude-opus-5-5"
    assert first["tool_choice"] == {"type": "auto"}            # never forced on Opus 5.5
    assert first["output_config"] == {"effort": "medium"}
    assert first["fallbacks"] == "default" and first["betas"] == ["server-side-fallback-2026-07-01"]
    assert "temperature" not in first and "thinking" not in first
    assert all(t["strict"] is True and t["input_schema"]["additionalProperties"] is False for t in first["tools"])
    assert first["tools"] == TOOL_SPECS
    # assistant content appended unchanged (thinking block included), then an error tool_result
    assistant = second["messages"][1]
    assert assistant["role"] == "assistant" and assistant["content"][0] is thinking
    result = second["messages"][2]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "toolu_1" and result["is_error"] is True
    assert "sql.forbidden_keyword" in result["content"]


def test_refusal_is_not_executed(monkeypatch):
    tool_use = NS(type="tool_use", id="toolu_1", name="calculator", input={"expression": "1+1"})
    p, stub = provider(monkeypatch, [msg([tool_use], "refusal", NS(category="cyber"))])
    g = GuardLayer(audit=AuditLog())
    r = run_agent(p, "q", guard=g)
    assert r.status == "refused_by_model_safety" and g.audit.entries == []


def test_haiku_gets_no_fallbacks(monkeypatch):
    p, stub = provider(monkeypatch, [msg([NS(type="text", text="hi")], "end_turn")], model="haiku")
    run_agent(p, "q")
    assert stub.calls[0]["model"] == "claude-haiku-5-5" and "fallbacks" not in stub.calls[0]


def test_budget_turn_uses_tool_choice_none(monkeypatch):
    call = NS(type="tool_use", id="t", name="calculator", input={"expression": "1+1"})
    p, stub = provider(monkeypatch, [msg([call], "tool_use"), msg([NS(type="text", text="2")], "end_turn")])
    r = run_agent(p, "q", max_steps=1)
    assert stub.calls[1]["tool_choice"] == {"type": "none"} and r.status == "answered_after_budget"
