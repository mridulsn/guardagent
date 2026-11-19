from guardagent.agent import run_agent
from guardagent.guard import AuditLog, GuardLayer
from guardagent.providers import FakeProvider, ToolResult, UserText


def guard():
    return GuardLayer(audit=AuditLog())


def test_normal_run_two_tools():
    p = FakeProvider([
        {"tool_calls": [("sql_query", {"query": "SELECT unit_price FROM products WHERE name = 'Ridgeline 2P Tent'"})]},
        {"tool_calls": [("calculator", {"expression": "289 * 3 * 0.95"})]},
        {"final_answer": "823.65"},
    ])
    r = run_agent(p, "q", guard=guard())
    assert r.status == "answered" and r.final_answer == "823.65"
    assert r.model_calls == 3 and r.tool_calls == 2
    assert [c["verdict"] for s in r.steps for c in s["tool_calls"]] == ["modified", "allowed"]
    assert len(r.audit) == 2


def test_blocked_call_returns_error_result_to_model():
    p = FakeProvider([
        {"tool_calls": [("sql_query", {"query": "DELETE FROM orders"})]},
        {"final_answer": "I can't delete data; the tools are read-only."},
    ])
    r = run_agent(p, "delete stuff", guard=guard())
    sent = p.received[1]
    assert len(sent) == 1 and isinstance(sent[0], ToolResult)
    assert sent[0].is_error and "sql.forbidden_keyword" in sent[0].content
    assert r.steps[0]["tool_calls"][0]["rule"] == "sql.forbidden_keyword"
    assert r.audit[0]["verdict"] == "blocked"


def test_step_budget_forces_final_answer():
    loop = [{"tool_calls": [("calculator", {"expression": "1+1"})]}] * 3
    p = FakeProvider(loop + [{"final_answer": "2"}])
    r = run_agent(p, "q", guard=guard(), max_steps=3)
    assert r.status == "answered_after_budget" and r.final_answer == "2"
    last = p.received[-1]
    assert isinstance(last[-1], UserText) and "budget" in last[-1].text.lower()
    assert r.steps[-1]["tools_allowed"] is False


def test_no_final_answer_when_model_keeps_calling_tools():
    loop = [{"tool_calls": [("calculator", {"expression": "1+1"})]}] * 5
    r = run_agent(FakeProvider(loop), "q", guard=guard(), max_steps=2)
    assert r.status == "no_final_answer" and r.final_answer is None


def test_protocol_error_gets_corrective_message():
    p = FakeProvider([{"protocol_error": "reply is not a single JSON object"}, {"final_answer": "ok"}])
    r = run_agent(p, "q", guard=guard())
    assert r.status == "answered" and r.steps[0]["protocol_error"]
    assert "could not be used" in p.received[1][0].text


def test_refusal_ends_run_without_tools():
    r = run_agent(FakeProvider([{"refusal": "declined"}]), "q", guard=guard())
    assert r.status == "refused_by_model_safety" and r.tool_calls == 0


def test_tool_call_budget_blocks_extra_calls():
    many = [("calculator", {"expression": f"{i}+1"}) for i in range(6)]
    p = FakeProvider([{"tool_calls": many}, {"final_answer": "done"}])
    r = run_agent(p, "q", guard=guard())
    verdicts = [c["rule"] for c in r.steps[0]["tool_calls"]]
    assert verdicts[:4] == ["calc.ok"] * 4 and verdicts[4:] == ["budget.tool_calls"] * 2
    assert len(p.received[1]) == 6  # every call still gets a tool_result
