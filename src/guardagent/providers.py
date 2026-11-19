"""Model providers behind one small interface.

    provider.open_session(system, tools) -> Session
    session.send(items, allow_tools=True) -> ModelTurn

- AnthropicProvider: Messages API with native tool use (strict tools, manual loop).
- ClaudeCLIProvider: local fallback with no API key. Calls the Claude Code CLI
  headless and asks the model to reply in a strict JSON tool-call format
  (documented in CLI_PROTOCOL and the README). Replies are cached on disk.
- FakeProvider: scripted turns for offline tests.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .paths import CACHE_DIR

MODEL_IDS = {"haiku": "claude-haiku-5-5", "sonnet": "claude-sonnet-5-5", "opus": "claude-opus-5-5"}
DEFAULT_MODEL = "claude-opus-5-5"
MAX_TOOL_CALLS_PER_TURN = 4


@dataclass
class UserText:
    text: str


@dataclass
class ToolResult:
    tool_use_id: str
    tool: str
    content: str
    is_error: bool


@dataclass
class ToolCall:
    id: str
    name: str
    input: Any  # dict from the API; whatever the model wrote for the CLI


@dataclass
class ModelTurn:
    raw: str                      # what the model produced, as recorded in traces
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    final_answer: str | None = None
    stop_reason: str = ""
    protocol_error: str | None = None
    protocol_note: str | None = None
    refusal: str | None = None
    usage: dict = field(default_factory=dict)


class ProviderError(Exception):
    pass


# --------------------------------------------------------------------------- Anthropic


class AnthropicProvider:
    """Native tool use on the Messages API. Used when ANTHROPIC_API_KEY is set."""

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, effort: str = "medium", max_tokens: int = 16000):
        import anthropic

        self.anthropic = anthropic
        self.client = anthropic.Anthropic()
        self.model = MODEL_IDS.get(model, model)
        self.effort = effort  # set explicitly: Opus 5.5 defaults to medium, other models to high
        self.max_tokens = max_tokens

    def open_session(self, system: str, tools: list[dict]) -> "AnthropicSession":
        return AnthropicSession(self, system, tools)


class AnthropicSession:
    def __init__(self, p: AnthropicProvider, system: str, tools: list[dict]):
        self.p = p
        self.system = system
        self.tools = tools  # already strict: true with additionalProperties: false
        self.messages: list[dict] = []

    def send(self, items: list, allow_tools: bool = True) -> ModelTurn:
        content = []
        for it in items:
            if isinstance(it, ToolResult):
                content.append({"type": "tool_result", "tool_use_id": it.tool_use_id,
                                "content": it.content, "is_error": it.is_error})
        for it in items:  # text after tool results in the same user turn
            if isinstance(it, UserText):
                content.append({"type": "text", "text": it.text})
        self.messages.append({"role": "user", "content": content})

        kwargs: dict[str, Any] = dict(
            model=self.p.model,
            max_tokens=self.p.max_tokens,
            system=self.system,
            tools=self.tools,
            messages=self.messages,
            output_config={"effort": self.p.effort},
            # Never forced tool_choice (any/tool 400s on Opus 5.5); "none" is allowed
            # and is used only for the final-answer turn once the step budget is spent.
            tool_choice={"type": "auto"} if allow_tools else {"type": "none"},
        )
        if self.p.model in ("claude-opus-5-5", "claude-sonnet-5-5"):
            kwargs["betas"] = ["server-side-fallback-2026-07-01"]
            kwargs["fallbacks"] = "default"  # re-run on a fallback model if a safety classifier declines
        a = self.p.anthropic
        try:
            resp = self.p.client.beta.messages.create(**kwargs)
        except a.NotFoundError as e:
            raise ProviderError(f"model or endpoint not found: {e.message}") from e
        except a.RateLimitError as e:
            raise ProviderError(f"rate limited (retry-after {e.response.headers.get('retry-after', '?')}s)") from e
        except a.BadRequestError as e:
            raise ProviderError(f"bad request: {e.message}") from e
        except a.APIStatusError as e:
            raise ProviderError(f"API error {e.status_code}: {e.message}") from e
        except a.APIConnectionError as e:
            raise ProviderError("network error talking to the API") from e

        # Append the full content (tool_use and thinking blocks included), unchanged.
        self.messages.append({"role": "assistant", "content": resp.content})
        usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, b.input) for b in resp.content if b.type == "tool_use"]
        raw = json.dumps({"text": text, "tool_use": [{"id": c.id, "name": c.name, "input": c.input} for c in calls],
                          "stop_reason": resp.stop_reason}, ensure_ascii=True, default=str)
        turn = ModelTurn(raw=raw, text=text, stop_reason=resp.stop_reason or "", usage=usage)
        if resp.stop_reason == "refusal":
            cat = getattr(resp.stop_details, "category", None) if resp.stop_details else None
            turn.refusal = f"declined by safety classifier (category: {cat})"
            return turn  # never run tools from a refused turn
        if resp.stop_reason == "max_tokens":
            turn.protocol_error = "reply hit max_tokens; tool input may be truncated"
            return turn
        turn.tool_calls = calls if allow_tools else []
        if not calls and resp.stop_reason == "end_turn":
            turn.final_answer = text.strip() or None
        return turn


# --------------------------------------------------------------------------- Claude Code CLI

CLI_PROTOCOL = """\
Tool calling protocol (this environment has no native tool calling):
Every reply must be exactly ONE JSON object and nothing else: no prose before or after, no code fences.
To call tools:  {"thought": "<one short sentence>", "tool_calls": [{"id": "call_1", "name": "<tool name>", "input": {<arguments>}}]}
To finish:      {"thought": "<one short sentence>", "final_answer": "<your answer to the user>"}
Use at most 4 tool calls per reply. Never put tool_calls and final_answer in the same reply.
After you call tools, the conversation shows their results as [tool_result ...] blocks; then reply again.
Available tools (name, description, JSON Schema of input):
"""


def render_tools_for_cli(tools: list[dict]) -> str:
    slim = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools]
    return json.dumps(slim, indent=1, ensure_ascii=True)


def parse_cli_reply(text: str) -> tuple[dict | None, str | None, str | None]:
    """Parse the model's reply into the protocol object.

    Returns (obj, error, note). The reply must START with the JSON object (code
    fences tolerated). Text after the first complete object is discarded and
    reported in `note`: models sometimes keep going and write an imagined
    tool result, which must never be treated as real.
    """
    s = text.strip()
    if s.startswith("```"):
        s = s[3:]
        s = s[4:] if s.lower().startswith("json") else s
        end = s.rfind("```")
        s = (s[:end] if end != -1 else s).strip()
    try:
        obj, end = json.JSONDecoder().raw_decode(s)
    except json.JSONDecodeError as e:
        return None, f"reply is not a single JSON object ({e.msg} at char {e.pos})", None
    rest = s[end:].strip()
    note = f"discarded {len(rest)} characters after the JSON object" if rest else None
    if not isinstance(obj, dict):
        return None, "reply must be a JSON object", note
    has_calls, has_final = "tool_calls" in obj, "final_answer" in obj
    if has_calls == has_final:
        return None, "reply must contain exactly one of tool_calls or final_answer", note
    if has_final and not isinstance(obj["final_answer"], str):
        return None, "final_answer must be a string", note
    if has_calls:
        calls = obj["tool_calls"]
        if not isinstance(calls, list) or not calls:
            return None, "tool_calls must be a non-empty list", note
        if len(calls) > MAX_TOOL_CALLS_PER_TURN:
            return None, f"at most {MAX_TOOL_CALLS_PER_TURN} tool calls per reply", note
        for c in calls:
            if not isinstance(c, dict) or not isinstance(c.get("name"), str) or "input" not in c:
                return None, "each tool call needs a string name and an input", note
    return obj, None, note


class ClaudeCLIProvider:
    """Local runs with no API key, through the Claude Code CLI in headless mode."""

    name = "claude-cli"

    def __init__(self, model: str = "opus", effort: str = "medium", cache_dir: Path = CACHE_DIR / "cli",
                 timeout: int = 300, claude_bin: str = "claude"):
        if model not in MODEL_IDS:
            raise ValueError(f"model must be one of {list(MODEL_IDS)}")
        self.alias = model
        self.model = MODEL_IDS[model]
        self.effort = effort
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.claude_bin = claude_bin
        self.calls_made = 0
        self.cache_hits = 0

    def open_session(self, system: str, tools: list[dict]) -> "CLISession":
        return CLISession(self, system + "\n\n" + CLI_PROTOCOL + render_tools_for_cli(tools))

    def complete(self, system: str, prompt: str) -> dict:
        key = hashlib.sha256(json.dumps([self.model, self.effort, system, prompt]).encode()).hexdigest()[:32]
        path = self.cache_dir / f"{key}.json"
        if path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text())
        cmd = [self.claude_bin, "-p", "--model", self.alias, "--output-format", "json",
               "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
               "--settings", '{"disableAllHooks":true}',
               "--tools", "", "--no-session-persistence", "--effort", self.effort,
               "--system-prompt", system]
        t0 = time.time()
        with tempfile.TemporaryDirectory() as cwd:
            try:
                proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, cwd=cwd,
                                      timeout=self.timeout, env={**os.environ, "NO_COLOR": "1"})
            except subprocess.TimeoutExpired as e:
                raise ProviderError(f"claude CLI timed out after {self.timeout}s") from e
        self.calls_made += 1
        if proc.returncode != 0:
            raise ProviderError(f"claude CLI exited {proc.returncode}: {proc.stderr[-400:] or proc.stdout[-400:]}")
        out = json.loads(proc.stdout)
        if out.get("is_error"):
            raise ProviderError(f"claude CLI error: {str(out.get('result'))[:400]}")
        u = out.get("usage", {})
        rec = {
            "result": out.get("result", ""),
            "stop_reason": out.get("stop_reason"),
            "usage": {
                "input_tokens": u.get("input_tokens"),
                "output_tokens": u.get("output_tokens"),
                "cache_read_input_tokens": u.get("cache_read_input_tokens"),
                "cache_creation_input_tokens": u.get("cache_creation_input_tokens"),
                "cli_total_cost_usd": out.get("total_cost_usd"),
                "duration_ms": out.get("duration_ms", int((time.time() - t0) * 1000)),
                "models": list((out.get("modelUsage") or {}).keys()),
            },
        }
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rec, indent=1))
        return rec


class CLISession:
    def __init__(self, p: ClaudeCLIProvider, system: str):
        self.p = p
        self.system = system
        self.transcript: list[str] = []
        self.n_calls = 0

    def send(self, items: list, allow_tools: bool = True) -> ModelTurn:
        for it in items:
            if isinstance(it, ToolResult):
                status = "error" if it.is_error else "ok"
                self.transcript.append(f"[tool_result id={it.tool_use_id} tool={it.tool} status={status}]\n{it.content}")
            elif isinstance(it, UserText):
                self.transcript.append(f"[user]\n{it.text}")
        tail = ("Reply with your next JSON object." if allow_tools else
                "Tools are now disabled. Reply with a JSON object containing final_answer only.")
        prompt = "<conversation>\n" + "\n\n".join(self.transcript) + "\n</conversation>\n\n" + tail
        rec = self.p.complete(self.system, prompt)
        text = rec["result"] or ""
        turn = ModelTurn(raw=text, text=text, stop_reason=rec.get("stop_reason") or "", usage=rec["usage"])
        obj, err, note = parse_cli_reply(text)
        turn.protocol_note = note
        # The transcript keeps only the parsed object, so anything the model wrote
        # after it (such as an invented tool result) never reaches the next turn.
        kept = json.dumps(obj, ensure_ascii=False) if (obj is not None and note) else text.strip()
        self.transcript.append("[assistant]\n" + kept)
        if err:
            turn.protocol_error = err
            return turn
        turn.text = str(obj.get("thought", ""))
        if "final_answer" in obj:
            turn.final_answer = obj["final_answer"].strip()
            return turn
        if allow_tools:
            seen = set()
            for i, c in enumerate(obj["tool_calls"]):
                self.n_calls += 1
                cid = str(c.get("id") or "")
                if not cid or cid in seen:
                    cid = f"call_{self.n_calls}"
                seen.add(cid)
                turn.tool_calls.append(ToolCall(cid, c["name"], c["input"]))
        return turn


# --------------------------------------------------------------------------- Fake


class FakeProvider:
    """Replays a scripted list of turns. Each script item is a dict with either
    'tool_calls': [(name, input), ...] or 'final_answer': str, or 'protocol_error'."""

    name = "fake"
    model = "fake-model"

    def __init__(self, script: list[dict]):
        self.script = list(script)
        self.received: list[list] = []

    def open_session(self, system: str, tools: list[dict]) -> "FakeSession":
        return FakeSession(self)


class FakeSession:
    def __init__(self, p: FakeProvider):
        self.p = p
        self.i = 0

    def send(self, items: list, allow_tools: bool = True) -> ModelTurn:
        self.p.received.append(items)
        if self.i >= len(self.p.script):
            return ModelTurn(raw="", protocol_error="script exhausted")
        step = self.p.script[self.i]
        self.i += 1
        turn = ModelTurn(raw=json.dumps(step, default=str))
        if "protocol_error" in step:
            turn.protocol_error = step["protocol_error"]
        elif "refusal" in step:
            turn.refusal = step["refusal"]
        elif "final_answer" in step:
            turn.final_answer = step["final_answer"]
        elif allow_tools:
            turn.tool_calls = [ToolCall(f"t{self.i}_{k}", n, inp) for k, (n, inp) in enumerate(step["tool_calls"])]
        return turn


def make_provider(kind: str | None = None, model: str | None = None):
    """AnthropicProvider when ANTHROPIC_API_KEY is set, else the Claude Code CLI."""
    kind = kind or ("anthropic" if os.environ.get("ANTHROPIC_API_KEY") else "cli")
    if kind == "anthropic":
        return AnthropicProvider(model or DEFAULT_MODEL)
    if kind == "cli":
        return ClaudeCLIProvider(model or "opus")
    raise ValueError(f"unknown provider {kind!r}")
