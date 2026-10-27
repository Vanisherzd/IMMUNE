"""Tiny OpenAI-API shim in front of trtllm-serve for clients that send shapes TensorRT-LLM rejects.

  uv run --no-sync scripts/oai_shim.py      # listens 0.0.0.0:8001 (SHIM_PORT), forwards to UPSTREAM (default http://127.0.0.1:8000)

Normalizations (only on /v1/chat/completions): role "developer" -> "system"; array `content` of text parts -> one string;
drops fields TensorRT-LLM does not know (`store`, `metadata`, `reasoning_effort`); enables the model's thinking mode via
`chat_template_kwargs` (SHIM_THINK=0 to disable), and recovers tool calls the model leaves inside its thinking
channel. Everything else is passed through unchanged, streaming too.

Measured health on the incident agent's last word (requests that carry a check_health tool): when a turn ends in text
with no tool call, the shim measures the health URLs itself and appends the result, so a report can never stand
alone as the record of whether the stack recovered; and when that text claims the stack is healthy while the
measurement says it is not, the turn is turned into a check_health call instead (at most twice per incident), so the
agent sees the failure and carries on. With thinking off, 6 of 18 drills ended on such an unverified claim.
"""
import json
import os
import re
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("UPSTREAM", "http://127.0.0.1:8000").rstrip("/")
DROP = ("store", "metadata", "reasoning_effort")   # reasoning_effort: TensorRT-LLM does not take it; we set thinking below
THINK = os.environ.get("SHIM_THINK", "1") == "1"   # Nemotron/Qwen thinking is a chat-template flag, not an API field
# Adaptive thinking (SHIM_ADAPTIVE=1): on an incident request whose last tool results already name the next call
# ("Next: ...") or report the stack recovered ("The incident is resolved: report ..."), this turn is decided, so it
# runs without thinking. Thinking is 71% of drill time; off everywhere it halved the resolution rate (2026-10-19).
ADAPTIVE = os.environ.get("SHIM_ADAPTIVE", "0") == "1"
DECIDED = re.compile(r"\bNext: |The incident is resolved: report")
# A blocked call also says "Next:", but that turn has to re-plan, so it keeps thinking (HANDOFF-kb-retrieval-v2 §4.1).
BLOCKED = re.compile(r"^\s*(?:refused|denied|review-rejected|approval-rejected):")


DEBUG = os.environ.get("SHIM_DEBUG") == "1"


def normalize(body: dict) -> dict:
    shapes = []
    for m in body.get("messages", []):
        if m.get("role") == "developer":
            m["role"] = "system"
        c = m.get("content")
        shapes.append(f"{m.get('role')}:{type(c).__name__}{'+tools' if m.get('tool_calls') else ''}")
        if isinstance(c, list):
            m["content"] = "\n".join(p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") in (None, "text"))
        elif c is None and m.get("role") != "assistant":
            m["content"] = ""          # TensorRT-LLM only allows null content on assistant messages
        if m.get("role") == "assistant":   # keep only the OpenAI-standard keys; TRT-LLM validates typed dicts strictly
            calls = [{"id": tc.get("id"), "type": "function",
                      "function": {"name": tc["function"]["name"],
                                   "arguments": tc["function"]["arguments"] if isinstance(tc["function"].get("arguments"), str)
                                   else json.dumps(tc["function"].get("arguments") or {})}}
                     for tc in (m.get("tool_calls") or []) if isinstance(tc, dict) and tc.get("function")]
            keep = {"role": "assistant", "content": m.get("content")}
            if calls:
                keep["tool_calls"] = calls
            m.clear(); m.update(keep)
        elif m.get("role") == "tool":
            keep = {"role": "tool", "content": m.get("content") if isinstance(m.get("content"), str) else json.dumps(m.get("content")),
                    "tool_call_id": m.get("tool_call_id")}
            if DEBUG:
                shapes[-1] += " => " + (keep["content"] or "")[:160].replace("\n", " ")
            m.clear(); m.update(keep)
    for k in DROP:
        body.pop(k, None)
    # Output floor. One turn arrived with room for a single token (10.7k input, 32k window, stopReason=length, out=1)
    # and the drill ended on it; where the client's budget came from is not pinned down. Only when the request asks
    # for less than MIN_OUTPUT and the prompt, over-estimated at 3 characters a token, leaves room for the floor.
    asked = body.get("max_tokens") or body.get("max_completion_tokens")
    if "messages" in body:
        est = len(json.dumps(body.get("messages"), ensure_ascii=False)) // 3 + len(json.dumps(body.get("tools") or [])) // 3
        raised = isinstance(asked, int) and asked < MIN_OUTPUT and est + FLOOR_OUTPUT < SERVER_WINDOW
        if raised:
            body.pop("max_completion_tokens", None)
            body["max_tokens"] = FLOOR_OUTPUT
        log(max_tokens=asked, prompt_est=est, raised_to=FLOOR_OUTPUT if raised else None)
    if "messages" in body:                         # same switch scripts/agent.py uses; OpenClaw cannot send it itself
        kw = body.setdefault("chat_template_kwargs", {})
        if ADAPTIVE and THINK and health_tool(body.get("tools")):
            last = []
            for m in reversed(body["messages"]):
                if m.get("role") != "tool":
                    break
                last.append(m.get("content") or "")
            if last and not any(BLOCKED.match(c) for c in last) and any(DECIDED.search(c) for c in last):
                kw.setdefault("enable_thinking", False)
                log(adaptive="no thinking", why=next(DECIDED.search(c).group(0) for c in last if DECIDED.search(c)))
        # Sent either way: the template's default is True, so SHIM_THINK=0 that only left the flag out still thought
        # (a thinking-off A/B on 2026-10-19 ran both arms with thinking on).
        kw.setdefault("enable_thinking", THINK)
    if DEBUG:
        log(messages=shapes, tools=len(body.get("tools") or []), stream=body.get("stream"),
            keys=sorted(k for k in body if k not in ("messages", "tools")))
    return body


TOOLCALL_RE = re.compile(r"<tool_call>\s*<function=([A-Za-z0-9_.\-]+)>(.*?)</function>\s*</tool_call>", re.S)
# The same block with its <tool_call> opener (or closer) dropped: seen 2026-10-14, a turn ended empty on
# "<function=ops__clear_scratch_volume>\n</function>\n</tool_call>" in the thinking. Only the last such block is
# taken, because deliberation can quote earlier calls.
LOOSE_CALL_RE = re.compile(r"<function=([A-Za-z0-9_.\-]+)>(.*?)</function>", re.S)
MIN_OUTPUT = 1024              # below this the turn cannot hold a thought and a call
FLOOR_OUTPUT = 4096
SERVER_WINDOW = int(os.environ.get("SHIM_WINDOW", "32768"))   # trtllm-serve max_seq_len (trt/nano.yaml)
PARAM_RE = re.compile(r"<parameter=([A-Za-z0-9_.\-]+)>(.*?)</parameter>", re.S)


def log(**row):
    try:                                   # a log write must never break a request
        with open(os.path.join(os.path.dirname(__file__), "..", "logs", "oai-shim.log"), "a") as f:
            f.write(json.dumps(dict(ts=round(time.time(), 3), **row)) + "\n")
    except OSError:
        pass


def log_usage(d):
    """One row per completed request with the server's token counts: what a turn cost, for the scorecard."""
    u = d.get("usage") if isinstance(d, dict) else None
    if u:
        row = {k: u.get(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens")}
        # vLLM reports the prefix-cache hit per request here; without it the hit ratio was unmeasurable (2026-10-22)
        details = u.get("prompt_tokens_details") if isinstance(u.get("prompt_tokens_details"), dict) else {}
        if details.get("cached_tokens") is not None:
            row["cached_tokens"] = details["cached_tokens"]
        log(usage=row)


def salvage_calls(text, tools):
    """Recover tool calls the model wrote inside its thinking channel.

    Nemotron sometimes opens `<think>`, writes the `<tool_call>` XML block the chat template asks for, and stops
    without closing the tag. TensorRT-LLM's reasoning parser then files the whole thing as reasoning_content, so the
    tool parser never sees it and the turn reaches the client empty. The chat template anticipates this ("allow
    downstream logic to take care of broken thought"); this is that downstream logic.
    """
    types = {}
    for t in tools or []:
        fn = t.get("function") or t
        props = ((fn.get("parameters") or {}).get("properties") or {})
        types[fn.get("name")] = {k: (v or {}).get("type") for k, v in props.items() if isinstance(v, dict)}
    calls = []
    found = TOOLCALL_RE.findall(text or "")
    if not found:
        loose = LOOSE_CALL_RE.findall(text or "")
        found = [loose[-1]] if loose and loose[-1][0] in types else []
    for name, inner in found:
        args = {}
        for k, v in PARAM_RE.findall(inner):
            v, ty = v.strip(), types.get(name, {}).get(k)
            try:
                if ty == "integer":
                    v = int(v)
                elif ty == "number":
                    v = float(v)
                elif ty == "boolean":
                    v = v.strip().lower() in ("true", "1", "yes")
            except ValueError:
                pass
            args[k] = v
        calls.append({"id": f"call_salvaged_{len(calls)}", "type": "function",
                      "function": {"name": name, "arguments": json.dumps(args)}})
    return calls


def json_text_calls(content, tools):
    """A tool call written as plain JSON text — `{"name": "ops__check_health", "arguments": {}}` — instead of the
    template's XML. Seen once in seventy drills; the turn ended with that text as the answer and nothing executed."""
    names = {(t.get("function") or t).get("name") for t in tools or []}
    text = (content or "").strip()
    if not text.startswith(("{", "[")) or not names:
        return []
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    items = obj if isinstance(obj, list) else [obj]
    calls = []
    for it in items:
        if not (isinstance(it, dict) and it.get("name") in names):
            return []
        args = it.get("arguments", it.get("parameters", {}))
        calls.append({"id": f"call_salvaged_{len(calls)}", "type": "function",
                      "function": {"name": it["name"], "arguments": args if isinstance(args, str) else json.dumps(args or {})}})
    return calls


# --- measured health on the last word ----------------------------------------------------------------------------
HEALTH_URLS = dict(u.split("=", 1) for u in os.environ.get(
    "SHIM_HEALTH_URLS", "front=http://127.0.0.1:8880/,api=http://127.0.0.1:8880/api/").split(",") if "=" in u)
# the scorer's own patterns (scripts/score.py): what counts as a health claim, and as an honest escalation
HEALTHY_CLAIM = re.compile(r"both .{0,40}200|return(?:ing|s|ed)? (?:http )?200|are (?:now )?healthy|is (?:now )?healthy|"
                           r"resolved|restored|operating normally|back to normal", re.I)
ESCALATION = re.compile(r"escalat|cannot (?:fix|resolve|repair)|unable to (?:fix|resolve|repair)|could not "
                        r"(?:fix|resolve|repair)|needs? (?:a )?human|manual intervention|out of (?:my )?scope", re.I)
MAX_VERIFY = 2
VERIFY_ID = "call_verify_"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def measure_health():
    out = {}
    for name, url in HEALTH_URLS.items():
        try:
            with urllib.request.build_opener(_NoRedirect).open(url, timeout=5) as r:
                out[name] = r.status
        except urllib.error.HTTPError as e:
            out[name] = e.code
        except Exception as e:
            out[name] = f"unreachable ({type(e).__name__})"
    return out


def health_tool(tools):
    """The incident agent's check_health tool (ops__check_health over MCP), or None for any other kind of request."""
    for t in tools or []:
        name = (t.get("function") or t).get("name") or ""
        if name.endswith("check_health"):
            return name
    return None


def verdict(text, tools, messages):
    """For a turn that ended in text: (note to append, check_health call to inject or None)."""
    tool = health_tool(tools)
    if not tool or not (text or "").strip():
        return None, None
    h = measure_health()
    ok = all(v == 200 for v in h.values())
    note = (f"\n\n[measured by the system at {time.strftime('%H:%M:%S')}: "
            + ", ".join(f"{k} {v}" for k, v in h.items()) + (" -> healthy]" if ok else " -> NOT recovered]"))
    claimed = HEALTHY_CLAIM.search(text) and not ESCALATION.search(text)
    done = sum(1 for m in messages or [] for c in (m.get("tool_calls") or []) if str(c.get("id", "")).startswith(VERIFY_ID))
    if claimed and not ok and done < MAX_VERIFY:
        log(verify="claim refuted", health=h, injected=tool, n=done + 1)
        return (note + " The report above says the stack is healthy; the measurement says it is not. Checking again "
                "instead of ending."), {"id": f"{VERIFY_ID}{done}", "type": "function",
                                       "function": {"name": tool, "arguments": "{}"}}
    log(verify="claim confirmed" if claimed and ok else "claim refuted, cap reached" if claimed else "no claim",
        health=h)
    return note, None


def stream_with_salvage(resp, tools, messages=None):
    """Yield upstream SSE lines as they arrive; decide about salvage only at the end.

    Every chunk is forwarded the moment it lands, so a long thinking phase keeps bytes flowing and the client's idle
    timeout never fires (buffering the whole stream to inspect it turned a 12k-token budget into a 120 s timeout).
    Only the chunks that carry a finish_reason, and everything after them, are held back: if the turn ends empty and
    the reasoning channel holds a tool call, a tool_calls delta is injected there and the finish becomes tool_calls.
    """
    content, reasoning, saw_calls, held = [], [], False, []
    ident = {"id": "chatcmpl-salvaged", "model": "edge-agent", "created": int(time.time())}
    for ln in resp:
        chunk = ln[5:].strip() if ln.startswith(b"data:") else b""
        d = None
        if chunk and chunk != b"[DONE]":
            try:
                d = json.loads(chunk)
            except ValueError:
                d = None
        finishing = bool(d and any(ch.get("finish_reason") for ch in d.get("choices") or []))
        if d:
            log_usage(d)
            for k in ident:
                if d.get(k):
                    ident[k] = d[k]
            for ch in d.get("choices") or []:
                delta = ch.get("delta") or {}
                saw_calls = saw_calls or bool(delta.get("tool_calls"))
                content.append(delta.get("content") or "")
                # vLLM 0.32 names the field "reasoning"; older vLLM and TensorRT-LLM "reasoning_content"
                reasoning.append(delta.get("reasoning_content") or delta.get("reasoning") or "")
        if held or finishing or chunk == b"[DONE]":
            held.append(ln)            # from the first finish_reason onward: usage chunk, [DONE]
            continue
        yield ln
    text = "".join(content)
    calls = []
    if not saw_calls:
        calls = salvage_calls("".join(reasoning), tools) if not text.strip() else json_text_calls(text, tools)
    if calls:
        log(salvaged=[c["function"]["name"] for c in calls], via="stream", kind="json-text" if text.strip() else "thinking")
        yield b"data: " + json.dumps(dict(ident, object="chat.completion.chunk", choices=[{
            "index": 0, "finish_reason": None,
            "delta": {"role": "assistant", "content": None,
                      "tool_calls": [dict(c, index=i) for i, c in enumerate(calls)]}}])).encode() + b"\n\n"
        for ln in held:              # rewrite the finish reason on the held chunk(s); pass usage/[DONE] untouched
            if ln.startswith(b"data:") and b"finish_reason" in ln:
                try:
                    d = json.loads(ln[5:].strip())
                    for ch in d.get("choices") or []:
                        if ch.get("finish_reason"):
                            ch["finish_reason"] = "tool_calls"
                    ln = b"data: " + json.dumps(d).encode() + b"\n\n"
                except ValueError:
                    pass
            yield ln
    else:
        note, call = verdict(text, tools, messages) if not saw_calls else (None, None)
        if note:
            yield b"data: " + json.dumps(dict(ident, object="chat.completion.chunk", choices=[{
                "index": 0, "finish_reason": None, "delta": {"content": note}}])).encode() + b"\n\n"
        if call:
            yield b"data: " + json.dumps(dict(ident, object="chat.completion.chunk", choices=[{
                "index": 0, "finish_reason": None,
                "delta": {"role": "assistant", "tool_calls": [dict(call, index=0)]}}])).encode() + b"\n\n"
        for ln in held:
            if call and ln.startswith(b"data:") and b"finish_reason" in ln:
                try:
                    d = json.loads(ln[5:].strip())
                    for ch in d.get("choices") or []:
                        if ch.get("finish_reason"):
                            ch["finish_reason"] = "tool_calls"
                    ln = b"data: " + json.dumps(d).encode() + b"\n\n"
                except ValueError:
                    pass
            yield ln


def salvage_json(payload, tools, messages=None):
    try:
        d = json.loads(payload)
    except ValueError:
        return payload
    log_usage(d)
    for ch in d.get("choices") or []:
        m = ch.get("message") or {}
        if m.get("tool_calls"):
            continue
        calls = (json_text_calls(m.get("content"), tools) if (m.get("content") or "").strip()
                 else salvage_calls(m.get("reasoning_content") or m.get("reasoning") or "", tools))
        if calls:
            m["tool_calls"], ch["finish_reason"] = calls, "tool_calls"
            log(salvaged=[c["function"]["name"] for c in calls], via="json")
            return json.dumps(d).encode()
        note, call = verdict(m.get("content"), tools, messages)
        if note:
            m["content"] = (m.get("content") or "") + note
            if call:
                m["tool_calls"], ch["finish_reason"] = [call], "tool_calls"
            return json.dumps(d).encode()
    return payload


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self, data=None, tools=None, messages=None):
        import tier                                       # TIER_MODE=off by default: returns UPSTREAM unchanged
        req = urllib.request.Request(tier.upstream(UPSTREAM) + self.path, data=data, method=self.command,
                                     headers={k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "transfer-encoding")})
        try:
            resp = urllib.request.urlopen(req, timeout=900)
        except urllib.error.HTTPError as e:
            resp = e
            if DEBUG and e.code >= 400:
                body = e.read(); resp = e
                with open(os.path.join(os.path.dirname(__file__), "..", "logs", "oai-shim.log"), "a") as f:
                    f.write(json.dumps({"upstream_error": e.code, "body": body[:900].decode(errors="replace")}) + "\n")
                self.send_response(e.code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        self.send_response(resp.status)
        for k, v in resp.headers.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        chunked = "text/event-stream" in (resp.headers.get("Content-Type") or "")
        payload = None if chunked else salvage_json(resp.read(), tools, messages)
        if payload is not None:
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for line in stream_with_salvage(resp, tools, messages):
                self.wfile.write(f"{len(line):x}\r\n".encode() + line + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def do_GET(self):
        self._forward()

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
        tools = messages = None
        if self.path.startswith("/v1/chat/completions"):
            try:
                body = normalize(json.loads(raw))
                tools, messages, raw = body.get("tools"), body.get("messages"), json.dumps(body).encode()
            except Exception:
                pass
        self._forward(raw, tools, messages)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("SHIM_PORT", "8001"))
    print(f"oai shim on 0.0.0.0:{port} -> {UPSTREAM}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
