"""Host-side ops API for the NemoClaw sandbox agent: the same whitelisted tools as agent.py, over HTTP.

  uv run --no-sync scripts/ops_api.py            # listens on 0.0.0.0:8790 (env OPS_PORT), logs every call to logs/ops-api.log
  GET  /tools                                     # tool list with JSON schemas (give this to the agent)
  POST /call  {"name": "<tool>", "args": {...}}   # -> {"result": "..."}
  POST /mcp   JSON-RPC 2.0 (MCP Streamable HTTP): initialize, tools/list, tools/call, ping   # native tools for OpenClaw

Only the two sandbox containers and victim/conf.d are reachable through it (see agent.run_tool). No auth by design for
the lab drill; put it behind a token or a firewall rule before exposing beyond the docker bridge.
"""
import json
import os
import pathlib
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import agent  # noqa: E402  (reuses TOOLS and run_tool)

LOG = pathlib.Path(__file__).resolve().parent.parent / "logs" / "ops-api.log"
LOG.parent.mkdir(exist_ok=True)
# self_heal is a scripted repair loop the harness can call on POST /call; it is no longer offered to the sandbox agent
# (SELF_HEAL_TOOL=1 puts it back): a model that reaches for it has not diagnosed anything, and OpenClaw's "runtime event
# continuation" made the prototype's agent call it on an already healthy stack in seven of twelve drills (2026-10-22).
TOOLS = [t for t in agent.TOOLS if t["name"] != "finish"] + ([] if os.environ.get("SELF_HEAL_TOOL", "0") != "1" else [{
    "name": "self_heal",
    "description": "Run the full autonomous diagnose-and-repair loop on the host (same model, same tools, up to 8 steps) and return its verdict and step log. Use this when you cannot drive the individual tools yourself.",
    "parameters": {"type": "object", "properties": {"note": {"type": "string", "description": "optional context for the run"}}},
}])


def self_heal(args):
    import subprocess
    env = dict(os.environ, VLLM_URL=os.environ.get("VLLM_URL", "http://127.0.0.1:8001"), SERVED_NAME=os.environ.get("SERVED_NAME", "edge-agent"))
    r = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve().parent / "agent.py"), "--case", "self-heal", "--max-steps", "8"],
                       capture_output=True, text=True, timeout=900, env=env, cwd=str(pathlib.Path(__file__).resolve().parent.parent))
    return (r.stdout + r.stderr).strip()[-3000:]


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") == "/tools":
            return self._send(200, {"tools": TOOLS})
        if self.path.rstrip("/") == "/mcp":   # no server-initiated stream; clients fall back to plain request/response
            self.send_response(405); self.send_header("Content-Length", "0"); self.end_headers(); return
        self._send(404, {"error": "use GET /tools, POST /call or POST /mcp"})

    def _mcp(self, req):
        """Minimal MCP server: enough of the Streamable HTTP transport for tools/list and tools/call."""
        rid, method, params = req.get("id"), req.get("method", ""), req.get("params") or {}
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": params.get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "edge-ops", "version": "0.1"}}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": t["name"], "description": t["description"], "inputSchema": t["parameters"]} for t in TOOLS]}}
        if method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            if name not in {t["name"] for t in TOOLS}:
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
            t0 = time.time()
            try:
                result, is_err = (self_heal(args) if name == "self_heal" else agent.run_tool(name, args, dry_run=os.environ.get("OPS_DRY_RUN") == "1")), False
            except Exception as e:  # a tool bug must come back as a tool error, never as a dropped connection
                result, is_err = f"tool {name} raised {type(e).__name__}: {e}", True
            if not is_err and isinstance(result, str) and result.startswith(("error:", "denied:", "bad arguments")):
                is_err = True
            with LOG.open("a") as f:
                f.write(json.dumps({"ts": time.strftime("%H:%M:%S"), "from": self.client_address[0], "via": "mcp", "tool": name,
                                    "args": args, "raw_params": json.dumps(params, ensure_ascii=False)[:300], "ms": int((time.time() - t0) * 1000),
                                    "is_error": is_err, "result": str(result)[:300]}, ensure_ascii=False) + "\n")
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": str(result)}], "isError": is_err}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": rid, "result": {}}
        if method.startswith("notifications/"):
            return None
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}}

    def do_DELETE(self):  # MCP session teardown
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

    def do_POST(self):
        if self.path.rstrip("/") == "/mcp":
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or b"{}"))
            except Exception as e:
                return self._send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}})
            reqs = req if isinstance(req, list) else [req]
            out = [r for r in (self._mcp(x) for x in reqs) if r is not None]
            if not out:
                self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers(); return
            return self._send(200, out if isinstance(req, list) else out[0])
        if self.path.rstrip("/") != "/call":
            return self._send(404, {"error": "use POST /call or POST /mcp"})
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or b"{}"))
            name, args = req["name"], req.get("args") or {}
        except Exception as e:
            return self._send(400, {"error": f"bad request: {e}"})
        if name not in {t["name"] for t in TOOLS}:
            return self._send(400, {"error": f"unknown tool {name}"})
        t0 = time.time()
        try:
            result = self_heal(args) if name == "self_heal" else agent.run_tool(name, args, dry_run=os.environ.get("OPS_DRY_RUN") == "1")
        except Exception as e:
            result = f"tool {name} raised {type(e).__name__}: {e}"
        with LOG.open("a") as f:
            f.write(json.dumps({"ts": time.strftime("%H:%M:%S"), "from": self.client_address[0], "tool": name,
                                "args": args, "ms": int((time.time() - t0) * 1000), "result": result[:300]}, ensure_ascii=False) + "\n")
        self._send(200, {"result": result})

    def log_message(self, *_):  # quiet; the JSONL log is the record
        pass


def warm_community_index():
    """Tokenising the community corpus (66k documents in v2) takes seconds; do it once at start, off the request path,
    so the agent's first search_incident_knowledge call does not pay for it. Failures stay silent: the layer is an extra."""
    try:
        import community_knowledge
        if (not community_knowledge.FTS_PATH.exists() and community_knowledge.CORPUS_V2.is_dir()
                and any(community_knowledge.CORPUS_V2.glob("*.jsonl.gz")) and os.environ.get("COMMUNITY_BACKEND", "fts5") == "fts5"):
            community_knowledge.build_fts()          # ~a minute for 159k documents, once per checkout
        community_knowledge.index()
    except Exception:
        pass


if __name__ == "__main__":
    import threading
    threading.Thread(target=warm_community_index, daemon=True).start()
    port = int(os.environ.get("OPS_PORT", "8790"))
    print(f"ops api on 0.0.0.0:{port}, tools: {[t['name'] for t in TOOLS]}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
