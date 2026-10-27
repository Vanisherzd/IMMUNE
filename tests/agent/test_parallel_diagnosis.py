import importlib.util
import json
import os
import pathlib
import sys
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_script(name, module_name):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


sdk = types.ModuleType("openai")
sdk.OpenAI = Mock(side_effect=AssertionError("unexpected real OpenAI client"))
with patch.dict(os.environ):
    os.environ.pop("AGENT_MODE", None)
    with patch.dict(sys.modules, {"openai": sdk}):
        agent = load_script("agent", "parallel_agent_under_test")
faults = load_script("faults", "parallel_faults_under_test")


class ToolCall:
    def __init__(self, call_id, name, args):
        self.id = call_id
        self.function = types.SimpleNamespace(name=name, arguments=json.dumps(args))


class FakeCompletions:
    def __init__(self, requests, lock):
        self.requests = requests
        self.lock = lock

    def create(self, **kwargs):
        tool_names = {tool["function"]["name"] for tool in kwargs["tools"]}
        role = "service" if "docker_logs" in tool_names else "platform"
        with self.lock:
            turn = len(self.requests[role])
            self.requests[role].append(kwargs)
        time.sleep(0.2)
        if turn == 0:
            calls = ([ToolCall("service-ok", "docker_ps", {}), ToolCall("service-no", "cleanup_disk", {})]
                     if role == "service" else
                     [ToolCall("platform-ok", "disk_usage", {}), ToolCall("platform-no", "docker_restart", {"name": "edge-victim"})])
            message = types.SimpleNamespace(content="", tool_calls=calls)
        else:
            text = ("Hypothesis: front-end config failure\nEvidence: nginx emerg line\nChecks: inspect front config"
                    if role == "service" else
                    "Hypothesis: host disk pressure\nEvidence: root at 99%\nChecks: inspect inode usage")
            message = types.SimpleNamespace(content=text, tool_calls=[])
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message)])


class FakeOpenAI:
    def __init__(self):
        self.requests = {"service": [], "platform": []}
        self.factory_args = []
        self.lock = threading.Lock()

    def __call__(self, **kwargs):
        self.factory_args.append(kwargs)
        return types.SimpleNamespace(chat=types.SimpleNamespace(
            completions=FakeCompletions(self.requests, self.lock)))


class ParallelDiagnosisTest(unittest.TestCase):
    def setUp(self):
        agent._incident["trace"] = []

    def test_specialists_run_concurrently_and_enforce_read_only_subsets(self):
        factory = FakeOpenAI()
        dispatched = []

        def dispatch(name, args, dry_run):
            dispatched.append((name, args, dry_run))
            return f"{name} result"

        started = time.monotonic()
        with patch.object(agent, "OpenAI", factory), \
                patch.object(agent, "_run_tool", side_effect=dispatch), \
                patch.object(agent, "search_incident_knowledge", return_value="knowledge result") as knowledge, \
                patch.object(agent, "with_health", return_value="\nhealth now: canned"):
            result = agent.parallel_diagnosis({"focus": "HTTP 502"}, False)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.7)
        self.assertEqual({name for name, _, _ in dispatched}, {"docker_ps", "disk_usage"})
        self.assertTrue(all(name not in agent.MUTATING for name, _, _ in dispatched))
        knowledge.assert_called_once_with("HTTP 502")
        for role in ("service", "platform"):
            self.assertEqual(len(factory.requests[role]), 2)
            request = factory.requests[role][0]
            self.assertEqual(request["model"], agent.MODEL)
            self.assertEqual(request["temperature"], 0)
            self.assertEqual(request["max_tokens"], 400)
            self.assertEqual(request["extra_body"], {"chat_template_kwargs": {"enable_thinking": False}})
            tool_results = [message["content"] for message in factory.requests[role][1]["messages"]
                            if message["role"] == "tool"]
            self.assertIn("denied: specialists are read-only", tool_results)
        self.assertTrue(all(args == {"base_url": f"{agent.BASE}/v1", "api_key": "none", "timeout": 120}
                            for args in factory.factory_args))
        for heading in ("## service specialist", "## platform specialist", "## knowledge", "## merge"):
            self.assertIn(heading, result)
        self.assertIn("inspect front config", result)
        self.assertIn("inspect inode usage", result)
        self.assertLessEqual(len(result), 6000)
        self.assertTrue(result.endswith(
            "Diagnosis was parallel and read-only; any change still goes through the normal tools, the reviewer and approval."))

    def test_knowledge_uses_first_error_from_latest_docker_log(self):
        import specialists
        agent._incident["trace"] = [
            {"tool": "docker_logs", "result": "old fatal line"},
            {"tool": "docker_ps", "result": "running"},
            {"tool": "docker_logs", "result": "notice\nconnection refused\nlater fatal"},
        ]

        with patch.object(agent, "search_incident_knowledge", return_value="matched") as knowledge:
            result = specialists._knowledge(agent, "")

        knowledge.assert_called_once_with("connection refused")
        self.assertEqual(result["role"], "knowledge")
        self.assertEqual(result["turns"], 0)

    def test_tool_visibility_policy_and_adaptive_trigger(self):
        with patch.dict(os.environ):
            os.environ.pop("AGENT_MODE", None)
            with patch.dict(sys.modules, {"openai": sdk, "agent": agent}):
                single_api = load_script("ops_api", "parallel_single_ops_api")
        with patch.dict(os.environ, {"AGENT_MODE": "adaptive"}), patch.dict(sys.modules, {"openai": sdk}):
            adaptive_agent = load_script("agent", "parallel_adaptive_agent")
        with patch.dict(os.environ, {"AGENT_MODE": "adaptive"}), \
                patch.dict(sys.modules, {"openai": sdk, "agent": adaptive_agent}):
            adaptive_api = load_script("ops_api", "parallel_adaptive_ops_api")

        self.assertNotIn("parallel_diagnosis", {tool["name"] for tool in agent.TOOLS})
        self.assertNotIn("parallel_diagnosis", {tool["name"] for tool in single_api.TOOLS})
        self.assertIn("parallel_diagnosis", {tool["name"] for tool in adaptive_agent.TOOLS})
        self.assertIn("parallel_diagnosis", {tool["name"] for tool in adaptive_api.TOOLS})
        self.assertIn("parallel_diagnosis", faults.DIAGNOSTIC)
        self.assertNotIn("parallel_diagnosis", agent.MUTATING)

        tier = types.SimpleNamespace(set_tier=lambda *_: None)
        with patch.object(agent, "http_status", return_value=503), patch.object(agent, "docker_ps", return_value="down"), \
                patch.dict(sys.modules, {"tier": tier}), patch.dict(os.environ):
            os.environ.pop("AGENT_MODE", None)
            single = agent.with_health("changed")
        with patch.object(agent, "http_status", return_value=503), patch.object(agent, "docker_ps", return_value="down"), \
                patch.dict(sys.modules, {"tier": tier}), patch.dict(os.environ, {"AGENT_MODE": "adaptive"}):
            adaptive = agent.with_health("changed")

        trigger = "still failing after an action: parallel_diagnosis gathers the service, platform and knowledge views at once."
        self.assertNotIn(trigger, single)
        self.assertIn(trigger, adaptive)


if __name__ == "__main__":
    unittest.main()
