"""Tests merged with PR #4 (the earlier version of the host-safety work); kept whole beside the follow-up suite."""
"""Rollback and command compatibility tests; no Docker, network, or file cleanup."""
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import Mock, patch

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from ops_safety import restore_config_file


class MemoryFile:
    def __init__(self, text):
        self.text = text

    def read_text(self):
        return self.text

    def write_text(self, text):
        self.text = text


class ConfigRestoreTest(unittest.TestCase):
    def test_previous_source_is_read_before_it_is_rotated(self):
        current = MemoryFile("broken config")
        previous = MemoryFile("previous healthy config")
        restore_config_file(current, previous, previous)
        self.assertEqual(current.text, "previous healthy config")
        self.assertEqual(previous.text, "broken config")

    def test_known_good_is_retained_and_current_is_backed_up(self):
        current, source, previous = (MemoryFile(v) for v in ("broken", "known good", "older"))
        restore_config_file(current, source, previous)
        self.assertEqual((current.text, source.text, previous.text), ("known good", "known good", "broken"))

    def test_unreadable_source_does_not_overwrite_current_or_backup(self):
        current, previous = MemoryFile("broken"), MemoryFile("older")
        source = Mock()
        source.read_text.side_effect = OSError("unreadable source")
        with self.assertRaises(OSError):
            restore_config_file(current, source, previous)
        self.assertEqual((current.text, previous.text), ("broken", "older"))

    def test_backup_failure_leaves_active_config_untouched(self):
        current, source = MemoryFile("broken"), MemoryFile("healthy")
        previous = Mock()
        previous.write_text.side_effect = OSError("cannot back up")
        with self.assertRaises(OSError):
            restore_config_file(current, source, previous)
        self.assertEqual(current.text, "broken")


class HostDispatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No model calls are made. Missing SDK imports use an inert stand-in.
        try:
            import openai
        except ModuleNotFoundError as error:
            if error.name != "openai":
                raise
            sdk = types.ModuleType("openai")
            sdk.OpenAI = Mock(side_effect=AssertionError("LLM calls are forbidden in host-tool tests"))
            with patch.dict(sys.modules, {"openai": sdk}):
                cls.agent = cls.load_agent()
        else:
            cls.agent = cls.load_agent()

    @staticmethod
    def load_agent():
        spec = importlib.util.spec_from_file_location("host_agent_safety_under_test", SCRIPTS / "agent.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def setUp(self):
        # these tests act inside an incident: the stack is down, whatever the real health URLs say
        health = patch.object(self.agent, "http_status", return_value=500)
        health.start()
        self.addCleanup(health.stop)

    def test_healthy_stack_refuses_state_changes(self):
        with patch.object(self.agent, "http_status", return_value=200), patch.object(self.agent, "sh") as run:
            for name, args in (("docker_restart", {"name": "edge-victim"}), ("write_config", {"content": "x"}),
                               ("restore_config", {"source": "known-good"})):
                with self.subTest(tool=name):
                    result = self.agent._run_tool(name, args, False)
                    self.assertTrue(result.startswith("refused: (automatic rule) the stack is healthy"), result)
            run.assert_not_called()

    def test_healthy_guard_can_be_switched_off(self):
        with patch.object(self.agent, "http_status", return_value=200), \
                patch.dict(self.agent.os.environ, {"HEALTHY_GUARD": "0"}), \
                patch.dict(self.agent._incident, runbook_seen=False, refusals=0):
            result = self.agent._run_tool("docker_restart", {"name": "edge-victim"}, False)
        self.assertNotIn("the stack is healthy", result)

    # test_existing_diagnostic_forms_are_not_newly_denied was removed in the merge of the follow-up branch: it
    # asserted the OLD policy (curl -L/-X POST/-o, tail -f, nginx -t -c <custom> allowed), which that branch
    # deliberately denies; tests/agent/test_host_safety.py covers the new policy.

    def test_original_container_and_shell_operator_guards_remain(self):
        cases = [
            {"name": "vllm-edge", "cmd": "id"},
            {"name": "edge-victim-app", "cmd": "ls / ; id"},
            {"name": "edge-victim-app", "cmd": "cat $(id)"},
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments), patch.object(self.agent, "sh") as run:
                result = self.agent._run_tool("docker_exec", arguments, False)
                self.assertTrue(result.startswith("denied:"))
                run.assert_not_called()

    def test_restore_dispatch_reads_backup_before_rotation(self):
        previous, conf_dir, good_dir = Mock(), pathlib.PurePosixPath("/fake/conf"), Mock()
        previous.name = "previous.conf"
        with patch.dict(self.agent._incident, runbook_seen=True), patch.object(self.agent, "PREVIOUS", previous), patch.object(self.agent, "CONF_DIR", conf_dir), patch.object(self.agent, "KNOWN_GOOD_DIR", good_dir), patch.object(self.agent, "restore_config_file") as restore:
            result = self.agent._run_tool("restore_config", {"source": "previous"}, False)
        self.assertTrue(result.startswith("restored previous.conf"))
        restore.assert_called_once_with(conf_dir / "default.conf", previous, previous)
        previous.write_text.assert_not_called()

    def test_restore_dry_run_never_writes_files(self):
        previous = Mock()
        previous.name = "previous.conf"
        with patch.dict(self.agent._incident, runbook_seen=True), patch.object(self.agent, "PREVIOUS", previous), patch.object(self.agent, "restore_config_file") as restore:
            result = self.agent._run_tool("restore_config", {"source": "previous"}, True)
        self.assertTrue(result.startswith("DRY-RUN"))
        restore.assert_not_called()

    def test_missing_backup_does_not_write_config(self):
        previous = Mock()
        previous.exists.return_value = False
        with patch.dict(self.agent._incident, runbook_seen=True), patch.object(self.agent, "PREVIOUS", previous), patch.object(self.agent, "restore_config_file") as restore:
            result = self.agent._run_tool("restore_config", {"source": "previous"}, False)
        self.assertTrue(result.startswith("error: no previous"))
        restore.assert_not_called()


if __name__ == "__main__":
    unittest.main()
