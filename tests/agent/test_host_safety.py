"""Host-tool regressions; no Docker, network, or filesystem cleanup is performed."""
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from ops_safety import diagnostic_argv, restore_config_file  # noqa: E402


class DiagnosticPolicyTest(unittest.TestCase):
    def test_existing_runbook_diagnostics_keep_their_arguments(self):
        cases = [
            ("nginx -t", ["nginx", "-t"]),
            ("nginx -T", ["nginx", "-T"]),
            ("du -sh /var/cache/nginx /tmp", ["du", "-sh", "/var/cache/nginx", "/tmp"]),
            ("df -i /", ["df", "-i", "/"]),
            ("cat '/tmp/file with spaces'", ["cat", "/tmp/file with spaces"]),
            ("grep -E 'failed|error' /var/log/nginx/error.log",
             ["grep", "-E", "failed|error", "/var/log/nginx/error.log"]),
            ("tail -n 40 /var/log/nginx/error.log", ["tail", "-n", "40", "/var/log/nginx/error.log"]),
            ("env", ["env"]),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(diagnostic_argv(command), expected)

    def test_prefix_matches_cannot_select_other_executables(self):
        for command in ("lsblk", "psql -c VACUUM", "/bin/sh -c id", "nginx -s reload"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                diagnostic_argv(command)

    def test_env_cannot_launch_children(self):
        for command in ("env sh -c id", "env -S 'sh -c id'", "env PATH=/tmp id"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                diagnostic_argv(command)

    def test_shell_controls_and_invalid_types_are_rejected(self):
        for command in (None, 1, "", "ls\nid", "cat $(id)", "cat `id`", "ls / ; id", "ls / | head", "ls 'oops"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                diagnostic_argv(command)

    def test_curl_keeps_read_requests_and_disables_implicit_configuration(self):
        for command in ("curl -fsS http://edge-victim-app/", "curl -I https://127.0.0.1/",
                        "curl --max-time=2 -X GET http://192.168.1.20:8880/",
                        "curl --url http://[::1]/", "curl --request HEAD http://localhost/"):
            with self.subTest(command=command):
                argv = diagnostic_argv(command)
                self.assertEqual(argv[:2], ["curl", "--disable"])
                self.assertIn("--globoff", argv)
                self.assertEqual(argv[argv.index("--max-redirs") + 1], "0")
                self.assertEqual(argv[argv.index("--proto") + 1], "=http,https")
                self.assertEqual(argv[argv.index("--noproxy") + 1], "*")

    def test_curl_cannot_write_upload_load_config_or_redirect(self):
        options = ["-X POST", "--request=DELETE", "-o /tmp/out", "--output=/tmp/out", "-O", "-T /tmp/data",
                   "--data=x", "-d x", "-K /tmp/curlrc", "--config=/tmp/curlrc", "-L", "--location",
                   "--write-out=%output{/tmp/out}", "--proxy http://127.0.0.1/", "--next", "--trace /tmp/trace",
                   "--resolve edge-victim-app:80:8.8.8.8", "--header X-HTTP-Method-Override:DELETE"]
        for option in options:
            with self.subTest(option=option), self.assertRaises(ValueError):
                diagnostic_argv(f"curl {option} http://edge-victim-app/")

    def test_curl_target_and_timeout_validation(self):
        cases = ["curl file:///etc/passwd", "curl ftp://127.0.0.1/", "curl https://example.com/",
                 "curl http://8.8.8.8/", "curl http://169.254.169.254/", "curl http://0.0.0.0/",
                 "curl http://224.0.0.1/", "curl http://user:pass@localhost/", "curl http://localhost:99999/",
                 "curl -m 0 http://localhost/", "curl -m nan http://localhost/", "curl -m inf http://localhost/",
                 "curl --max-time 11 http://localhost/", "curl --max-time", "curl --max-time=bad http://localhost/",
                 "curl http://localhost/ http://edge-victim-app/", "curl"]
        for command in cases:
            with self.subTest(command=command), self.assertRaises(ValueError):
                diagnostic_argv(command)

    def test_tail_cannot_leave_a_following_process_running(self):
        for command in ("tail -f /tmp/log", "tail -nF 10 /tmp/log", "tail --follow=name /tmp/log"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                diagnostic_argv(command)


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
        try:
            # unittest discovery also creates a package named agent from tests/agent.
            # Load the operational script by file path to avoid testing that package.
            spec = importlib.util.spec_from_file_location("host_agent_safety_under_test", SCRIPTS / "agent.py")
            cls.agent = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.agent)
        except ModuleNotFoundError as error:
            if error.name == "openai":
                raise unittest.SkipTest("host integration requires the project's openai dependency") from error
            raise

    def setUp(self):
        # These tests exercise the dispatch of mutating tools; on a box whose stack is healthy, main's HEALTHY_GUARD
        # would refuse them first. The guard has its own tests in test_host_safety_pr4.py.
        self._guard = patch.dict(self.agent.os.environ, {"HEALTHY_GUARD": "0"})
        self._guard.start()
        self.addCleanup(self._guard.stop)

    def test_docker_exec_runs_argv_without_an_inner_shell(self):
        with patch.object(self.agent, "sh", return_value="ok") as run:
            result = self.agent._run_tool("docker_exec", {"name": "edge-victim-app", "cmd": "df -h /"}, True)
        self.assertEqual(result, "ok")
        run.assert_called_once_with(["docker", "exec", "edge-victim-app", "df", "-h", "/"])

    def test_mutating_diagnostics_never_reach_the_executor(self):
        for command in ("curl -X POST http://edge-victim-app/", "env sh -c id"):
            with self.subTest(command=command), patch.object(self.agent, "sh") as run:
                result = self.agent._run_tool("docker_exec", {"name": "edge-victim-app", "cmd": command}, False)
                self.assertTrue(result.startswith("denied:"))
                run.assert_not_called()

    def test_outside_container_is_denied_before_execution(self):
        with patch.object(self.agent, "sh") as run:
            result = self.agent._run_tool("docker_exec", {"name": "vllm-edge", "cmd": "id"}, False)
        self.assertTrue(result.startswith("denied:"))
        run.assert_not_called()

    def test_argv_subprocess_does_not_enable_shell(self):
        completed = Mock(stdout="ok", stderr="", returncode=0)
        with patch.object(self.agent.subprocess, "run", return_value=completed) as run:
            self.assertEqual(self.agent.sh(["docker", "exec", "edge-victim", "id"]), "ok")
        self.assertIs(run.call_args.kwargs["shell"], False)

    def test_restore_dispatch_passes_previous_without_overwriting_it(self):
        previous, conf_dir, good_dir = Mock(), pathlib.PurePosixPath("/fake/conf"), Mock()
        previous.name = "previous.conf"
        with patch.dict(self.agent._incident, runbook_seen=True), patch.object(self.agent, "PREVIOUS", previous), \
                patch.object(self.agent, "CONF_DIR", conf_dir), patch.object(self.agent, "KNOWN_GOOD_DIR", good_dir), \
                patch.object(self.agent, "restore_config_file") as restore:
            result = self.agent._run_tool("restore_config", {"source": "previous"}, False)
        self.assertTrue(result.startswith("restored previous.conf"))
        restore.assert_called_once_with(conf_dir / "default.conf", previous, previous)
        previous.write_text.assert_not_called()

    def test_restore_dry_run_never_writes_files(self):
        previous = Mock()
        previous.name = "previous.conf"
        with patch.dict(self.agent._incident, runbook_seen=True), patch.object(self.agent, "PREVIOUS", previous), \
                patch.object(self.agent, "restore_config_file") as restore:
            result = self.agent._run_tool("restore_config", {"source": "previous"}, True)
        self.assertTrue(result.startswith("DRY-RUN"))
        restore.assert_not_called()

    def test_restore_rejects_unknown_sources(self):
        with patch.dict(self.agent._incident, runbook_seen=True), patch.object(self.agent, "restore_config_file") as restore:
            result = self.agent._run_tool("restore_config", {"source": "typo"}, False)
        self.assertTrue(result.startswith("error:"))
        restore.assert_not_called()


if __name__ == "__main__":
    unittest.main()
