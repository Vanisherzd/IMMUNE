"""VM victim mode: the read-only allow-list over ssh, the tool list and health switch, and the vm_* tool guards."""
import os
import pathlib
import subprocess
import sys
import types
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
if "openai" not in sys.modules:
    try:
        import openai  # noqa: F401
    except Exception:
        sys.modules["openai"] = types.SimpleNamespace(OpenAI=object)
import agent  # noqa: E402
import vm_victim  # noqa: E402


class VmArgvTest(unittest.TestCase):
    def test_read_only_commands_pass_and_mutating_or_shell_forms_are_refused(self):
        self.assertEqual(agent.vm_argv("systemctl status nginx")[:3], ["systemctl", "status", "nginx"])
        self.assertIn("--no-pager", agent.vm_argv("journalctl -u nginx -n 20"))
        self.assertEqual(agent.vm_argv("cat /etc/nginx/sites-available/default"), ["cat", "/etc/nginx/sites-available/default"])
        for bad in ("systemctl stop nginx", "systemctl restart nginx", "rm -rf /var/www", "cat /etc/passwd | grep root",
                    "journalctl -f -u nginx", "sudo systemctl status nginx", "bash -c id"):
            with self.subTest(cmd=bad):
                with self.assertRaises(ValueError):
                    agent.vm_argv(bad)


class VmToolGuardTest(unittest.TestCase):
    def setUp(self):
        self.saved = agent.VM_VICTIM
        agent.VM_VICTIM = True
        agent.vm_victim = vm_victim

    def tearDown(self):
        agent.VM_VICTIM = self.saved

    def test_service_refuses_other_units_and_actions(self):
        self.assertTrue(agent.vm_tool("vm_service", {"unit": "sshd", "action": "restart"}, False).startswith("denied:"))
        self.assertTrue(agent.vm_tool("vm_service", {"unit": "nginx", "action": "stop"}, False).startswith("denied:"))
        self.assertTrue(agent.vm_tool("vm_service", {"unit": "nginx", "action": "mask"}, False).startswith("denied:"))

    def test_exec_runs_only_allowed_argv_over_ssh(self):
        with mock.patch.object(vm_victim, "run", return_value="active") as run:
            self.assertEqual(agent.vm_tool("vm_exec", {"cmd": "systemctl is-active nginx"}, False), "active")
            self.assertEqual(run.call_args[0][0], ["systemctl", "is-active", "nginx"])
            self.assertTrue(agent.vm_tool("vm_exec", {"cmd": "systemctl stop nginx"}, False).startswith("denied:"))
            self.assertEqual(run.call_count, 1)

    def test_dry_run_changes_nothing(self):
        with mock.patch.object(vm_victim, "run") as run:
            self.assertTrue(agent.vm_tool("vm_service", {"unit": "nginx", "action": "restart"}, True).startswith("DRY-RUN"))
            run.assert_not_called()

    def test_vm_tools_denied_when_mode_is_off(self):
        agent.VM_VICTIM = False
        self.assertTrue(agent._run_tool("vm_exec", {"cmd": "id"}, False).startswith("denied:"))


class VmModeImportTest(unittest.TestCase):
    def test_vm_mode_swaps_health_and_tool_list(self):
        code = ("import sys, types; sys.modules.setdefault('openai', types.SimpleNamespace(OpenAI=object)); "
                "import agent, json; print(json.dumps({'health': agent.HEALTH, 'tools': [t['name'] for t in agent.TOOLS]}))")
        out = subprocess.run([sys.executable, "-c", code], cwd=SCRIPTS, capture_output=True, text=True,
                             env={**os.environ, "VM_VICTIM": "1", "VM_HTTP_PORT": "8881"})
        self.assertEqual(out.returncode, 0, out.stderr[-500:])
        import json
        d = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(d["health"], {"front": "http://127.0.0.1:8881/", "api": "http://127.0.0.1:8881/api/"})
        self.assertTrue({"vm_exec", "vm_logs", "vm_service", "vm_write_config", "vm_restore_config", "check_health", "search_runbooks", "finish"} <= set(d["tools"]))
        self.assertFalse({"docker_restart", "recreate_stack", "write_config", "kill_process"} & set(d["tools"]))

    def test_vm_victim_module_shapes(self):
        self.assertEqual(set(vm_victim.CASES), {"vm-nginx-stopped", "vm-bad-config", "vm-unit-masked", "vm-config-deleted"})
        self.assertIn("-o", vm_victim.ssh_argv())
        self.assertIn("BatchMode=yes", vm_victim.ssh_argv())


if __name__ == "__main__":
    unittest.main()
