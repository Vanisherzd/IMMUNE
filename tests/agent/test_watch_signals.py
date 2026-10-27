import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import watch_signals


class WatchSignalTests(unittest.TestCase):
    def test_container_state_opens_for_exited_restarting_and_oom(self):
        text = ("edge-victim\tExited (1) 2 seconds ago\t3 minutes\n"
                "edge-victim-app\tRestarting (1) 1 second ago\t3 minutes\n"
                "edge-victim-app OOMKilled=yes RestartCount=2\n")

        findings = watch_signals.container_state(text)

        self.assertEqual([item["severity"] for item in findings], ["open", "open", "open"])
        self.assertTrue(any("Exited" in item["detail"] for item in findings))
        self.assertTrue(any("Restarting" in item["detail"] for item in findings))
        self.assertTrue(any("OOMKilled=yes" in item["detail"] for item in findings))

    def test_restart_count_increase_warns_while_container_is_up(self):
        previous = "edge-victim\tUp 10 minutes\n/edge-victim\tOOMKilled=false\tRestartCount=2"
        current = "edge-victim\tUp 2 minutes\n/edge-victim\tOOMKilled=false\tRestartCount=3"

        findings = watch_signals.container_state(current, previous)

        self.assertEqual(findings, [{"signal": "container_restart", "severity": "warn",
                                     "detail": "edge-victim restart count 2 -> 3 while Up"}])

    def test_log_errors_carry_each_matching_line(self):
        text = ("2026/10/22 [emerg] invalid directive\n"
                "write() failed (28: No space left on device)\n"
                "ordinary access log\n")

        findings = watch_signals.log_errors("edge-victim", text)

        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item["severity"] == "warn" for item in findings))
        self.assertIn("[emerg] invalid directive", findings[0]["detail"])
        self.assertIn("No space left on device", findings[1]["detail"])

    def test_disk_warns_at_91_and_opens_at_99(self):
        text = ("Filesystem Size Used Avail Use% Mounted on\n"
                "/dev/a 100G 91G 9G 91% /\n"
                "/dev/b 100G 99G 1G 99% /cache\n")

        findings = watch_signals.disk(text)

        self.assertEqual([item["severity"] for item in findings], ["warn", "open"])

    def test_disk_warns_for_inode_usage_at_95(self):
        text = ("inodes:\nFilesystem Inodes IUsed IFree IUse% Mounted on\n"
                "/dev/a 100 95 5 95% /\n")

        findings = watch_signals.disk(text)

        self.assertEqual(findings[0]["signal"], "disk_inodes")
        self.assertEqual(findings[0]["severity"], "warn")

    def test_docker_events_return_only_open_stack_events(self):
        lines = "\n".join((
            json.dumps({"Action": "die", "Actor": {"Attributes": {"name": "edge-victim-app"}}}),
            json.dumps({"Action": "start", "Actor": {"Attributes": {"name": "unrelated"}}}),
        ))

        findings = watch_signals.docker_events(lines)

        self.assertEqual(findings, [{"signal": "docker_event", "severity": "open",
                                     "detail": "edge-victim-app: die"}])

    def test_append_signals_adds_heading_and_details(self):
        findings = [{"signal": "docker_event", "severity": "open", "detail": "edge-victim-app: die"}]

        alert = watch_signals.append_signals("Alert: degraded.", findings)

        self.assertEqual(alert, "Alert: degraded.\n\nSignals:\n- [open] docker_event: edge-victim-app: die")


if __name__ == "__main__":
    unittest.main()
