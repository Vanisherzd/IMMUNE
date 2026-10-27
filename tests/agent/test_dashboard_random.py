"""The dashboard's random real fault: one case drawn from the whole catalogue, injected through faults.py like any card."""
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import faults  # noqa: E402

spec = importlib.util.spec_from_file_location("dashboard", SCRIPTS / "dashboard.py")
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class RandomCardTest(unittest.TestCase):
    def test_draw_case_comes_from_the_catalogue(self):
        seen = {dashboard.draw_case() for _ in range(40)}
        self.assertTrue(seen <= set(faults.CASES))
        self.assertGreater(len(seen), 5, "forty draws from 49 cases should not collapse onto a handful")

    def test_random_action_injects_a_drawn_case_and_rejects_unknown_ones(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return types.SimpleNamespace(returncode=0, stdout="injected", stderr="")
        with mock.patch.object(dashboard, "ACTIONS", True), mock.patch.object(dashboard, "pgrep", return_value=False), \
             mock.patch.object(dashboard.subprocess, "run", side_effect=fake_run):
            code, body = dashboard.action({"action": "inject", "case": "random"})
            self.assertEqual(code, 200, body)
            self.assertEqual(calls[-1][1:3], ["scripts/faults.py", "inject"])
            self.assertIn(calls[-1][3], faults.CASES)
            code, body = dashboard.action({"action": "inject", "case": "not-a-case"})
            self.assertEqual(code, 400)

    def test_actions_refused_while_a_drill_runs(self):
        with mock.patch.object(dashboard, "ACTIONS", True), mock.patch.object(dashboard, "pgrep", return_value=True):
            code, _ = dashboard.action({"action": "inject", "case": "random"})
            self.assertEqual(code, 409)


if __name__ == "__main__":
    unittest.main()
