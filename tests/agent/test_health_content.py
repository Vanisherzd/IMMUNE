"""A 200 with the wrong page is not healthy (upstream-wrong-content, 2026-10-22)."""
import io
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
os.environ.setdefault("HEALTHY_GUARD", "0")
try:
    import openai  # noqa: F401
except ImportError:
    sys.modules["openai"] = types.SimpleNamespace(OpenAI=object)
import agent  # noqa: E402
import faults  # noqa: E402


class Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class HealthContentTest(unittest.TestCase):
    def _probe(self, body):
        old = agent.urllib.request.build_opener
        agent.urllib.request.build_opener = lambda *a, **k: types.SimpleNamespace(open=lambda url, timeout=None: Resp(body))
        try:
            return agent.http_status("http://127.0.0.1:8880/api/")
        finally:
            agent.urllib.request.build_opener = old

    def test_expected_markers_come_from_the_stack_definition(self):
        self.assertEqual(agent.expected_body("http://127.0.0.1:8880/"), faults.EXPECT_BODY["/"])
        self.assertEqual(agent.expected_body("http://127.0.0.1:8880/api/"), faults.EXPECT_BODY["/api/"])
        self.assertEqual(agent.expected_body("http://127.0.0.1:8880/other"), "")

    def test_right_page_is_200(self):
        self.assertEqual(self._probe(b"<html><title>Welcome to nginx!</title></html>"), 200)

    def test_wrong_page_is_not_200(self):
        out = self._probe(b"service under maintenance\n")
        self.assertNotEqual(out, 200)
        self.assertIn("not the deployed page", out)
        self.assertIn("maintenance", out)

    def test_escape_hatch_restores_status_only(self):
        os.environ["HEALTH_CONTENT"] = "0"
        try:
            self.assertEqual(self._probe(b"service under maintenance\n"), 200)
        finally:
            del os.environ["HEALTH_CONTENT"]


if __name__ == "__main__":
    unittest.main()
