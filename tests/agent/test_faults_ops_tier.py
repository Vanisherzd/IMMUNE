"""The ops tier's metadata and injection patterns, checked without docker: every case names real tools, its cause
regex compiles and is not vacuous on a blank report, and the sed patterns match the official nginx default.conf."""
import ast
import pathlib
import re
import subprocess
import sys
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import faults  # noqa: E402

NGINX_DEFAULT_CONF = """server {
    listen       80;
    listen  [::]:80;
    server_name  localhost;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }
}
"""


def tool_names():
    tree = ast.parse((SCRIPTS / "agent.py").read_text())
    tools = next(n.value for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "TOOLS" for t in n.targets))
    return {ast.literal_eval(e)["name"] for e in tools.elts}


class OpsTierTest(unittest.TestCase):
    def test_ops_cases_are_well_formed(self):
        tools = tool_names()
        ops = {k: v for k, v in faults.CASES.items() if v["tier"] == "ops"}
        self.assertGreaterEqual(len(ops), 9)
        for name, meta in ops.items():
            with self.subTest(case=name):
                self.assertTrue(meta["fix_tools"] <= tools, meta["fix_tools"] - tools)
                self.assertIsNone(re.compile(meta["cause"], re.I).search("Root cause: unknown. Actions: none. Final health: 200/200."),
                                  "cause regex is vacuous")
                self.assertTrue(meta.get("diag_tools"))

    def test_listen_localhost_sed_rewrites_the_official_conf(self):
        out = subprocess.run(["sed", "-E", "s/listen( +)80;/listen\\1127.0.0.1:80;/; /listen( +)\\[::\\]:80;/d"],
                             input=NGINX_DEFAULT_CONF, capture_output=True, text=True).stdout
        self.assertIn("listen       127.0.0.1:80;", out)
        self.assertNotIn("[::]:80", out)

    def test_slow_body_sed_adds_limit_rate_inside_the_location(self):
        out = subprocess.run(["sed", "-E", "s/(index +index\\.html index\\.htm;)/\\1 limit_rate 1;/"],
                             input=NGINX_DEFAULT_CONF, capture_output=True, text=True).stdout
        self.assertIn("index  index.html index.htm; limit_rate 1;", out)

    def test_wrong_service_conf_points_the_api_at_the_front_end_itself(self):
        self.assertIn("proxy_pass http://edge-victim:80/", faults.WRONG_SERVICE_CONF)
        self.assertNotIn("edge-victim-app", faults.WRONG_SERVICE_CONF)

    def test_readonly_and_squatter_are_undone_by_reset_source(self):
        src = (SCRIPTS / "faults.py").read_text()
        self.assertIn("ReadonlyRootfs", src.split("def reset")[1].split("def inject")[0])
        self.assertIn("SQUATTER", src.split("def reset")[1].split("def inject")[0])


if __name__ == "__main__":
    unittest.main()
