"""The tool layer pushes community references for symptoms no runbook owns (scripts/agent.py community_push)."""
import pathlib
import sys
import tempfile
import time
import types
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
if "openai" not in sys.modules:                 # agent.py imports the client at module level; these tests never call it
    try:
        import openai  # noqa: F401
    except Exception:
        sys.modules["openai"] = types.SimpleNamespace(OpenAI=object)
import agent  # noqa: E402
import community_knowledge  # noqa: E402

TOO_BIG = 'upstream sent too big header while reading response header from upstream, upstream: "http://172.24.0.3:80/", host: "127.0.0.1:8880"'
NOFILE = "socket() failed (24: Too many open files) while connecting to upstream"


class OwnedSymptomTest(unittest.TestCase):
    def test_runbook_symptoms_and_status_codes_are_owned(self):
        for q in ["connect() failed (111: Connection refused) while connecting to upstream",
                  "the service itself answers HTTP 502 Bad Gateway to requests, container is up.",
                  "directory index of /usr/share/nginx/html/ is forbidden"]:
            self.assertTrue(community_knowledge.owned_symptom(q), q)

    def test_entity_names_alone_do_not_own_an_error_line(self):
        for q in (TOO_BIG, NOFILE):
            self.assertFalse(community_knowledge.owned_symptom(q), q)
            self.assertTrue(community_knowledge.stack_covers(q), q)   # the wider gate says covered: why the push has its own


class PushFixture(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.stub = types.SimpleNamespace(owned_symptom=community_knowledge.owned_symptom,
                                          references=lambda q, k=2, owned=None: self.calls.append(q) or "\ncommunity references (x):\n- A :: x\n- B :: y")
        self.real = sys.modules.get("community_knowledge")
        sys.modules["community_knowledge"] = self.stub
        self.saved = (agent.COMMUNITY_PUSH, agent.COMMUNITY_PUSH_TIMEOUT, agent.ROOT)
        agent._incident["community_seen"], agent._incident["community_pending"] = set(), {}
        agent.COMMUNITY_PUSH, agent.COMMUNITY_PUSH_TIMEOUT = True, 4.0
        agent.ROOT = pathlib.Path(tempfile.mkdtemp())
        (agent.ROOT / "logs").mkdir()

    def tearDown(self):
        sys.modules["community_knowledge"] = self.real
        agent.COMMUNITY_PUSH, agent.COMMUNITY_PUSH_TIMEOUT, agent.ROOT = self.saved


class CommunityPushTest(PushFixture):
    def test_pushes_once_per_symptom_and_drops_the_status_prefix(self):
        q = "the service itself answers HTTP 502 Bad Gateway to requests, container is up. " + TOO_BIG
        out = agent.community_push(q)
        self.assertIn("- A", out)
        self.assertEqual(self.calls, ["upstream sent too big header while reading response header from upstream"])   # fields stripped
        self.assertEqual(agent.community_push(q), "")          # same symptom, same incident: once
        self.assertEqual(len(self.calls), 1)
        logged = (agent.ROOT / "logs" / "ops-api.log").read_text()
        self.assertIn('"tool": "community_push"', logged)
        self.assertIn("2 references", logged)

    def test_owned_symptoms_and_status_only_queries_push_nothing(self):
        self.assertEqual(agent.community_push("connect() failed (111: Connection refused) while connecting to upstream"), "")
        self.assertEqual(agent.community_push("the service itself answers HTTP 504 Gateway Timeout to requests, container is up."), "")
        self.assertEqual(self.calls, [])

    def test_failure_and_timeout_fail_open(self):
        def boom(q, k=2, owned=None):
            raise RuntimeError("sidecar down")
        self.stub.references = boom
        self.assertEqual(agent.community_push(NOFILE), "")
        agent._incident["community_seen"], agent._incident["community_pending"] = set(), {}

        def slow(q, k=2, owned=None):
            time.sleep(0.4)
            return "late"
        self.stub.references = slow
        agent.COMMUNITY_PUSH_TIMEOUT = 0.05
        self.assertEqual(agent.community_push(NOFILE), "")

    def test_off_switch(self):
        agent.COMMUNITY_PUSH = False
        self.assertEqual(agent.community_push(NOFILE), "")
        self.assertEqual(self.calls, [])

    def test_reviewer_trace_never_sees_other_hosts_text(self):
        kept = agent.trace_summary("search_runbooks", "## runbook\nsteps\ncommunity references (x):\n- A :: other host")
        self.assertNotIn("other host", kept)


if __name__ == "__main__":
    unittest.main()


OWNED_LINES = [   # error lines of existing faults that the first gate let through (review of 1ac26df)
    '[emerg] 1#1: invalid number of arguments in "return" directive in /etc/nginx/conf.d/default.conf:3',
    "upstream timed out (110: Connection timed out) while reading response header from upstream",
    "connect() failed (113: No route to host) while connecting to upstream",
    'open() "/etc/nginx/snippets/proxy.conf" failed (2: No such file or directory)',
    '[emerg] 1#1: invalid parameter "weight=x" in /etc/nginx/conf.d/default.conf:2',
    'open() "/usr/share/nginx/html/index.html" failed (13: Permission denied)',
    '[emerg] 1#1: unexpected "}" in /etc/nginx/conf.d/default.conf:5',
]
PREAMBLE = ('2026/10/22 07:40:12 [error] 29#29: *503 upstream sent too big header while reading response header from upstream, '
            'client: 172.24.0.1, server: _, request: "GET /api/ HTTP/1.1", upstream: "http://172.24.0.3:80/", host: "127.0.0.1:8880"')


class ReviewRegressionTest(PushFixture):
    def test_existing_faults_error_lines_are_owned(self):
        for line in OWNED_LINES:
            self.assertTrue(community_knowledge.owned_symptom(line), line)
            self.assertEqual(agent.community_push(line), "")
        self.assertEqual(self.calls, [])

    def test_nginx_preamble_and_fields_do_not_trip_the_gate_and_are_cleaned_for_retrieval(self):
        self.assertIn("- A", agent.community_push(PREAMBLE))
        self.assertEqual(self.calls, ["upstream sent too big header while reading response header from upstream"])

    def test_slow_push_lands_on_the_next_read_instead_of_being_lost(self):
        def slow(q, k=2, owned=None):
            time.sleep(0.3)
            return "\ncommunity references (x):\n- late :: y"
        self.stub.references = slow
        agent.COMMUNITY_PUSH_TIMEOUT = 0.05
        self.assertEqual(agent.community_push(NOFILE), "")
        time.sleep(0.5)
        self.assertIn("- late", agent.community_push(NOFILE))
        self.assertEqual(agent.community_push(NOFILE), "")      # then once, as usual

    def test_trace_cut_is_block_local_for_a_bundle(self):
        bundle = ("## docker_logs {}\nlog line\n\n--- matching runbook ---\n## x\nsteps\ncommunity references (x):\n- A :: other host\n\n"
                  "## read_config {}\nserver {}\nhealth now: {\"front\": 200}")
        kept = agent.trace_summary("evidence_bundle", bundle)
        self.assertNotIn("other host", kept)
        self.assertIn("read_config", kept)
        self.assertIn("health now", kept)


FLOOD = "\n".join(
    ['2026/10/22 00:14:05 [emerg] 39#39: epoll_create() failed (24: Too many open files)'] +
    [f'2026/10/22 00:14:05 [notice] 1#1: signal 17 (SIGCHLD) received from {n}\n'
     f'2026/10/22 00:14:05 [notice] 1#1: worker process {n} exited with code 2\n'
     f'2026/10/22 00:14:05 [alert] 1#1: worker process {n} exited with fatal code 2 and cannot be respawned\n'
     f'2026/10/22 00:14:05 [notice] 1#1: signal 29 (SIGIO) received' for n in range(40, 60)])
MIXED = ('2026/10/22 00:13:43 [error] 30#30: *14 connect() failed (111: Connection refused) while connecting to upstream, client: 172.23.0.1 '
         + PREAMBLE)


class FloodAndHistoryTest(PushFixture):
    def test_symptom_query_keeps_the_line_that_names_the_cause_under_a_flood(self):
        q = agent.symptom_query(FLOOD)
        self.assertIn("Too many open files", q)
        self.assertIn("cannot be respawned", q)
        self.assertEqual(q.count("cannot be respawned"), 1)

    def test_push_decides_ownership_per_line(self):
        out = agent.community_push(MIXED)               # an earlier incident's refused line plus this one's header line
        self.assertIn("- A", out)
        self.assertEqual(self.calls, ["upstream sent too big header while reading response header from upstream"])

    def test_earlier_errors_surfaces_distinct_cause_lines_the_tail_lacks(self):
        tail = "\n".join(FLOOD.splitlines()[-30:])
        answers = {"inspect": "2026-10-22T00:14:00.000000000Z\n", "logs": FLOOD}
        real = agent.sh
        agent.sh = lambda cmd, **kw: answers["inspect"] if "inspect" in cmd else answers["logs"]
        try:
            got = agent.earlier_errors("edge-victim", tail)
        finally:
            agent.sh = real
        self.assertEqual(len(got), 1)
        self.assertIn("Too many open files", got[0])
