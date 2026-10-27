import importlib.util
import json
import pathlib
import socket
import sys
import threading
import unittest
import os
os.environ.setdefault("COMMUNITY_JUDGE", "0")   # the judge gate calls the model; unit tests never do
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "community_knowledge_under_test", ROOT / "scripts" / "community_knowledge.py"
)
assert SPEC and SPEC.loader
community_knowledge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(community_knowledge)

DOCS = [
    {
        "index_text": "kernel nf_conntrack conntrack table full dropping packet increase hashsize",
        "title": "nf_conntrack: table full, dropping packet",
        "answer_excerpt": "Inspect conntrack utilization and size the table for the observed traffic before changing limits.",
        "site": "serverfault", "score": 42, "category": "networking", "link": "https://serverfault.com/a/101",
        "answer_owner": "Alex Netops", "answer_license": "CC BY-SA 4.0", "answer_id": "101",
    },
    {
        "index_text": "ups battery power upsc ups.status OB LB runtime charge",
        "title": "UPS reports on battery and low battery",
        "answer_excerpt": "Confirm input power, battery charge, runtime, and the OB LB flags reported by upsc.",
        "site": "unix", "score": 37, "category": "power", "link": "https://unix.stackexchange.com/a/202",
        "answer_owner": "Sam Power", "answer_license": "CC BY-SA 3.0", "answer_id": "202",
    },
    {
        "index_text": "nginx address bind already in use listen socket port process",
        "title": "nginx cannot bind: address already in use",
        "answer_excerpt": "Find the process holding the listen socket and resolve the duplicate binding before restarting nginx.",
        "site": "serverfault", "score": 31, "category": "web", "link": "https://serverfault.com/a/303",
        "answer_owner": "Nina Web", "answer_license": "CC BY-SA 4.0", "answer_id": "303",
    },
    {
        "index_text": "image pull ImagePullBackOff registry credentials manifest tag kubelet",
        "title": "Pod remains in ImagePullBackOff",
        "answer_excerpt": "Inspect kubelet events, the image tag, and registry credentials before retrying the pull.",
        "site": "serverfault", "score": 29, "category": "containers", "link": "https://serverfault.com/a/404",
        "answer_owner": "Kai Cluster", "answer_license": "CC BY-SA 4.0", "answer_id": "404",
    },
    {
        "index_text": "edac memory corrected error dimm ecc mce hardware syndrome",
        "title": "EDAC reports a memory error",
        "answer_excerpt": "Map the EDAC report to a DIMM and review corrected error counts before scheduling hardware service.",
        "site": "unix", "score": 25, "category": "hardware", "link": "https://unix.stackexchange.com/a/505",
        "answer_owner": "Eve Hardware", "answer_license": "CC BY-SA 3.0", "answer_id": "505",
    },
]


class RerankHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        documents = json.loads(body)["documents"]
        payload = {"results": [
            {"index": index, "relevance_score": float(index + 1)}
            for index in range(len(documents))
        ]}
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *args):
        return


class CommunityKnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.original = (
            community_knowledge._index,
            community_knowledge.RERANK_URL,
            community_knowledge.RERANK_TOP_N,
            community_knowledge.RERANK_MIN_SCORE,
            community_knowledge.RERANK_TIMEOUT,
        )
        original_path = sys.path[:]
        try:
            self.index = community_knowledge.CommunityIndex(DOCS)
        finally:
            sys.path[:] = original_path
        community_knowledge._index = self.index
        community_knowledge.RERANK_URL = ""
        community_knowledge.RERANK_TOP_N = 20
        community_knowledge.RERANK_MIN_SCORE = 0
        community_knowledge.RERANK_TIMEOUT = 1
        self.server = None
        self.thread = None

    def tearDown(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        (
            community_knowledge._index,
            community_knowledge.RERANK_URL,
            community_knowledge.RERANK_TOP_N,
            community_knowledge.RERANK_MIN_SCORE,
            community_knowledge.RERANK_TIMEOUT,
        ) = self.original

    def test_index_searches_by_bm25_and_enforces_shared_token_floor(self):
        query = "kernel nf_conntrack table full dropping packet"
        results = self.index.search(query, k=5)

        self.assertEqual(results[0][2]["title"], DOCS[0]["title"])
        query_tokens = set(self.index.tokens(query))
        for score, shared_tokens, document in results:
            with self.subTest(title=document["title"]):
                self.assertIsInstance(score, float)
                self.assertGreaterEqual(len(shared_tokens), community_knowledge.MIN_SHARED)
                self.assertLessEqual(set(shared_tokens), query_tokens)
        self.assertEqual(self.index.search("galactic quasar"), [])
        self.assertEqual(self.index.search(""), [])

    def test_stack_covers_only_explicit_stack_symptoms_and_http_codes(self):
        covered = [
            "nginx stopped exited 0",
            "connect() failed (111: Connection refused) while connecting to upstream",
            "container edge-victim-app removed",
            "the service itself answers HTTP 504 Gateway Timeout",
            "502 bad gateway",
        ]
        uncovered = [
            "kernel: nf_conntrack: table full, dropping packet",
            "UPS on battery: upsc shows ups.status OB LB",
            "Pod stuck in ImagePullBackOff",
            "GPU reports Xid 79",
        ]
        for query in covered:
            with self.subTest(query=query):
                self.assertTrue(community_knowledge.stack_covers(query))
        for query in uncovered:
            with self.subTest(query=query):
                self.assertFalse(community_knowledge.stack_covers(query))

    def test_render_preserves_attribution_links_and_budget_boundaries(self):
        refs = [(2.0, ["conntrack"], DOCS[0]), (1.0, ["ups"], DOCS[1])]
        full = community_knowledge.render(refs, budget=10_000)

        self.assertTrue(full.startswith("\ncommunity references"))
        reference_lines = [line for line in full.splitlines() if line.startswith("- ")]
        for line, document in zip(reference_lines, DOCS[:2]):
            link = f"https://{community_knowledge.SITE_HOST[document['site']]}/a/{document['answer_id']}"
            self.assertIn(document["title"], line)
            self.assertIn(document["site"], line)
            self.assertIn(f"answer by {document['answer_owner']}", line)
            self.assertIn(document["answer_license"], line)
            self.assertTrue(line.endswith(link))

        first_full = community_knowledge.render(refs[:1], budget=10_000)
        first_only = community_knowledge.render(refs, budget=len(first_full) + 1)
        self.assertEqual(len([line for line in first_only.splitlines() if line.startswith("- ")]), 1)
        self.assertTrue(first_only.endswith("https://serverfault.com/a/101"))
        shortened = community_knowledge.render(refs[:1], budget=len(first_full) - 20)
        self.assertNotEqual(shortened, first_full)
        self.assertIn(DOCS[0]["title"], shortened)
        self.assertTrue(shortened.endswith("https://serverfault.com/a/101"))

    def test_rank_uses_sidecar_order_fails_open_and_honors_score_floor(self):
        query = "conntrack packet ups battery address bind image pull edac memory"
        bm25 = self.index.search(query, k=5)
        self.assertEqual(self.original[3], 0)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), RerankHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        community_knowledge.RERANK_URL = f"http://127.0.0.1:{self.server.server_port}/rerank"

        reranked = community_knowledge.rank(query, k=5)
        self.assertEqual([row[2] for row in reranked], [row[2] for row in reversed(bm25)])

        with socket.socket() as closed_socket:
            closed_socket.bind(("127.0.0.1", 0))
            closed_port = closed_socket.getsockname()[1]
        community_knowledge.RERANK_URL = f"http://127.0.0.1:{closed_port}/rerank"
        community_knowledge.RERANK_TIMEOUT = 0.05
        self.assertEqual(community_knowledge.rank(query, k=5), bm25)

        community_knowledge.RERANK_URL = f"http://127.0.0.1:{self.server.server_port}/rerank"
        community_knowledge.RERANK_MIN_SCORE = 100
        self.assertEqual(community_knowledge.rank(query, k=5), [])

    def test_references_suppresses_stack_covered_queries(self):
        self.assertEqual(community_knowledge.references("502 bad gateway"), "")
        self.assertTrue(community_knowledge.references("nf_conntrack table full"))


if __name__ == "__main__":
    unittest.main()
