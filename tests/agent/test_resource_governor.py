import pathlib
import tempfile
import unittest

from scripts.resource_governor import plan, read_mem_available_gib


class ResourceGovernorTest(unittest.TestCase):
    def test_modes_at_boundaries(self):
        # Given memory values at each mode boundary.
        cases = ((20, "full", 2, True, "v2"),
                 (8, "reduced", 1, True, "v1"),
                 (7.99, "minimal", 0, False, "v1"))

        # When each value is planned, then its complete resource policy applies.
        for memory, mode, specialists, reranker, corpus in cases:
            with self.subTest(memory=memory):
                result = plan(memory, env={})
                self.assertEqual(
                    (result["mode"], result["max_parallel_specialists"],
                     result["reranker_allowed"], result["community_corpus"]),
                    (mode, specialists, reranker, corpus),
                )

    def test_second_instance_subtracts_memory(self):
        # Given 32 GiB, when a second instance runs, then effective memory is 7 GiB.
        result = plan(32, running_llm_instances=2, env={})
        self.assertEqual(result["mode"], "minimal")

    def test_environment_overrides_thresholds(self):
        # Given custom thresholds, when planning, then all overrides are honored.
        env = {"GOV_FULL_GB": "30", "GOV_REDUCED_GB": "10",
               "GOV_EXTRA_INSTANCE_GB": "5"}
        result = plan(34, running_llm_instances=2, env=env)
        self.assertEqual(result["mode"], "reduced")

    def test_unknown_memory_does_not_restrict(self):
        # Given unknown memory, when planning, then optional resources stay enabled.
        result = plan(None, env={})
        self.assertEqual(result, {
            "mode": "full", "max_parallel_specialists": 2,
            "reranker_allowed": True, "community_corpus": "v2",
            "reason": "memory unknown: not restricting",
        })

    def test_reads_mem_available_from_proc_format(self):
        # Given synthetic proc text, when read, then kB is converted to GiB.
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "meminfo"
            path.write_text("MemTotal: 131072000 kB\nMemAvailable: 12582912 kB\n")
            self.assertEqual(read_mem_available_gib(path), 12.0)


if __name__ == "__main__":
    unittest.main()
