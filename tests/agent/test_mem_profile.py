import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "mem-profile.py"


class MemoryProfileReportTest(unittest.TestCase):
    def run_report(self, rows, *args):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "memory.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(path), *args],
                check=True, capture_output=True, text=True,
            ).stdout

    def test_report_shows_minimum_median_peak_headroom_and_container_delta(self):
        # Given three samples whose extrema and median differ.
        rows = [
            {"ts": 1, "MemTotal": 128, "MemAvailable": 12, "MemFree": 4,
             "Cached": 20, "Shmem": 1, "containers": {"vllm-edge": 20},
             "services": {"watchdog": 0.1}},
            {"ts": 2, "MemTotal": 128, "MemAvailable": 8, "MemFree": 2,
             "Cached": 24, "Shmem": 2, "containers": {"vllm-edge": 24},
             "services": {"watchdog": 0.2}},
            {"ts": 3, "MemTotal": 128, "MemAvailable": 10, "MemFree": 3,
             "Cached": 22, "Shmem": 1.5, "containers": {"vllm-edge": 22},
             "services": {"watchdog": 0.15}},
        ]

        # When the CLI summarises the JSONL.
        output = self.run_report(rows)

        # Then the table and drill-growth calculation use all three samples.
        self.assertIn("| MemAvailable | 8.000 | 10.000 | 12.000 |", output)
        self.assertIn("| containers.vllm-edge | 20.000 | 22.000 | 24.000 |", output)
        self.assertIn("Headroom (minimum MemAvailable): **8.000 GiB**", output)
        self.assertIn("| vllm-edge | 20.000 | 24.000 | 4.000 |", output)

    def test_since_and_until_cut_the_report_window(self):
        # Given samples both inside and outside an inclusive drill window.
        rows = [
            {"ts": 1, "MemAvailable": 50, "containers": {"vllm-edge": 2}},
            {"ts": 2, "MemAvailable": 8, "containers": {"vllm-edge": 24}},
            {"ts": 3, "MemAvailable": 10, "containers": {"vllm-edge": 22}},
            {"ts": 4, "MemAvailable": 1, "containers": {"vllm-edge": 40}},
        ]

        # When only epochs two through three are requested.
        output = self.run_report(rows, "--since", "2", "--until", "3")

        # Then out-of-window low headroom and container peaks are excluded.
        self.assertIn("| MemAvailable | 8.000 | 9.000 | 10.000 |", output)
        self.assertIn("| containers.vllm-edge | 22.000 | 23.000 | 24.000 |", output)
        self.assertIn("| vllm-edge | 24.000 | 24.000 | 0.000 |", output)


if __name__ == "__main__":
    unittest.main()
