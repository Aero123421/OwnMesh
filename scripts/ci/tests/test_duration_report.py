"""Unit tests for the CI duration reporter (Issue #230 Phase 0).

Guards the fail-closed SLO contract:
- p95 uses nearest-rank (ceil(p/100*N)-1), not truncation;
- a missing Rust p50 metric is a failure, never a silent pass.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import duration_report as report


def good_current(**overrides):
    metrics = {
        "docs_only_p95": 1.0,
        "rust_p95": 9.0,
        "rust_p50": 5.0,
        "tag_to_build_p95": 1.0,
        "runner_minutes_current": 40.0,
    }
    metrics.update(overrides)
    return metrics


BASELINE = {"runner_minutes_baseline": 100.0}


class PercentileTests(unittest.TestCase):
    def test_p95_nearest_rank_n20(self):
        vals = [float(i) for i in range(1, 21)]
        # ceil(0.95*20)-1 = 18 -> 19th value.
        self.assertEqual(report.percentile(vals, 95), 19.0)

    def test_p95_nearest_rank_n100(self):
        vals = [float(i) for i in range(1, 101)]
        # ceil(0.95*100)-1 = 94 -> 95th value (not the max).
        self.assertEqual(report.percentile(vals, 95), 95.0)

    def test_p50_nearest_rank(self):
        vals = [float(i) for i in range(1, 21)]
        # ceil(0.50*20)-1 = 9 -> 10th value.
        self.assertEqual(report.percentile(vals, 50), 10.0)

    def test_single_value(self):
        self.assertEqual(report.percentile([3.5], 95), 3.5)

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            report.percentile([], 95)


class SloFailClosedTests(unittest.TestCase):
    def test_missing_rust_p50_is_failure(self):
        current = good_current()
        del current["rust_p50"]
        failures, _ = report.evaluate_slo(current, BASELINE)
        self.assertTrue(any("rust p50" in f.lower() for f in failures),
                        f"Rust p50 absence must fail-closed: {failures}")

    def test_present_rust_p50_passes(self):
        failures, passes = report.evaluate_slo(good_current(), BASELINE)
        self.assertEqual(failures, [])
        self.assertTrue(any("rust p50" in p.lower() for p in passes))

    def test_rust_p50_over_max_fails(self):
        failures, _ = report.evaluate_slo(good_current(rust_p50=6.5), BASELINE)
        self.assertTrue(any("rust p50" in f.lower() for f in failures))


if __name__ == "__main__":
    unittest.main()
