"""Tests for :mod:`baseline`."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from baseline import BaselineManager
from parsers import ParsedPacket
from utils import to_utc_iso

EPOCH = 1_700_000_000.0


def _packet(protocol: str, src_ip: str, dst_ip: str) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(EPOCH),
        timestamp_epoch=EPOCH,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
    )


class BaselineManagerTests(unittest.TestCase):

    def test_first_run_without_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = BaselineManager(
                baseline_path=Path(tmp) / "baseline.json",
                observation_seconds=60,
            )
            self.assertFalse(mgr.has_baseline)
            comparison = mgr.compare()
            self.assertFalse(comparison.has_baseline)

    def test_learning_mode_observe_and_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            mgr = BaselineManager(baseline_path=path, observation_seconds=60, learning_mode=True)
            mgr.observe(_packet("TCP", "10.0.0.1", "10.0.0.2"))
            mgr.observe(_packet("UDP", "10.0.0.1", "10.0.0.3"))
            mgr.observe(_packet("TCP", "10.0.0.2", "10.0.0.1"))
            saved = mgr.save()

            self.assertTrue(saved.is_file())
            data = json.loads(saved.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], 1)
            self.assertEqual(data["packets_observed"], 3)
            self.assertIn("TCP", data["protocol_counts"])
            self.assertIn("10.0.0.1", data["observed_hosts"])

    def test_compare_detects_new_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"

            # Learn about one host.
            learner = BaselineManager(baseline_path=path, observation_seconds=60, learning_mode=True)
            learner.observe(_packet("TCP", "10.0.0.1", "10.0.0.2"))
            learner.save()

            # Re-load and observe a new host.
            detector = BaselineManager(baseline_path=path, observation_seconds=60)
            self.assertTrue(detector.has_baseline)
            detector.observe(_packet("TCP", "10.0.0.1", "10.0.0.2"))
            detector.observe(_packet("TCP", "10.0.0.42", "10.0.0.2"))

            comparison = detector.compare()
            self.assertTrue(comparison.has_baseline)
            self.assertIn("10.0.0.42", comparison.new_hosts)

    def test_compare_detects_protocol_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"

            learner = BaselineManager(baseline_path=path, observation_seconds=60, learning_mode=True)
            for _ in range(20):
                learner.observe(_packet("TCP", "10.0.0.1", "10.0.0.2"))
            learner.save()

            detector = BaselineManager(baseline_path=path, observation_seconds=60)
            for _ in range(10):
                detector.observe(_packet("TCP", "10.0.0.1", "10.0.0.2"))
            for _ in range(10):
                detector.observe(_packet("UDP", "10.0.0.1", "10.0.0.2"))

            comparison = detector.compare()
            self.assertTrue(comparison.has_baseline)
            self.assertIn("UDP", comparison.protocol_drift)

    def test_corrupt_baseline_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text("this is not json", encoding="utf-8")
            mgr = BaselineManager(baseline_path=path, observation_seconds=60)
            self.assertFalse(mgr.has_baseline)
            # The manager must remain usable.
            mgr.observe(_packet("TCP", "10.0.0.1", "10.0.0.2"))
            self.assertEqual(mgr.summary()["packets_observed"], 1)

    def test_unsupported_schema_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps({"version": 999}), encoding="utf-8")
            mgr = BaselineManager(baseline_path=path, observation_seconds=60)
            self.assertFalse(mgr.has_baseline)

    def test_reset_clears_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            mgr = BaselineManager(baseline_path=path, observation_seconds=60, learning_mode=True)
            mgr.observe(_packet("TCP", "10.0.0.1", "10.0.0.2"))
            mgr.reset()
            self.assertEqual(mgr.summary()["packets_observed"], 0)
            self.assertEqual(mgr.summary()["observed_hosts_count"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()