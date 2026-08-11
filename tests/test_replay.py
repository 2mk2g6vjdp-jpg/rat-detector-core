from concurrent.futures import ThreadPoolExecutor
import itertools
import unittest

from rat_detector_core.replay import (
    EvidenceLedger,
    EvidenceRecord,
    EvidenceVerdict,
    IngestOutcome,
)


def record(verdict, source, detail=""):
    return EvidenceRecord(
        delivery_id="bsc:synthetic:1",
        key="provenance",
        verdict=EvidenceVerdict(verdict),
        source=source,
        detail=detail,
    )


class ReplayScenarioTests(unittest.TestCase):
    def test_bad_same_delivery_verdict_survives_every_arrival_order(self):
        rows = [
            record("good", "initial"),
            record("unknown", "timeout"),
            record("bad", "original-source"),
        ]

        snapshots = set()
        for permutation in itertools.permutations(rows):
            ledger = EvidenceLedger()
            ledger.ingest_many(permutation)
            snapshots.add(str(ledger.snapshot()))
            self.assertEqual(
                ledger.get("bsc:synthetic:1", "provenance").verdict,
                EvidenceVerdict.BAD,
            )
        self.assertEqual(len(snapshots), 1)

    def test_duplicate_is_idempotent(self):
        ledger = EvidenceLedger()
        item = record("unknown", "provider")

        self.assertEqual(ledger.ingest(item), IngestOutcome.INSERTED)
        self.assertEqual(ledger.ingest(item), IngestOutcome.DUPLICATE)
        self.assertEqual(len(ledger.snapshot()), 1)

    def test_snapshot_restart_preserves_precedence(self):
        ledger = EvidenceLedger()
        ledger.ingest(record("bad", "original-source"))
        restarted = EvidenceLedger.from_snapshot(ledger.snapshot())
        restarted.ingest(record("unknown", "late-timeout"))

        self.assertEqual(restarted.snapshot(), ledger.snapshot())

    def test_equal_severity_conflict_has_stable_tie_break(self):
        first = record("bad", "z-source", "z-detail")
        second = record("bad", "a-source", "a-detail")

        left = EvidenceLedger()
        left.ingest_many([first, second])
        right = EvidenceLedger()
        right.ingest_many([second, first])

        self.assertEqual(left.snapshot(), right.snapshot())
        self.assertEqual(left.snapshot()[0]["source"], "a-source")

    def test_concurrent_ingestion_is_race_safe(self):
        ledger = EvidenceLedger()
        rows = [
            record("good", f"good-{index:03d}") for index in range(25)
        ] + [
            record("unknown", f"unknown-{index:03d}") for index in range(25)
        ] + [
            record("bad", f"bad-{index:03d}") for index in range(25)
        ]

        with ThreadPoolExecutor(max_workers=12) as executor:
            list(executor.map(ledger.ingest, rows))

        winner = ledger.get("bsc:synthetic:1", "provenance")
        self.assertEqual(winner.verdict, EvidenceVerdict.BAD)
        self.assertEqual(winner.source, "bad-000")

    def test_different_delivery_does_not_inherit_bad_verdict(self):
        ledger = EvidenceLedger()
        ledger.ingest(record("bad", "original-source"))
        other = EvidenceRecord(
            delivery_id="bsc:synthetic:2",
            key="provenance",
            verdict=EvidenceVerdict.UNKNOWN,
            source="timeout",
        )
        ledger.ingest(other)

        self.assertEqual(
            ledger.get("bsc:synthetic:2", "provenance").verdict,
            EvidenceVerdict.UNKNOWN,
        )


if __name__ == "__main__":
    unittest.main()

