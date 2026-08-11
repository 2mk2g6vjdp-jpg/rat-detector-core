import unittest

from rat_detector_core.models import ValidationError
from rat_detector_core.provenance import (
    ControlStatus,
    FundingHop,
    assess_shared_control,
)


A = "0x1111111111111111111111111111111111111111"
B = "0x2222222222222222222222222222222222222222"
C = "0x3333333333333333333333333333333333333333"
TX1 = "0x" + "a" * 64
TX2 = "0x" + "b" * 64


def hop(source=A, destination=B, tx=TX1, channel="eoa", evidence="none"):
    return FundingHop.from_mapping(
        {
            "source": source,
            "destination": destination,
            "transaction_hash": tx,
            "channel": channel,
            "evidence": evidence,
        }
    )


class ProvenanceScenarioTests(unittest.TestCase):
    def test_direct_original_source_evidence_is_proven(self):
        result = assess_shared_control(B, [hop(evidence="original_source")])

        self.assertEqual(result.status, ControlStatus.PROVEN)
        self.assertEqual(result.supporting_transactions, (TX1,))

    def test_relay_transfer_remains_unknown(self):
        result = assess_shared_control(
            B,
            [hop(channel="relay", evidence="third_party_transfer")],
        )

        self.assertEqual(result.status, ControlStatus.UNKNOWN)
        self.assertIn("does not prove", result.reason)

    def test_cex_hot_wallet_remains_unknown(self):
        result = assess_shared_control(B, [hop(channel="cex")])

        self.assertEqual(result.status, ControlStatus.UNKNOWN)

    def test_original_source_evidence_does_not_propagate_downstream(self):
        upstream = hop(destination=B, evidence="original_source")
        downstream = hop(
            source=B,
            destination=C,
            tx=TX2,
            channel="eoa",
            evidence="third_party_transfer",
        )

        result = assess_shared_control(C, [upstream, downstream])
        self.assertEqual(result.status, ControlStatus.UNKNOWN)

    def test_unrelated_hop_is_not_evidence(self):
        result = assess_shared_control(C, [hop(destination=B)])

        self.assertEqual(result.status, ControlStatus.UNKNOWN)
        self.assertIn("no direct", result.reason)

    def test_malformed_transaction_hash_is_rejected(self):
        with self.assertRaises(ValidationError):
            hop(tx="0xdeadbeef")


if __name__ == "__main__":
    unittest.main()

