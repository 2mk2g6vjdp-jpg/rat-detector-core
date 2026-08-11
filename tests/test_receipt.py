import unittest

from rat_detector_core.models import DependencyState, ValidationError
from rat_detector_core.receipt import TRANSFER_TOPIC, ZERO_ADDRESS, analyze_receipt


TOKEN = "0x1111111111111111111111111111111111111111"
ALICE = "0x2222222222222222222222222222222222222222"
BOB = "0x3333333333333333333333333333333333333333"


def topic(address):
    return "0x" + "0" * 24 + address[2:]


def transfer_log(source, destination, amount, log_index=0):
    return {
        "address": TOKEN,
        "logIndex": log_index,
        "topics": [TRANSFER_TOPIC, topic(source), topic(destination)],
        "data": "0x" + amount.to_bytes(32, byteorder="big").hex(),
    }


class ReceiptScenarioTests(unittest.TestCase):
    def test_mint_and_transfer_are_neutral_evidence(self):
        receipt = {
            "logs": [
                transfer_log(ZERO_ADDRESS, ALICE, 1_000_000, 2),
                transfer_log(ALICE, BOB, 1_000, 3),
            ]
        }

        result = analyze_receipt(receipt)
        self.assertEqual(result.dependency_state, DependencyState.COMPLETE)
        self.assertEqual(result.transfer_count, 2)
        self.assertEqual(result.mint_count, 1)
        self.assertEqual(result.transfers[0].amount, 1_000_000)

    def test_unrelated_logs_are_ignored(self):
        receipt = {
            "logs": [
                {
                    "address": TOKEN,
                    "topics": ["0x" + "f" * 64],
                    "data": "0x",
                }
            ]
        }

        result = analyze_receipt(receipt)
        self.assertEqual(result.transfer_count, 0)
        self.assertEqual(result.malformed_log_count, 0)

    def test_malformed_transfer_is_partial_not_silently_complete(self):
        broken = transfer_log(ALICE, BOB, 1)
        broken["data"] = "0x01"

        result = analyze_receipt({"logs": [broken]})
        self.assertEqual(result.dependency_state, DependencyState.PARTIAL)
        self.assertEqual(result.transfer_count, 0)
        self.assertEqual(result.malformed_log_count, 1)

    def test_noncanonical_address_padding_is_malformed(self):
        broken = transfer_log(ALICE, BOB, 1)
        broken["topics"][1] = "0x" + "f" * 24 + ALICE[2:]

        result = analyze_receipt({"logs": [broken]})
        self.assertEqual(result.dependency_state, DependencyState.PARTIAL)
        self.assertEqual(result.transfer_count, 0)
        self.assertEqual(result.malformed_log_count, 1)

    def test_non_object_log_is_counted_as_malformed(self):
        result = analyze_receipt({"logs": [None]})

        self.assertEqual(result.dependency_state, DependencyState.PARTIAL)
        self.assertEqual(result.malformed_log_count, 1)

    def test_receipt_without_logs_array_is_rejected(self):
        with self.assertRaises(ValidationError):
            analyze_receipt({"logs": None})


if __name__ == "__main__":
    unittest.main()
