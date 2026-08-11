import unittest

from rat_detector_core.bytecode import (
    analyze_bytecode,
    extract_ascii_strings,
    extract_push4_selectors,
    fingerprint_bytecode,
    normalize_bytecode,
    strip_solidity_metadata,
)
from rat_detector_core.models import ValidationError


def with_metadata(core: bytes, metadata: bytes) -> bytes:
    return core + metadata + len(metadata).to_bytes(2, byteorder="big")


class BytecodeScenarioTests(unittest.TestCase):
    def test_valid_metadata_changes_do_not_change_fingerprint(self):
        core = bytes.fromhex("6001600055" * 60)
        first = with_metadata(core, bytes.fromhex("a16469706673420102"))
        second = with_metadata(core, bytes.fromhex("a16469706673420304"))

        self.assertEqual(fingerprint_bytecode(first.hex()), fingerprint_bytecode(second.hex()))
        self.assertEqual(strip_solidity_metadata(first), core)

    def test_malformed_metadata_length_is_not_truncated(self):
        raw = bytes.fromhex("6001600055") + (500).to_bytes(2, byteorder="big")

        self.assertEqual(strip_solidity_metadata(raw), raw)

    def test_non_cbor_tail_is_not_truncated(self):
        core = bytes.fromhex("6001600055")
        fake_metadata = bytes.fromhex("60010203")
        raw = with_metadata(core, fake_metadata)

        self.assertEqual(strip_solidity_metadata(raw), raw)

    def test_truncated_cbor_map_is_not_stripped_or_collapsed(self):
        core = bytes.fromhex("6001600055" * 20)
        first = with_metadata(core, bytes.fromhex("a1"))
        second = with_metadata(core, bytes.fromhex("a2"))

        self.assertEqual(strip_solidity_metadata(first), first)
        self.assertEqual(strip_solidity_metadata(second), second)
        self.assertNotEqual(fingerprint_bytecode(first.hex()), fingerprint_bytecode(second.hex()))

    def test_invalid_cbor_utf8_is_not_stripped_or_collapsed(self):
        core = bytes.fromhex("6001600055" * 20)
        first = with_metadata(core, bytes.fromhex("a161ff00"))
        second = with_metadata(core, bytes.fromhex("a161fe00"))

        self.assertEqual(strip_solidity_metadata(first), first)
        self.assertEqual(strip_solidity_metadata(second), second)
        self.assertNotEqual(fingerprint_bytecode(first.hex()), fingerprint_bytecode(second.hex()))

    def test_push4_selector_extraction_is_stable_and_unique(self):
        value = "0x63a9059cbb600063095ea7b363ffffffff63a9059cbb"

        self.assertEqual(
            extract_push4_selectors(value),
            ("095ea7b3", "a9059cbb"),
        )

    def test_push4_bytes_inside_push_operand_are_not_selectors(self):
        value = "0x6463a9059cbb00"

        self.assertEqual(extract_push4_selectors(value), ())

    def test_empty_bytecode_has_empty_fingerprint(self):
        self.assertEqual(fingerprint_bytecode("0x"), "")

    def test_odd_or_non_hex_bytecode_is_rejected(self):
        with self.assertRaises(ValidationError):
            normalize_bytecode("0x123")
        with self.assertRaises(ValidationError):
            normalize_bytecode("0xzz")

    def test_ascii_strings_are_bounded_evidence(self):
        value = "0x00" + "suspicious message".encode().hex() + "00"

        self.assertEqual(extract_ascii_strings(value), ("suspicious message",))
        self.assertEqual(analyze_bytecode(value).printable_strings, ("suspicious message",))

    def test_oversized_bytecode_is_rejected(self):
        with self.assertRaises(ValidationError):
            normalize_bytecode("00" * 1_000_001)


if __name__ == "__main__":
    unittest.main()
