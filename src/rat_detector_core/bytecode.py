"""Pure bytecode helpers with no RPC, filesystem, or execution dependency."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .models import ValidationError


MAX_BYTECODE_BYTES = 1_000_000


def normalize_bytecode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValidationError("bytecode must be a hex string")
    text = value[2:] if value.startswith(("0x", "0X")) else value
    if not text:
        return b""
    if len(text) % 2:
        raise ValidationError("bytecode must contain an even number of hex characters")
    if len(text) // 2 > MAX_BYTECODE_BYTES:
        raise ValidationError(f"bytecode exceeds the {MAX_BYTECODE_BYTES}-byte analysis limit")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValidationError("bytecode contains non-hex characters") from exc


def strip_solidity_metadata(bytecode: bytes) -> bytes:
    """Strip a plausible CBOR metadata trailer using Solidity's length suffix.

    The last two bytes encode the metadata length. The metadata is removed only
    when the length is in bounds and the first metadata byte is a CBOR map, so
    malformed data is left unchanged rather than truncated heuristically.
    """

    if len(bytecode) < 3:
        return bytecode
    metadata_length = int.from_bytes(bytecode[-2:], byteorder="big")
    if metadata_length <= 0 or metadata_length + 2 > len(bytecode):
        return bytecode
    start = len(bytecode) - metadata_length - 2
    metadata = bytecode[start:-2]
    if not _is_complete_cbor_map(metadata):
        return bytecode
    return bytecode[:start]


def _read_cbor_argument(data: bytes, index: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, index
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths.get(additional)
    if width is None or index + width > len(data):
        raise ValueError("invalid or truncated CBOR argument")
    value = int.from_bytes(data[index : index + width], byteorder="big")
    return value, index + width


def _parse_cbor_item(data: bytes, index: int, depth: int = 0) -> tuple[int, int]:
    if depth > 16 or index >= len(data):
        raise ValueError("invalid CBOR nesting or truncation")

    initial = data[index]
    index += 1
    major = initial >> 5
    additional = initial & 0x1F
    argument, index = _read_cbor_argument(data, index, additional)

    if major in {0, 1, 7}:
        return index, major
    if major in {2, 3}:
        end = index + argument
        if end > len(data):
            raise ValueError("truncated CBOR string")
        if major == 3:
            try:
                data[index:end].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ValueError("invalid CBOR UTF-8 text string") from exc
        return end, major
    if major == 4:
        if argument > 4_096:
            raise ValueError("CBOR array is too large")
        for _ in range(argument):
            index, _ = _parse_cbor_item(data, index, depth + 1)
        return index, major
    if major == 5:
        if argument > 4_096:
            raise ValueError("CBOR map is too large")
        for _ in range(argument * 2):
            index, _ = _parse_cbor_item(data, index, depth + 1)
        return index, major
    if major == 6:
        index, _ = _parse_cbor_item(data, index, depth + 1)
        return index, major
    raise ValueError("unsupported CBOR major type")


def _is_complete_cbor_map(data: bytes) -> bool:
    try:
        end, major = _parse_cbor_item(data, 0)
    except ValueError:
        return False
    return major == 5 and end == len(data)


def fingerprint_bytecode(value: str) -> str:
    """Return the full SHA-256 hash of normalized, metadata-stripped bytecode."""

    normalized = normalize_bytecode(value)
    if not normalized:
        return ""
    return hashlib.sha256(strip_solidity_metadata(normalized)).hexdigest()


def extract_push4_selectors(value: str) -> tuple[str, ...]:
    """Extract stable PUSH4 selector candidates from EVM bytecode."""

    bytecode = normalize_bytecode(value)
    selectors: set[str] = set()
    index = 0
    while index < len(bytecode):
        opcode = bytecode[index]
        index += 1
        if not 0x60 <= opcode <= 0x7F:
            continue
        operand_length = opcode - 0x5F
        end = index + operand_length
        if end > len(bytecode):
            break
        if opcode == 0x63:
            selector = bytecode[index:end].hex()
            if selector != "ffffffff":
                selectors.add(selector)
        index = end
    return tuple(sorted(selectors))


def extract_ascii_strings(
    value: str,
    *,
    minimum_length: int = 4,
    maximum_items: int = 100,
) -> tuple[str, ...]:
    """Extract bounded printable ASCII runs as neutral analysis evidence."""

    if minimum_length < 1 or maximum_items < 1:
        raise ValidationError("string extraction bounds must be positive")
    bytecode = normalize_bytecode(value)
    found: list[str] = []
    current = bytearray()

    def flush() -> None:
        if len(current) >= minimum_length and len(found) < maximum_items:
            found.append(current.decode("ascii"))
        current.clear()

    for item in bytecode:
        if 32 <= item <= 126:
            current.append(item)
            if len(current) >= 256:
                flush()
        else:
            flush()
        if len(found) >= maximum_items:
            break
    flush()
    return tuple(found[:maximum_items])


@dataclass(frozen=True, slots=True)
class BytecodeReport:
    byte_length: int
    analysis_byte_length: int
    metadata_stripped: bool
    fingerprint: str
    selectors: tuple[str, ...]
    printable_strings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "byte_length": self.byte_length,
            "analysis_byte_length": self.analysis_byte_length,
            "metadata_stripped": self.metadata_stripped,
            "fingerprint": self.fingerprint,
            "selectors": list(self.selectors),
            "printable_strings": list(self.printable_strings),
        }


def analyze_bytecode(value: str) -> BytecodeReport:
    normalized = normalize_bytecode(value)
    stripped = strip_solidity_metadata(normalized)
    fingerprint = hashlib.sha256(stripped).hexdigest() if stripped else ""
    return BytecodeReport(
        byte_length=len(normalized),
        analysis_byte_length=len(stripped),
        metadata_stripped=len(stripped) != len(normalized),
        fingerprint=fingerprint,
        selectors=extract_push4_selectors(value),
        printable_strings=extract_ascii_strings(value),
    )
