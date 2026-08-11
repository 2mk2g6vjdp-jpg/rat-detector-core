"""Neutral ERC-20 transfer evidence extraction from supplied receipt JSON."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

from .models import DependencyState, ValidationError, normalize_address


TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ZERO_ADDRESS = "0x" + "0" * 40
_TOPIC_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_WORD_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


@dataclass(frozen=True, slots=True)
class TransferEvidence:
    log_index: int
    token_address: str
    source: str
    destination: str
    amount: int
    is_mint: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_index": self.log_index,
            "token_address": self.token_address,
            "source": self.source,
            "destination": self.destination,
            "amount": str(self.amount),
            "is_mint": self.is_mint,
        }


@dataclass(frozen=True, slots=True)
class ReceiptReport:
    dependency_state: DependencyState
    transfer_count: int
    mint_count: int
    malformed_log_count: int
    token_addresses: tuple[str, ...]
    recipient_addresses: tuple[str, ...]
    transfers: tuple[TransferEvidence, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_state": self.dependency_state.value,
            "transfer_count": self.transfer_count,
            "mint_count": self.mint_count,
            "malformed_log_count": self.malformed_log_count,
            "token_addresses": list(self.token_addresses),
            "recipient_addresses": list(self.recipient_addresses),
            "transfers": [item.to_dict() for item in self.transfers],
        }


def _topic_address(value: Any) -> str:
    if not isinstance(value, str) or not _TOPIC_RE.fullmatch(value):
        raise ValidationError("indexed address topic must be a 32-byte hex word")
    if value[2:26] != "0" * 24:
        raise ValidationError("indexed address topic must use canonical zero padding")
    return normalize_address("0x" + value[-40:], "indexed address")


def analyze_receipt(receipt: Mapping[str, Any]) -> ReceiptReport:
    """Extract standard ERC-20 Transfer logs without assigning a risk verdict."""

    if not isinstance(receipt, Mapping):
        raise ValidationError("receipt must be a JSON object")
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise ValidationError("receipt.logs must be an array")

    transfers: list[TransferEvidence] = []
    malformed = 0

    for fallback_index, raw_log in enumerate(logs):
        if not isinstance(raw_log, Mapping):
            malformed += 1
            continue
        topics = raw_log.get("topics")
        if not isinstance(topics, list) or not topics:
            continue
        first_topic = topics[0]
        if not isinstance(first_topic, str) or first_topic.lower() != TRANSFER_TOPIC:
            continue

        try:
            if len(topics) != 3:
                raise ValidationError("ERC-20 Transfer must have exactly three topics")
            token_address = normalize_address(raw_log.get("address"), "log.address")
            source = _topic_address(topics[1])
            destination = _topic_address(topics[2])
            data = raw_log.get("data")
            if not isinstance(data, str) or not _WORD_RE.fullmatch(data):
                raise ValidationError("ERC-20 Transfer data must be a 32-byte hex word")
            log_index = raw_log.get("logIndex", fallback_index)
            if isinstance(log_index, str):
                log_index = int(log_index, 16) if log_index.startswith("0x") else int(log_index)
            if isinstance(log_index, bool) or not isinstance(log_index, int) or log_index < 0:
                raise ValidationError("logIndex must be a non-negative integer")
            transfers.append(
                TransferEvidence(
                    log_index=log_index,
                    token_address=token_address,
                    source=source,
                    destination=destination,
                    amount=int(data, 16),
                    is_mint=source == ZERO_ADDRESS,
                )
            )
        except (ValidationError, ValueError, OverflowError):
            malformed += 1

    ordered = tuple(sorted(transfers, key=lambda item: item.log_index))
    return ReceiptReport(
        dependency_state=(
            DependencyState.COMPLETE if malformed == 0 else DependencyState.PARTIAL
        ),
        transfer_count=len(ordered),
        mint_count=sum(item.is_mint for item in ordered),
        malformed_log_count=malformed,
        token_addresses=tuple(sorted({item.token_address for item in ordered})),
        recipient_addresses=tuple(sorted({item.destination for item in ordered})),
        transfers=ordered,
    )
