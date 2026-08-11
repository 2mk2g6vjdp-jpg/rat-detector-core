"""Conservative controller-evidence classification for funding paths."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Iterable, Mapping

from .models import ControlEvidence, FunderKind, ValidationError, normalize_address


_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


class ControlStatus(str, Enum):
    PROVEN = "proven"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FundingHop:
    source: str
    destination: str
    transaction_hash: str
    channel: FunderKind
    evidence: ControlEvidence = ControlEvidence.NONE

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "FundingHop":
        if not isinstance(data, Mapping):
            raise ValidationError("each funding hop must be a JSON object")

        tx_hash = data.get("transaction_hash")
        if not isinstance(tx_hash, str) or not _TX_HASH_RE.fullmatch(tx_hash):
            raise ValidationError("transaction_hash must be a 32-byte 0x-prefixed hash")

        try:
            channel = FunderKind(str(data.get("channel", "unknown")).lower())
        except ValueError as exc:
            raise ValidationError("invalid funding channel") from exc
        try:
            evidence = ControlEvidence(str(data.get("evidence", "none")).lower())
        except ValueError as exc:
            raise ValidationError("invalid control evidence") from exc

        return cls(
            source=normalize_address(data.get("source"), "source"),
            destination=normalize_address(data.get("destination"), "destination"),
            transaction_hash=tx_hash.lower(),
            channel=channel,
            evidence=evidence,
        )


@dataclass(frozen=True, slots=True)
class ControlAssessment:
    target_address: str
    status: ControlStatus
    reason: str
    supporting_transactions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_address": self.target_address,
            "status": self.status.value,
            "reason": self.reason,
            "supporting_transactions": list(self.supporting_transactions),
        }


def assess_shared_control(
    target_address: str,
    hops: Iterable[FundingHop],
) -> ControlAssessment:
    """Require original-source evidence delivered directly to ``target_address``.

    A CEX hot wallet, bridge, relay, solver, or unrelated third-party transfer is
    infrastructure evidence, not controller evidence. Evidence attached to an
    upstream hop is not propagated automatically to downstream recipients.
    """

    target = normalize_address(target_address, "target_address")
    inbound = tuple(hop for hop in hops if hop.destination == target)

    proven = tuple(
        sorted(
            hop.transaction_hash
            for hop in inbound
            if hop.evidence is ControlEvidence.ORIGINAL_SOURCE
        )
    )
    if proven:
        return ControlAssessment(
            target_address=target,
            status=ControlStatus.PROVEN,
            reason="direct original-source evidence links the target to the controller",
            supporting_transactions=proven,
        )

    if any(
        hop.channel in {FunderKind.CEX, FunderKind.RELAY, FunderKind.BRIDGE}
        for hop in inbound
    ):
        reason = "infrastructure funding is present but does not prove shared control"
    elif inbound:
        reason = "funding exists without original-source controller evidence"
    else:
        reason = "no direct funding evidence was supplied for the target"

    return ControlAssessment(
        target_address=target,
        status=ControlStatus.UNKNOWN,
        reason=reason,
    )

