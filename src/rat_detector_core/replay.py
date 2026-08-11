"""Thread-safe, deterministic evidence replay with immutable delivery keys."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Any, Iterable, Mapping

from .models import ValidationError


class EvidenceVerdict(str, Enum):
    GOOD = "good"
    UNKNOWN = "unknown"
    BAD = "bad"


_VERDICT_RANK = {
    EvidenceVerdict.GOOD: 1,
    EvidenceVerdict.UNKNOWN: 2,
    EvidenceVerdict.BAD: 3,
}


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    delivery_id: str
    key: str
    verdict: EvidenceVerdict
    source: str
    detail: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "EvidenceRecord":
        if not isinstance(data, Mapping):
            raise ValidationError("evidence record must be a JSON object")

        values: dict[str, str] = {}
        for name in ("delivery_id", "key", "source"):
            value = data.get(name)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{name} must be a non-empty string")
            values[name] = value.strip()

        detail = data.get("detail", "")
        if not isinstance(detail, str):
            raise ValidationError("detail must be a string")

        try:
            verdict = EvidenceVerdict(str(data.get("verdict", "unknown")).lower())
        except ValueError as exc:
            raise ValidationError("verdict must be good, unknown, or bad") from exc

        return cls(
            delivery_id=values["delivery_id"],
            key=values["key"],
            verdict=verdict,
            source=values["source"],
            detail=detail,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "delivery_id": self.delivery_id,
            "key": self.key,
            "verdict": self.verdict.value,
            "source": self.source,
            "detail": self.detail,
        }


class IngestOutcome(str, Enum):
    INSERTED = "inserted"
    REPLACED = "replaced"
    RETAINED = "retained"
    DUPLICATE = "duplicate"


class EvidenceLedger:
    """In-memory ledger safe for concurrent ingestion and deterministic replay.

    Records are keyed by immutable ``(delivery_id, key)``. A bad verdict has
    precedence over unknown and good, so a later incomplete result cannot hide
    an exact same-delivery bad verdict. Equal-severity conflicts use a stable
    lexical tie-break instead of arrival order.
    """

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], EvidenceRecord] = {}
        self._lock = RLock()

    @staticmethod
    def _stable_key(record: EvidenceRecord) -> tuple[str, str]:
        return (record.source, record.detail)

    def ingest(self, record: EvidenceRecord) -> IngestOutcome:
        key = (record.delivery_id, record.key)
        with self._lock:
            current = self._records.get(key)
            if current is None:
                self._records[key] = record
                return IngestOutcome.INSERTED
            if current == record:
                return IngestOutcome.DUPLICATE

            current_rank = _VERDICT_RANK[current.verdict]
            candidate_rank = _VERDICT_RANK[record.verdict]
            if candidate_rank > current_rank:
                self._records[key] = record
                return IngestOutcome.REPLACED
            if candidate_rank < current_rank:
                return IngestOutcome.RETAINED

            if self._stable_key(record) < self._stable_key(current):
                self._records[key] = record
                return IngestOutcome.REPLACED
            return IngestOutcome.RETAINED

    def ingest_many(self, records: Iterable[EvidenceRecord]) -> dict[str, int]:
        counts = {outcome.value: 0 for outcome in IngestOutcome}
        for record in records:
            counts[self.ingest(record).value] += 1
        return counts

    def get(self, delivery_id: str, key: str) -> EvidenceRecord | None:
        with self._lock:
            return self._records.get((delivery_id, key))

    def snapshot(self) -> list[dict[str, str]]:
        with self._lock:
            records = sorted(
                self._records.values(),
                key=lambda item: (item.delivery_id, item.key),
            )
            return [record.to_dict() for record in records]

    @classmethod
    def from_snapshot(cls, rows: Iterable[Mapping[str, Any]]) -> "EvidenceLedger":
        ledger = cls()
        ledger.ingest_many(EvidenceRecord.from_mapping(row) for row in rows)
        return ledger


def replay_records(rows: Iterable[Mapping[str, Any]]) -> EvidenceLedger:
    ledger = EvidenceLedger()
    ledger.ingest_many(EvidenceRecord.from_mapping(row) for row in rows)
    return ledger

