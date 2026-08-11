"""Validated, dependency-free models for offline launch analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import re
from typing import Any, Mapping


_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_CHAIN_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


class ValidationError(ValueError):
    """Raised when untrusted observation input does not match the schema."""


class DependencyState(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class FunderKind(str, Enum):
    EOA = "eoa"
    CEX = "cex"
    RELAY = "relay"
    BRIDGE = "bridge"
    CONTRACT = "contract"
    UNKNOWN = "unknown"


class ControlEvidence(str, Enum):
    NONE = "none"
    THIRD_PARTY_TRANSFER = "third_party_transfer"
    ORIGINAL_SOURCE = "original_source"


class RiskLevel(str, Enum):
    LOW = "low"
    REVIEW = "review"
    HIGH = "high"
    UNKNOWN = "unknown"


class Conclusion(str, Enum):
    SUSPICIOUS_PATTERNS_PRESENT = "suspicious_patterns_present"
    NO_MATCHING_PATTERNS = "no_matching_patterns"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


def normalize_address(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValidationError(f"{field_name} must be a 20-byte 0x-prefixed EVM address")
    return value.lower()


def _optional_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(f"{field_name} must be a non-negative integer or null")
    return value


def _optional_float(
    value: Any,
    field_name: str,
    *,
    minimum: float,
    maximum: float,
) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be numeric or null")
    number = float(value)
    if not math.isfinite(number):
        raise ValidationError(f"{field_name} must be finite")
    if number < minimum or number > maximum:
        raise ValidationError(f"{field_name} must be between {minimum} and {maximum}")
    return number


def _optional_bool(value: Any, field_name: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise ValidationError(f"{field_name} must be true, false, or null")


def _enum_value(enum_type: type[Enum], value: Any, field_name: str) -> Enum:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string")
    try:
        return enum_type(value.lower())
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise ValidationError(f"{field_name} must be one of: {allowed}") from exc


@dataclass(frozen=True, slots=True)
class DependencyCheck:
    name: str
    state: DependencyState
    detail: str = ""

    @classmethod
    def from_pair(cls, name: Any, state: Any) -> "DependencyCheck":
        if not isinstance(name, str) or not name.strip():
            raise ValidationError("dependency names must be non-empty strings")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
            raise ValidationError(f"invalid dependency name: {name!r}")
        parsed_state = _enum_value(DependencyState, state, f"dependencies.{name}")
        return cls(name=name, state=parsed_state)


@dataclass(frozen=True, slots=True)
class LaunchObservation:
    chain: str
    token_address: str
    creator_address: str
    delivery_id: str
    creator_nonce: int | None
    creator_age_seconds: int | None
    creator_deploys_24h: int | None
    creator_token_share_pct: float | None
    has_social: bool | None
    bytecode_family_matches: bool | None
    funder_kind: FunderKind
    control_evidence: ControlEvidence
    dependencies: tuple[DependencyCheck, ...]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "LaunchObservation":
        if not isinstance(data, Mapping):
            raise ValidationError("observation must be a JSON object")

        chain_value = data.get("chain")
        if not isinstance(chain_value, str):
            raise ValidationError("chain must be a string")
        chain = chain_value.strip().lower()
        if not _CHAIN_RE.fullmatch(chain):
            raise ValidationError("chain must contain only lowercase letters, digits, _ or -")

        delivery_value = data.get("delivery_id")
        if not isinstance(delivery_value, str) or not delivery_value.strip():
            raise ValidationError("delivery_id must be a non-empty string")
        delivery_id = delivery_value.strip()
        if len(delivery_id) > 256:
            raise ValidationError("delivery_id must be at most 256 characters")

        raw_dependencies = data.get("dependencies")
        if not isinstance(raw_dependencies, Mapping):
            raise ValidationError("dependencies must be a JSON object")
        dependencies = tuple(
            sorted(
                (DependencyCheck.from_pair(name, state) for name, state in raw_dependencies.items()),
                key=lambda item: item.name,
            )
        )

        return cls(
            chain=chain,
            token_address=normalize_address(data.get("token_address"), "token_address"),
            creator_address=normalize_address(data.get("creator_address"), "creator_address"),
            delivery_id=delivery_id,
            creator_nonce=_optional_int(data.get("creator_nonce"), "creator_nonce"),
            creator_age_seconds=_optional_int(
                data.get("creator_age_seconds"), "creator_age_seconds"
            ),
            creator_deploys_24h=_optional_int(
                data.get("creator_deploys_24h"), "creator_deploys_24h"
            ),
            creator_token_share_pct=_optional_float(
                data.get("creator_token_share_pct"),
                "creator_token_share_pct",
                minimum=0,
                maximum=100,
            ),
            has_social=_optional_bool(data.get("has_social"), "has_social"),
            bytecode_family_matches=_optional_bool(
                data.get("bytecode_family_matches"), "bytecode_family_matches"
            ),
            funder_kind=_enum_value(
                FunderKind, data.get("funder_kind", "unknown"), "funder_kind"
            ),
            control_evidence=_enum_value(
                ControlEvidence,
                data.get("control_evidence", "none"),
                "control_evidence",
            ),
            dependencies=dependencies,
        )

    def dependency_map(self) -> dict[str, DependencyState]:
        return {item.name: item.state for item in self.dependencies}

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain,
            "token_address": self.token_address,
            "creator_address": self.creator_address,
            "delivery_id": self.delivery_id,
            "creator_nonce": self.creator_nonce,
            "creator_age_seconds": self.creator_age_seconds,
            "creator_deploys_24h": self.creator_deploys_24h,
            "creator_token_share_pct": self.creator_token_share_pct,
            "has_social": self.has_social,
            "bytecode_family_matches": self.bytecode_family_matches,
            "funder_kind": self.funder_kind.value,
            "control_evidence": self.control_evidence.value,
            "dependencies": {
                item.name: item.state.value for item in self.dependencies
            },
        }


@dataclass(frozen=True, slots=True)
class RiskSignal:
    code: str
    points: int
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "points": self.points,
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    schema_version: str
    delivery_id: str
    risk_level: RiskLevel
    conclusion: Conclusion
    score: int
    signals: tuple[RiskSignal, ...]
    unresolved_dependencies: tuple[str, ...]
    policy_version: str
    observation_digest: str
    policy_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "delivery_id": self.delivery_id,
            "risk_level": self.risk_level.value,
            "conclusion": self.conclusion.value,
            "score": self.score,
            "signals": [signal.to_dict() for signal in self.signals],
            "unresolved_dependencies": list(self.unresolved_dependencies),
            "policy_version": self.policy_version,
            "observation_digest": self.observation_digest,
            "policy_digest": self.policy_digest,
        }
