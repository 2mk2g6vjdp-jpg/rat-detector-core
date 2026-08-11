"""Deterministic, explainable policy engine for launch observations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re

from .models import (
    Conclusion,
    ControlEvidence,
    DependencyState,
    FunderKind,
    LaunchObservation,
    RiskAssessment,
    RiskLevel,
    RiskSignal,
)


@dataclass(frozen=True, slots=True)
class RiskPolicy:
    """Auditable thresholds; no network or execution behavior is attached."""

    policy_version: str = "1.0.0"
    fresh_creator_nonce_max: int = 1
    young_creator_age_max_seconds: int = 3_600
    rapid_deployer_min_24h: int = 5
    concentrated_creator_share_min_pct: float = 20.0
    review_score_min: int = 25
    high_score_min: int = 60
    required_dependencies: tuple[str, ...] = (
        "creator_profile",
        "holdings",
        "provenance",
    )

    def __post_init__(self) -> None:
        integer_fields = {
            "fresh_creator_nonce_max": self.fresh_creator_nonce_max,
            "young_creator_age_max_seconds": self.young_creator_age_max_seconds,
            "rapid_deployer_min_24h": self.rapid_deployer_min_24h,
            "review_score_min": self.review_score_min,
            "high_score_min": self.high_score_min,
        }
        for name, value in integer_fields.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

        share = self.concentrated_creator_share_min_pct
        if (
            isinstance(share, bool)
            or not isinstance(share, (int, float))
            or not math.isfinite(float(share))
            or not 0 <= float(share) <= 100
        ):
            raise ValueError(
                "concentrated_creator_share_min_pct must be finite and between 0 and 100"
            )
        if not 0 <= self.review_score_min <= self.high_score_min <= 100:
            raise ValueError("score thresholds must satisfy 0 <= review <= high <= 100")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("policy_version must be a non-empty string")
        if not isinstance(self.required_dependencies, tuple) or not self.required_dependencies:
            raise ValueError("required_dependencies must be a non-empty tuple")
        for name in self.required_dependencies:
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
                raise ValueError(f"invalid required dependency name: {name!r}")
        if len(set(self.required_dependencies)) != len(self.required_dependencies):
            raise ValueError("required_dependencies must not contain duplicates")


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _unresolved_dependencies(
    observation: LaunchObservation,
    policy: RiskPolicy,
) -> tuple[str, ...]:
    states = observation.dependency_map()
    unresolved = [
        name
        for name in policy.required_dependencies
        if states.get(name) is not DependencyState.COMPLETE
    ]

    if observation.creator_nonce is None or observation.creator_age_seconds is None:
        unresolved.append("creator_profile.fields")
    if observation.creator_deploys_24h is None:
        unresolved.append("creator_profile.deploy_history")
    if observation.creator_token_share_pct is None:
        unresolved.append("holdings.creator_share")

    return tuple(sorted(set(unresolved)))


def assess_launch(
    observation: LaunchObservation,
    policy: RiskPolicy | None = None,
) -> RiskAssessment:
    """Assess one observation without side effects.

    Incomplete mandatory dependencies produce ``unknown`` rather than being
    silently treated as low risk. Infrastructure funders such as CEX hot
    wallets, bridges and relays never prove shared control by themselves.
    """

    policy = policy or RiskPolicy()
    signals: list[RiskSignal] = []
    dependency_states = observation.dependency_map()
    creator_profile_complete = (
        dependency_states.get("creator_profile") is DependencyState.COMPLETE
    )
    holdings_complete = dependency_states.get("holdings") is DependencyState.COMPLETE
    provenance_complete = (
        dependency_states.get("provenance") is DependencyState.COMPLETE
    )

    if (
        creator_profile_complete
        and
        observation.creator_nonce is not None
        and observation.creator_nonce <= policy.fresh_creator_nonce_max
    ):
        signals.append(
            RiskSignal(
                "fresh_creator_nonce",
                15,
                f"creator nonce is {observation.creator_nonce}",
            )
        )

    if (
        creator_profile_complete
        and
        observation.creator_age_seconds is not None
        and observation.creator_age_seconds <= policy.young_creator_age_max_seconds
    ):
        signals.append(
            RiskSignal(
                "young_creator",
                15,
                f"creator age is {observation.creator_age_seconds} seconds",
            )
        )

    if (
        creator_profile_complete
        and
        observation.creator_deploys_24h is not None
        and observation.creator_deploys_24h >= policy.rapid_deployer_min_24h
    ):
        signals.append(
            RiskSignal(
                "rapid_deployer",
                25,
                f"creator deployed {observation.creator_deploys_24h} contracts in 24h",
            )
        )

    if (
        holdings_complete
        and
        observation.creator_token_share_pct is not None
        and observation.creator_token_share_pct
        >= policy.concentrated_creator_share_min_pct
    ):
        signals.append(
            RiskSignal(
                "creator_concentration",
                30,
                f"creator-associated share is {observation.creator_token_share_pct:.2f}%",
            )
        )

    if observation.has_social is False:
        signals.append(
            RiskSignal(
                "missing_social",
                5,
                "no project social link was observed",
            )
        )

    if observation.bytecode_family_matches is True:
        signals.append(
            RiskSignal(
                "known_bad_bytecode_family",
                40,
                "bytecode matches a reviewed suspicious family",
            )
        )

    if provenance_complete and observation.control_evidence is ControlEvidence.ORIGINAL_SOURCE:
        signals.append(
            RiskSignal(
                "shared_controller_proven",
                30,
                "original-source evidence links the creator to a known controller",
            )
        )
    elif provenance_complete and observation.funder_kind in {
        FunderKind.CEX,
        FunderKind.RELAY,
        FunderKind.BRIDGE,
    }:
        signals.append(
            RiskSignal(
                "infrastructure_funder_not_control",
                0,
                f"{observation.funder_kind.value} routing does not prove shared control",
            )
        )

    score = min(100, sum(signal.points for signal in signals))
    unresolved = _unresolved_dependencies(observation, policy)

    if unresolved:
        risk_level = RiskLevel.UNKNOWN
        conclusion = Conclusion.INSUFFICIENT_EVIDENCE
    elif score >= policy.high_score_min:
        risk_level = RiskLevel.HIGH
        conclusion = Conclusion.SUSPICIOUS_PATTERNS_PRESENT
    elif score >= policy.review_score_min:
        risk_level = RiskLevel.REVIEW
        conclusion = Conclusion.SUSPICIOUS_PATTERNS_PRESENT
    else:
        risk_level = RiskLevel.LOW
        conclusion = Conclusion.NO_MATCHING_PATTERNS

    return RiskAssessment(
        schema_version="1.0",
        delivery_id=observation.delivery_id,
        risk_level=risk_level,
        conclusion=conclusion,
        score=score,
        signals=tuple(signals),
        unresolved_dependencies=unresolved,
        policy_version=policy.policy_version,
        observation_digest=_digest(observation.to_dict()),
        policy_digest=_digest(asdict(policy)),
    )
