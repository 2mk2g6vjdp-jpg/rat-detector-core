import unittest
import math

from rat_detector_core import (
    Conclusion,
    LaunchObservation,
    RiskLevel,
    RiskPolicy,
    ValidationError,
    assess_launch,
)


BASE = {
    "chain": "bsc",
    "token_address": "0x1111111111111111111111111111111111111111",
    "creator_address": "0x2222222222222222222222222222222222222222",
    "delivery_id": "bsc:synthetic:1",
    "creator_nonce": 42,
    "creator_age_seconds": 7_776_000,
    "creator_deploys_24h": 1,
    "creator_token_share_pct": 2.0,
    "has_social": True,
    "bytecode_family_matches": False,
    "funder_kind": "eoa",
    "control_evidence": "none",
    "dependencies": {
        "creator_profile": "complete",
        "holdings": "complete",
        "provenance": "complete",
    },
}


def observation(**changes):
    payload = dict(BASE)
    payload.update(changes)
    return LaunchObservation.from_mapping(payload)


class EngineScenarioTests(unittest.TestCase):
    def test_happy_path_reports_explainable_suspicious_patterns(self):
        result = assess_launch(
            observation(
                creator_nonce=1,
                creator_age_seconds=900,
                creator_deploys_24h=8,
                creator_token_share_pct=28.5,
                has_social=False,
                bytecode_family_matches=True,
            )
        )

        self.assertEqual(result.risk_level, RiskLevel.HIGH)
        self.assertEqual(result.conclusion, Conclusion.SUSPICIOUS_PATTERNS_PRESENT)
        self.assertEqual(result.score, 100)
        self.assertIn("rapid_deployer", {signal.code for signal in result.signals})
        self.assertEqual(len(result.observation_digest), 64)
        self.assertEqual(len(result.policy_digest), 64)

    def test_threshold_boundaries_are_inclusive(self):
        at_boundary = assess_launch(
            observation(
                creator_nonce=1,
                creator_age_seconds=3_600,
                creator_deploys_24h=5,
                creator_token_share_pct=20,
            )
        )
        outside_boundary = assess_launch(
            observation(
                creator_nonce=2,
                creator_age_seconds=3_601,
                creator_deploys_24h=4,
                creator_token_share_pct=19.999,
            )
        )

        self.assertEqual(at_boundary.score, 85)
        self.assertEqual(at_boundary.risk_level, RiskLevel.HIGH)
        self.assertEqual(outside_boundary.score, 0)
        self.assertEqual(outside_boundary.risk_level, RiskLevel.LOW)
        self.assertEqual(outside_boundary.conclusion, Conclusion.NO_MATCHING_PATTERNS)

    def test_dependency_failure_is_never_coerced_to_low_risk(self):
        dependencies = dict(BASE["dependencies"])
        dependencies["provenance"] = "failed"
        result = assess_launch(observation(dependencies=dependencies))

        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertEqual(result.conclusion, Conclusion.INSUFFICIENT_EVIDENCE)
        self.assertIn("provenance", result.unresolved_dependencies)

    def test_missing_required_field_is_insufficient_evidence(self):
        result = assess_launch(observation(creator_token_share_pct=None))

        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertIn("holdings.creator_share", result.unresolved_dependencies)

    def test_failed_holdings_dependency_suppresses_untrusted_signal(self):
        dependencies = dict(BASE["dependencies"])
        dependencies["holdings"] = "failed"
        result = assess_launch(
            observation(
                creator_token_share_pct=99,
                dependencies=dependencies,
            )
        )

        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertNotIn(
            "creator_concentration",
            {signal.code for signal in result.signals},
        )

    def test_relay_does_not_become_controller_evidence(self):
        result = assess_launch(
            observation(
                funder_kind="relay",
                control_evidence="third_party_transfer",
            )
        )

        signal = next(
            item for item in result.signals if item.code == "infrastructure_funder_not_control"
        )
        self.assertEqual(signal.points, 0)
        self.assertEqual(result.risk_level, RiskLevel.LOW)

    def test_invalid_address_fails_before_analysis(self):
        with self.assertRaises(ValidationError):
            observation(token_address="0x1234")

    def test_non_finite_percentage_is_rejected(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                observation(creator_token_share_pct=value)

    def test_invalid_policy_thresholds_are_rejected(self):
        invalid_policies = (
            {"review_score_min": 90, "high_score_min": 10},
            {"review_score_min": -1},
            {"high_score_min": 101},
            {"concentrated_creator_share_min_pct": math.nan},
            {"fresh_creator_nonce_max": -1},
            {"required_dependencies": ("creator_profile", "creator_profile")},
        )
        for values in invalid_policies:
            with self.subTest(values=values), self.assertRaises(ValueError):
                RiskPolicy(**values)

    def test_digest_is_independent_of_dependency_input_order(self):
        forward = observation()
        reverse_dependencies = dict(reversed(list(BASE["dependencies"].items())))
        reverse = observation(dependencies=reverse_dependencies)

        self.assertEqual(
            assess_launch(forward).observation_digest,
            assess_launch(reverse).observation_digest,
        )


if __name__ == "__main__":
    unittest.main()
