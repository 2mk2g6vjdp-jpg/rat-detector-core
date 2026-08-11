import ast
from unittest.mock import patch
from pathlib import Path
import unittest

from rat_detector_core.bytecode import analyze_bytecode
from rat_detector_core.engine import assess_launch
from rat_detector_core.models import LaunchObservation
from rat_detector_core.receipt import analyze_receipt


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "rat_detector_core"

BANNED_IMPORT_ROOTS = {
    "aiohttp",
    "dotenv",
    "eth_account",
    "ftplib",
    "flask",
    "http",
    "httpx",
    "paramiko",
    "requests",
    "smtplib",
    "socket",
    "ssl",
    "subprocess",
    "urllib",
    "web3",
    "websockets",
}

BANNED_CALL_NAMES = {
    "approve",
    "broadcast_transaction",
    "buy",
    "sell",
    "send_raw_transaction",
    "send_transaction",
    "sign_transaction",
    "swap",
}

BANNED_WRITE_CALL_NAMES = {
    "makedirs",
    "mkdir",
    "remove",
    "rename",
    "replace",
    "unlink",
    "write_bytes",
    "write_text",
}


class PublicationBoundaryTests(unittest.TestCase):
    def test_source_has_no_network_wallet_or_service_imports(self):
        violations = []
        for path in SOURCE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = {alias.name.split(".")[0] for alias in node.names}
                    for name in sorted(names & BANNED_IMPORT_ROOTS):
                        violations.append(f"{path.name}:{node.lineno}: import {name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    name = node.module.split(".")[0]
                    if name in BANNED_IMPORT_ROOTS:
                        violations.append(f"{path.name}:{node.lineno}: from {name}")
        self.assertEqual(violations, [])

    def test_source_has_no_transaction_execution_call_names(self):
        violations = []
        for path in SOURCE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                else:
                    continue
                if name in BANNED_CALL_NAMES:
                    violations.append(f"{path.name}:{node.lineno}: {name}")
        self.assertEqual(violations, [])

    def test_source_has_no_persistent_write_calls(self):
        violations = []
        for path in SOURCE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in BANNED_WRITE_CALL_NAMES:
                        violations.append(f"{path.name}:{node.lineno}: {node.func.attr}")
                    is_open = node.func.attr == "open"
                    mode_node = node.args[0] if is_open and node.args else None
                else:
                    is_open = isinstance(node.func, ast.Name) and node.func.id == "open"
                    mode_node = node.args[1] if is_open and len(node.args) > 1 else None
                if is_open and mode_node is None:
                    mode_node = next(
                        (item.value for item in node.keywords if item.arg == "mode"),
                        None,
                    )
                if mode_node is not None:
                    if (
                        isinstance(mode_node, ast.Constant)
                        and isinstance(mode_node.value, str)
                        and any(flag in mode_node.value for flag in "wax+")
                    ):
                        violations.append(f"{path.name}:{node.lineno}: open({mode_node.value!r})")
        self.assertEqual(violations, [])

    def test_core_analysis_runs_with_network_socket_disabled(self):
        payload = {
            "chain": "bsc",
            "token_address": "0x1111111111111111111111111111111111111111",
            "creator_address": "0x2222222222222222222222222222222222222222",
            "delivery_id": "bsc:synthetic:offline",
            "creator_nonce": 42,
            "creator_age_seconds": 7_776_000,
            "creator_deploys_24h": 1,
            "creator_token_share_pct": 2,
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

        with patch("socket.socket", side_effect=AssertionError("network access attempted")):
            assess_launch(LaunchObservation.from_mapping(payload))
            analyze_bytecode("0x63a9059cbb")
            analyze_receipt({"logs": []})


if __name__ == "__main__":
    unittest.main()
