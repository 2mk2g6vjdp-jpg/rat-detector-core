"""Command-line interface for local JSON analysis and deterministic replay."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from .bytecode import analyze_bytecode
from .engine import assess_launch
from .models import LaunchObservation, ValidationError
from .provenance import FundingHop, assess_shared_control
from .receipt import analyze_receipt
from .replay import EvidenceRecord, replay_records


def _load_json(path: str) -> Any:
    def reject_nonstandard_constant(value: str) -> None:
        raise ValidationError(f"non-standard JSON constant is not allowed: {value}")

    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle, parse_constant=reject_nonstandard_constant)
    except OSError as exc:
        raise ValidationError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc.msg}") from exc


def _write_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rat-detector",
        description="Offline, explainable EVM suspicious-launch analysis",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="analyze one launch JSON file")
    analyze_parser.add_argument("path")

    provenance_parser = subparsers.add_parser(
        "provenance", help="classify controller evidence from funding hops"
    )
    provenance_parser.add_argument("path")

    replay_parser = subparsers.add_parser(
        "replay", help="replay evidence records with deterministic precedence"
    )
    replay_parser.add_argument("path")

    fingerprint_parser = subparsers.add_parser(
        "fingerprint", help="inspect and fingerprint literal EVM bytecode"
    )
    fingerprint_parser.add_argument("bytecode")

    receipt_parser = subparsers.add_parser(
        "receipt", help="extract neutral ERC-20 transfer evidence from receipt JSON"
    )
    receipt_parser.add_argument("path")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "analyze":
            observation = LaunchObservation.from_mapping(_load_json(args.path))
            _write_json(assess_launch(observation).to_dict())
            return 0

        if args.command == "provenance":
            payload = _load_json(args.path)
            if not isinstance(payload, dict) or not isinstance(payload.get("hops"), list):
                raise ValidationError("provenance input must contain a hops array")
            hops = [FundingHop.from_mapping(item) for item in payload["hops"]]
            assessment = assess_shared_control(payload.get("target_address"), hops)
            _write_json(assessment.to_dict())
            return 0

        if args.command == "replay":
            payload = _load_json(args.path)
            rows = payload.get("records") if isinstance(payload, dict) else payload
            if not isinstance(rows, list):
                raise ValidationError("replay input must be an array or contain a records array")
            records = [EvidenceRecord.from_mapping(item) for item in rows]
            ledger = replay_records(record.to_dict() for record in records)
            _write_json({"records": ledger.snapshot(), "record_count": len(ledger.snapshot())})
            return 0

        if args.command == "fingerprint":
            _write_json(analyze_bytecode(args.bytecode).to_dict())
            return 0

        if args.command == "receipt":
            _write_json(analyze_receipt(_load_json(args.path)).to_dict())
            return 0

        parser.error("unknown command")
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 2
