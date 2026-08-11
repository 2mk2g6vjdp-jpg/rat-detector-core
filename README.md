# Rat Detector Core

Rat Detector Core is an explainable, offline-first toolkit for reviewing
suspicious BSC/EVM token launches. It turns already-collected observations into
deterministic risk signals, conservative controller-evidence verdicts, bytecode
fingerprints, and replayable evidence records.

This repository intentionally contains **no wallet, signing, order, swap,
sniping, transaction-submission, RPC, alerting, or live-service control code**.
It is a public analysis component, not a trading system.

[繁體中文說明](README.zh-TW.md)

## Why it exists

Launch investigations are easy to make opaque: missing API data may be treated
as safe, a relay or exchange hot wallet may be mistaken for a shared
controller, and a late retry may overwrite stronger evidence. Rat Detector Core
makes those decisions explicit and testable:

- incomplete required dependencies remain `unknown`;
- CEX, bridge, and relay transfers do not prove shared control;
- only direct original-source evidence can mark control as `proven`;
- a bad same-delivery verdict cannot be shadowed by a later unknown result;
- every result contains machine-readable signals and explanations;
- the core performs no network or filesystem writes during analysis.

## Quick start

Python 3.11 or newer is required. The runtime has no third-party dependencies.

```bash
python -m venv .venv
python -m pip install --no-build-isolation -e .
rat-detector analyze examples/suspicious_launch.json
rat-detector provenance examples/provenance_relay.json
rat-detector replay examples/evidence_race.json
rat-detector fingerprint 0x63a9059cbb600063095ea7b3
rat-detector receipt examples/receipt_transfers.json
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

## Python API

```python
import json
from pathlib import Path

from rat_detector_core import LaunchObservation, assess_launch

payload = json.loads(Path("examples/suspicious_launch.json").read_text())
observation = LaunchObservation.from_mapping(payload)
assessment = assess_launch(observation)
print(assessment.to_dict())
```

## Repository boundaries

Included:

- validated launch-observation models;
- deterministic and explainable risk scoring;
- conservative funding/controller provenance classification;
- metadata-aware bytecode fingerprinting and PUSH4 selector extraction;
- neutral ERC-20 mint and transfer evidence extraction from supplied receipts;
- thread-safe evidence replay with immutable delivery keys;
- synthetic examples and regression tests.

Explicitly excluded:

- private keys, seed phrases, credentials, endpoints, wallet addresses, or
  production datasets;
- transaction construction, signing, simulation, broadcasting, buying,
  selling, routing, or approval logic;
- live mempool/RPC clients, alert bots, dashboards, service controls, and
  deployment automation;
- proprietary production thresholds, allowlists, blocklists, or incident logs.

See [Architecture](docs/architecture.md), [Input schema](docs/input-schema.md),
[Security policy](SECURITY.md), and [Contributing](CONTRIBUTING.md).

## Project status

This is an alpha extraction of the analysis and replay concepts used by Rat
Detector. Inputs and outputs are stable enough for tests and experimentation,
but policy thresholds should be reviewed for each research context.

## License

Licensed under the [Apache License 2.0](LICENSE).
