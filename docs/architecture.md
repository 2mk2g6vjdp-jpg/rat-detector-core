# Architecture

Rat Detector Core is intentionally a small, dependency-free analysis library.

```text
synthetic or user-supplied JSON
            |
            v
  validation and normalization
            |
      +-----+------------------+
      |                        |
      v                        v
risk policy            provenance policy
      |                        |
      +-----------+------------+
                  v
       explainable JSON results

independent path: evidence records -> in-memory replay ledger -> snapshot
independent path: bytecode -> normalization -> metadata strip -> fingerprint
```

## Modules

- `models.py`: strict untrusted-input validation and result models.
- `engine.py`: deterministic thresholds and risk explanations.
- `provenance.py`: direct-evidence-only shared-control classification.
- `replay.py`: thread-safe immutable-delivery evidence precedence.
- `bytecode.py`: pure normalization, metadata stripping, hashing, and selector
  extraction.
- `receipt.py`: neutral ERC-20 transfer evidence extraction from supplied JSON.
- `cli.py`: local JSON interface with stable machine-readable output.

## Trust boundaries

The caller owns data collection. The core never connects to a blockchain, API,
wallet, browser, database, alert service, or trading venue. It cannot sign or
send a transaction.

All input is untrusted. Validation happens before policy evaluation. Missing or
failed mandatory dependencies produce `unknown`; callers must not reinterpret
that result as low risk.

## Determinism and replay

The same validated observation and policy version always produce the same
assessment. Evidence replay uses `(delivery_id, key)` as an immutable identity.
Verdict precedence is `bad > unknown > good`, and equal-severity conflicts use a
stable lexical tie-break. Arrival order therefore cannot erase a stronger
same-delivery result.
