# Contributing

Contributions that improve explainability, validation, deterministic replay,
documentation, or synthetic test coverage are welcome after the repository is
published.

## Development

1. Use Python 3.11 or newer.
2. Install locally with `python -m pip install --no-build-isolation -e .`.
3. Run `python -m unittest discover -s tests -v`.
4. Run `python -m compileall -q src`.
5. Keep examples synthetic and free of real wallet or transaction identifiers.

Every behavior change should include production-shaped tests for the relevant
happy path, race/replay behavior, threshold boundary, failure mode, and
dependency-chain behavior.

## Hard boundaries

Pull requests must not add:

- wallet import, private-key handling, signing, approvals, orders, swaps, buys,
  sells, transaction construction, or transaction broadcasting;
- live RPC/API calls in the core analysis path;
- synchronous persistent writes in the analysis path;
- production addresses, credentials, logs, allowlists, blocklists, or customer
  data;
- claims that CEX, bridge, or relay routing proves shared control.

Use synthetic fixtures. If a real incident motivates a regression, reduce it to
the smallest anonymized state shape before committing it.

## Pull requests

Describe the observed failure, the intended invariant, the tests that reproduce
it, and any compatibility impact. Generated code must be reviewed and tested by
a human maintainer before merge.

