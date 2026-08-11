# Security Policy

## Supported versions

Security fixes currently target the latest `0.x` release on the default branch.

## Reporting a vulnerability

After publication, use the repository's private GitHub Security Advisory flow.
Do not open a public issue containing exploit details, credentials, private
keys, seed phrases, RPC URLs, production addresses, or non-public incident data.

Include a minimal synthetic reproduction, affected version, expected invariant,
and impact. The maintainer will acknowledge valid reports and coordinate a fix
and disclosure timeline.

## Scope

Security-sensitive areas include:

- malformed or adversarial JSON/bytecode input;
- evidence precedence and replay consistency;
- dependency failures incorrectly becoming low-risk results;
- provenance claims that infer control from infrastructure wallets;
- accidental introduction of network, persistence, wallet, signing, or
  transaction-execution behavior.

This project performs analysis only. Any pull request adding transaction
execution or secret handling is out of scope and will be rejected.

