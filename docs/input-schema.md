# Input schema

## Launch observation

`rat-detector analyze` accepts one JSON object:

| Field | Type | Meaning |
|---|---|---|
| `chain` | string | Lowercase EVM chain identifier. |
| `token_address` | address | 20-byte `0x`-prefixed token address. |
| `creator_address` | address | 20-byte `0x`-prefixed creator address. |
| `delivery_id` | string | Immutable delivery identity chosen by the collector. |
| `creator_nonce` | integer/null | Creator nonce at the observation boundary. |
| `creator_age_seconds` | integer/null | Observed creator age. |
| `creator_deploys_24h` | integer/null | Deployments in the preceding 24 hours. |
| `creator_token_share_pct` | number/null | Creator-associated token percentage, from 0 to 100. |
| `has_social` | boolean/null | Whether a project social link was observed. |
| `bytecode_family_matches` | boolean/null | Match against a reviewed suspicious family. |
| `funder_kind` | enum | `eoa`, `cex`, `relay`, `bridge`, `contract`, or `unknown`. |
| `control_evidence` | enum | `none`, `third_party_transfer`, or `original_source`. |
| `dependencies` | object | Dependency names mapped to `complete`, `partial`, or `failed`. |

The default policy requires `creator_profile`, `holdings`, and `provenance` to
be complete. Missing required fields or dependencies yield `risk_level:
"unknown"`.

## Provenance input

`rat-detector provenance` accepts `target_address` and a `hops` array. Each hop
contains `source`, `destination`, `transaction_hash`, `channel`, and `evidence`.
Only `original_source` evidence delivered directly to the target can produce a
`proven` controller verdict.

## Replay input

`rat-detector replay` accepts an array, or an object containing a `records`
array. Each record contains `delivery_id`, `key`, `verdict`, `source`, and an
optional `detail`. Verdicts are `good`, `unknown`, or `bad`.

