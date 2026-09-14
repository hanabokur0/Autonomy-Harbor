# Autonomous Observer v1.0 — Autonomy Harbor

v1.0 names and consolidates the architecture developed through Personal Agent Runtime v0.1–v0.9.

## What v1.0 establishes

- model-independent planner boundary;
- default-deny capability registry and deterministic gate;
- hard separation between protocol knowledge and authority;
- human review through signed one-shot leases;
- Ed25519-signed registries, permits, execution evidence, and receipts;
- replay-resistant one-shot permits using persistent ledgers;
- PRSP-backed capability promotion evidence where PASS never auto-grants authority;
- separate planner / review signer / gate / executor / verifier OS processes;
- role-scoped signing keys;
- Repo Maintainer reference application;
- learning separation through Compost / LCA / ProtocolMemory integration contracts.

## v0.x lineage

- v0.1 — Capability Runtime
- v0.2 — Architecture and component manifest
- v0.3 — CHD integration
- v0.4 — DRM / LCA integration
- v0.5 — Repo Maintainer Agent
- v0.6 — Review Broker
- v0.7 — Verifiable Capability and signed receipts
- v0.8 — PRSP Promotion Gate
- v0.9 — Appliance Profile and ExecutionPermit process boundary
- v1.0 — Autonomy Harbor product / architecture identity

## Core invariants

```text
protocol knowledge != capability grant
experience != validated learning
validated learning != authority
PRSP PASS != capability grant
signature validity != permission expansion
planner != gate != executor != verifier
```

## Status

Reference implementation. Not a production PKI, HSM/KMS, remote revocation service, or complete hardened operating environment.
