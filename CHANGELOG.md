# Changelog

## v1.0.0 — Autonomy Harbor

- Promotes the v0.1–v0.9 Personal Agent Runtime lineage into **Autonomous Observer v1.0 — Autonomy Harbor**.
- Defines the public concept: **Observe freely. Act through authority. Return with evidence.**
- Keeps the Python package name `personal-agent-runtime` for compatibility.
- Adds `docs/CONCEPT.md` and `RELEASE_NOTES_v1.0.md`.
- No weakening of v0.9 capability, signing, replay, promotion, or appliance boundaries.

## v0.9.0

- Added the Appliance Profile with five distinct service roles: Planner, Review Signer, Gate, Executor, and Verifier.
- Added Unix-domain-socket JSON RPC reference transport and service CLI entrypoints.
- Added role-scoped Ed25519 keys and process-specific trust stores.
- Added Gate-signed `ExecutionPermit` envelopes bound to the exact ActionRequest and Capability Registry version.
- Added 30-second default, one-shot execution permits with SQLite replay protection that survives Executor restarts.
- Executor now rejects raw ActionRequests without a trusted Gate permit.
- Added signed Executor results and independent Verifier finalization into signed Action Receipts.
- Added a five-process end-to-end demo proving distinct PIDs, REVIEW approval, permit issuance, execution, verification, raw-call rejection, and replay rejection.
- Added appliance, execution-permit, and execution-result schemas.
- Added Linux systemd hardening examples and explicit non-goals for root compromise, trusted time, rollback-proof state, and production key custody.

## v0.8.0

- Added a signed PRSP Promotion Gate for capability-registry changes.
- Added deterministic Capability Registry diffing and exact PromotionRequest digests.
- Added PRSP v0.1-compatible simulation receipt parsing and independent overall-gate recomputation.
- Added required-domain coverage checks for authorization, failure, observability, and security.
- Bound signed PRSP evidence to the exact promotion request so evidence cannot be replayed across capability deltas.
- Kept promotion PASS non-authoritative: it never mutates the registry or signs a new capability snapshot.
- Added promotion request/decision schemas, demo fixtures, CLI demo, and regression tests.

## v0.7.0

- Integrated the cryptographic evidence pattern from `Verifiable-Capability-Exchange` into the Personal Agent Runtime profile.
- Added deterministic canonical JSON and SHA-256 payload/envelope hashing.
- Added Ed25519 `SignedEnvelope` support with independent public-key verification.
- Added immutable-by-interface `TrustStore` records with role-scoped signers: `review_issuer`, `capability_authority`, and `runtime_receipt_signer`.
- Added signed capability-registry attestations; Runtime can optionally require an exact attested registry snapshot at startup.
- Added signed one-shot Review Leases that can be issued by a separate process; Runtime does not need the review issuer private key.
- Added SQLite-backed Replay Ledger so one-shot signed approvals remain consumed across Runtime restarts.
- Added signed Action Receipt envelopes with previous-envelope hash chaining and independent chain verification.
- Added tamper, wrong-role, untrusted-signer, scope-mismatch, expiry, replay, DENY-override, registry-mismatch, executor-failure, and chain-break tests.
- Added `signed_envelope.schema.json` and `trusted_signer.schema.json`.
- Added trust-root fields to `forbidden_learning_targets`.
- This remains a reference security profile, not production PKI or key management.

## v0.6.0

- Added a trusted `ReviewBroker` control-plane reference.
- Added exact ActionRequest SHA-256 binding for human approvals.
- Added expiring one-shot `ReviewLease` objects (`max_uses = 1`).
- Added explicit lease cancellation, replay rejection, and policy-change rejection.
- Leases are consumed before executor invocation, including failed executions.
- Added hash-chained Review Event Receipts for ISSUE / REDEEM / CANCEL / REJECT events.
- Added `review_lease.schema.json` and `review_event_receipt.schema.json`.
- Added runtime executor injection for adapter testing while preserving the sandboxed executor default.
- `DENY` remains non-overridable; REVIEW approval never becomes a durable capability grant.
- Cryptographic issuer proof remains deferred to v0.7.

## v0.5.0

- Added the first concrete application profile: `Repo Maintainer Agent`.
- Added deterministic repository triage from a normalized repository snapshot.
- Added explicit maintenance signal weights and a top-3 proposal limit.
- Added `repo_snapshot.schema.json` and `maintenance_receipt.schema.json`.
- Added a GitHub integration contract that separates read observation from mutation authority.
- Added the current 35-repository bootstrap snapshot example.
- Maintenance candidates can be converted into `github.issue.create` ActionRequests.
- Default GitHub mutation profile routes issue/file/PR creation to `REVIEW` and merge/delete/permission changes to `DENY`.
- The reference Repo Maintainer holds no GitHub write credential and does not execute GitHub mutations.

## v0.4.0

- Added LoPAS-DRM as a `core_candidate` decision-contract layer.
- Resolved the DDA naming collision locally: DRM's Decision Dependency Architecture is referred to as `DDM` (Decision Dependency Mapper); `LoPAS-DDA` retains the Deliberative Decision Architecture name.
- Added LoPAS-LCA as a `core_candidate` learning-claim gate.
- Added `decision_contract.schema.json`.
- Added separate `learning_claim.schema.json` and `learning_validation.schema.json` contracts.
- Added DRM and LCA integration invariants.
- Preserved the core rule that cognition, responsibility stamps, and validated learning cannot create authority.
- Runtime execution behavior remains unchanged from the v0.1 deterministic trust boundary; v0.4 expands ecosystem contracts around it.
