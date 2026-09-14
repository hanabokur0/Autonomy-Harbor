# Architecture note

This file is the compact trust-plane view. See `../ARCHITECTURE.md` for the full LoPAS ecosystem map and `../SECURITY.md` for the v0.7 threat model.

## Separation of planes

```text
DATA / INTELLIGENCE PLANE
model -> planner -> protocol -> ActionRequest

COGNITIVE CONTROL PLANE
MCCP / LPTM / CHD / DRM / Deliberative DDA / LCA
proposal, routing, learning validation

TRUST PLANE
human/admin -> TrustStore + Capability Registry -> Capability Gate
                  |                 |
                  |                 +-> optional signed registry attestation
                  +-> trusted public keys / signer roles

REVIEW CONTROL PLANE
human review issuer private key
  -> signed one-shot ReviewLease
  -> Runtime verifies with public key only
  -> SQLite Replay Ledger consumes BEFORE execution

EXECUTION PLANE
ALLOW only -> sandboxed executor / credential adapter -> external effect

EVIDENCE PLANE
ActionReceipt hash chain
  + SignedEnvelope hash chain
  -> independent public-key verification
```

No output from the intelligence or cognitive plane is interpreted as a trust-plane mutation.

## Security progression

### v0.1

- default-deny capability gate;
- DENY > REVIEW > ALLOW;
- action/resource scope matching;
- protected control-plane capabilities;
- sandboxed reference file executor;
- hash-chained Action Receipts.

### v0.6

- exact-request human ReviewLease;
- expiry / cancellation / one-shot redemption;
- lease consumed before executor call;
- REVIEW never falls through without explicit release.

### v0.7

- canonical JSON + SHA-256 + Ed25519 SignedEnvelope;
- role-scoped TrustStore;
- signed Capability Registry attestation;
- signed one-shot review leases from a separate issuer process;
- durable SQLite replay protection across Runtime restarts;
- signed Action Receipt envelopes;
- independent chain verification and tamper detection.

## Still outside the reference boundary

- OS/kernel compromise and container escape;
- production PKI/KMS/HSM lifecycle;
- remote signed lease revocation for the separate-process signed path;
- trusted time / transparency-log anchoring;
- replay-ledger rollback protection against storage snapshot restoration;
- external credential theft;
- proof that a remote side effect really occurred;
- TOCTOU on external resources;
- prompt injection inside a trusted adapter;
- full production readiness certification.

These belong in hardening work and PRSP scenarios rather than being hidden behind the phrase "signed therefore safe."
