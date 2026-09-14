# Review Broker integration contract — v0.6

The Review Broker is a trusted control-plane component between a `REVIEW` gate result and execution.
It does **not** convert REVIEW into durable ALLOW authority.

## Required flow

```text
ActionRequest
  -> Capability Gate = REVIEW
  -> Human approval in trusted control plane
  -> exact-request ReviewLease
  -> Review Broker redemption
  -> one execution attempt
  -> lease consumed before executor call
  -> Action Receipt + Review Event Receipt
```

## v0.6 invariants

- leases are issued only for requests already routed to `REVIEW`;
- a lease is bound to the SHA-256 digest of the complete ActionRequest;
- capability, action, resource, and matching REVIEW grant IDs must remain unchanged;
- leases are one-shot (`max_uses = 1`);
- expired and cancelled leases cannot be redeemed;
- a redeemed lease stays consumed even if the executor fails;
- a lease cannot override `DENY`;
- the planner/agent must not hold lease issuance or cancellation authority;
- v0.6 local leases remain supported for compatibility; v0.7 additionally supports a separate-process Ed25519-signed lease path. See `../verifiable_capability/README.md`.

For external systems such as GitHub, the runtime should hand the authorized request to a separate credential-holding adapter. The model/planner should not receive the credential.


## v0.7 signed path

The v0.7 Runtime can receive a signed ReviewLease without sharing the issuer private key or ReviewBroker object. Public-key verification, signer-role checks, exact-request binding, and a SQLite Replay Ledger preserve one-shot behavior across Runtime restarts. The signed path currently has no remote signed revocation channel; use short TTLs and protected trust-root controls.
