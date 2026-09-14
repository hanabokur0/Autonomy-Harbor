# Verifiable Capability integration — v0.7

This integration adapts the cryptographic evidence profile from `hanabokur0/Verifiable-Capability-Exchange` to the Personal Agent Runtime.

The borrowed pattern is intentionally narrow:

```text
canonical JSON
  -> SHA-256 payload hash
  -> Ed25519 signature
  -> signer role / public trust record
  -> optional previous-envelope hash
  -> independent verification
```

It is applied to three payload types:

1. `capability_registry`
2. `review_lease`
3. `action_receipt`

## Responsibility split

```text
Capability Authority
  signs exact registry snapshot
          |
Review Issuer
  signs exact one-shot REVIEW lease
          |
          v
Personal Agent Runtime
  public TrustStore only for verification
  deterministic Capability Gate
  durable Replay Ledger
          |
          v
Runtime Receipt Signer
  signs exact Action Receipt
          |
          v
Independent Verifier
```

A signature is evidence about an exact payload. It is not a general capability.

- A `review_issuer` signature cannot change `DENY` to `ALLOW`.
- A `runtime_receipt_signer` signature cannot create a grant.
- A `capability_authority` signature attests the grants already present in the exact signed registry snapshot.
- Adding a new trusted signer or assigning a new signer role is a control-plane operation, not a learning operation.

## One-shot approval across process boundaries

v0.6 required the local `ReviewBroker` object to hold lease state. v0.7 can instead receive a signed Review Lease from a separate process. The Runtime validates:

- trusted signer public key;
- `review_issuer` role;
- signer subject;
- Ed25519 signature;
- canonical payload hash and envelope hash;
- payload type;
- exact ActionRequest digest;
- capability/action/resource scope;
- current REVIEW grant IDs;
- issue/expiry timestamps;
- `max_uses = 1`.

The lease is atomically recorded in a SQLite Replay Ledger **before** executor invocation. A second redemption is rejected even after Runtime restart when the same ledger file is reused.

## Signed receipts

`PersonalAgentRuntime.run_signed(...)` returns the normal `ActionReceipt` plus a signed envelope. Success, failure, REVIEW, and DENY receipts can all be signed. Signed receipt envelopes can be chained through `previous_envelope_hash` and checked with `verify_envelope_chain(...)`.

The plain Action Receipt hash chain and the signed-envelope chain are separate on purpose. The plain chain does not depend on key availability; the signed chain adds provenance and tamper-evident signer identity.

## Capability Registry attestation

`attest_capability_registry(...)` signs a deterministic view of the registry. `PersonalAgentRuntime(..., require_signed_registry=True)` refuses startup unless a trusted `capability_authority` attested that exact snapshot.

This does not turn the signature system into a policy author. The trusted registry content remains the policy; the signature authenticates its origin and exact bytes/semantics.

## Production boundary

This v0.7 profile is a reference implementation, not production PKI or key management.

Production deployments should add:

- KMS/HSM-backed private keys;
- protected trust-root provisioning;
- key rotation and revocation;
- issuer/certificate policy;
- durable backup and integrity policy for the Replay Ledger;
- trusted timestamps or transparency-log anchoring when required;
- separate OS identities for issuer, gate, executor, and credential-holding adapters.

Demo/test code generates private keys in memory. Private key material must not be committed to the repository.
