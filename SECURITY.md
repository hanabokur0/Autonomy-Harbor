# Security Model — v0.8 Reference Profile

`personal-agent-runtime` assumes the planner/model is not a trusted security principal.

The core invariant remains:

> A model may propose or learn a protocol. It may not grant itself authority.

v0.8 keeps the v0.7 cryptographic provenance model and adds signed PRSP promotion evidence. Neither signatures nor readiness results become authority by themselves.

## Protected assets

- Capability Registry contents and policy files
- TrustStore membership and signer-role assignment
- review-issuer private keys
- capability-authority private keys
- runtime-receipt signing keys
- promotion-evidence issuer keys
- exact PromotionRequest / registry-delta binding
- Replay Ledger integrity
- executor credentials
- audit / receipt history

## Attacker capabilities assumed in tests

The agent may attempt to:

- request undeclared capabilities;
- smuggle a different action under an allowed capability name;
- modify an ActionRequest after human approval;
- replay a previously approved signed lease;
- reuse approval after executor failure;
- present a lease signed by an untrusted or wrong-role key;
- modify a signed payload or chain link;
- use a signed REVIEW lease against a policy that now resolves to DENY.

The reference tests require these attempts to stop before unauthorized execution.

## Trust boundaries

```text
Untrusted / replaceable
  planner / model
  cognitive modules
  protocol candidates
  maintenance scorer

Trusted control plane
  Capability Registry
  TrustStore
  Review issuer
  Capability authority
  Capability Gate
  Replay Ledger
  PRSP Promotion Gate
  Promotion evidence verifier

Execution / evidence
  sandboxed executor or credential adapter
  Action Receipt
  runtime receipt signer
```

The reference Python objects are not an OS security boundary. Production deployment should place planner, gate, issuer, executor, and credential-holding adapters under appropriately separated OS identities/processes.

## What signatures prove

A valid v0.7 SignedEnvelope proves that:

- the exact canonical payload matches its SHA-256 hash;
- the envelope matches its own hash;
- the signature verifies under a trusted public key;
- the signer identity matches that TrustStore record;
- the signer currently has the required verifier-side role;
- optional hash-chain continuity can be independently checked.

A signature does **not** prove:

- the signed statement is factually true;
- the signer should have been trusted;
- the underlying device was uncompromised;
- the executor actually performed an external side effect unless independent evidence confirms it;
- the system is production safe.

## Known v0.8 limitations

1. **No production PKI/KMS/HSM integration.** Demo/test private keys are generated in memory.
2. **No signed remote lease-revocation channel.** The separate-process signed lease path relies on short expiry plus trust-root controls. The local v0.6 broker path still supports explicit cancellation.
3. **Clock trust.** Lease validity depends on the Runtime's system clock.
4. **Replay-ledger rollback.** SQLite prevents ordinary replay across process restart, but restoring an old database snapshot can restore old replay state unless protected by external monotonic storage/anchoring.
5. **Host compromise.** An attacker with control of the Runtime host, TrustStore, gate code, or private keys can bypass assumptions of this reference profile.
6. **No trusted timestamp / transparency log.** Envelope timestamps are signed issuer claims, not third-party time attestations.
7. **No credential adapter proof.** A successful local executor receipt is not automatically proof of a remote GitHub/email/etc. side effect.

8. **PRSP evidence quality remains bounded by its scenarios and adapters.** A signed PASS can prove that a trusted issuer attested a particular scenario result; it cannot prove the scenario set is complete. The default domain-coverage rule reduces but does not eliminate this risk.
9. **Promotion evidence signer compromise.** A compromised promotion-evidence key can sign false readiness claims. Separation from the capability-authority key prevents that compromise from directly minting new capability authority, but operator review and key revocation are still required.
10. **No automatic rollback of promoted registries.** v0.8 gates promotion eligibility; it does not yet manage staged rollout, post-promotion canaries, or automatic registry rollback.

## Production hardening direction

- KMS/HSM-backed keys and key rotation
- signed revocation statements / online revocation checks where needed
- protected trust-root provisioning
- separate OS/service identities
- append-only or externally anchored audit log
- secure/monotonic time source where expiry is security-critical
- credential adapter isolation and least privilege
- PRSP scenarios for key loss, revoked signer, clock skew, replay-ledger loss, partial external failure, and rollback recovery


## v0.9 appliance threat model additions

v0.9 adds process isolation, not a claim of host compromise resistance.

### ExecutionPermit boundary

The Executor rejects raw ActionRequests and requires a valid Gate-signed `execution_permit`. The permit is exact-request-bound, short-lived, one-shot, and consumed in a persistent SQLite ledger before execution. This prevents a Planner from bypassing the Gate merely because it can reach the Executor socket.

### Review Signer endpoint is privileged

The reference demo sends `{approved: true, approved_by: ...}` to the Review Signer. This field is **not an authentication mechanism**. In deployment, access to the Review Signer socket is itself approval authority and must be restricted to a trusted human UI/service account (for example, a private runtime directory with OS ACLs). The Planner must not be able to connect to that socket. Alternatively, replace the local endpoint with an external authenticated approval system.

### Separate service accounts

The systemd examples assume different Linux identities for planner, review signer, gate, executor, and verifier. Key files should be mode `0600` and owned only by the role that uses them. Sharing one Unix account removes much of the OS-level benefit, even though cryptographic role separation still applies.

### Still unresolved

- root/Administrator compromise can read process memory, keys, sockets, and state;
- filesystem rollback can restore an older SQLite replay ledger unless storage is externally anchored;
- wall-clock rollback can affect expiry checks;
- the reference Review Signer does not provide MFA or remote-user authentication;
- Unix-domain sockets do not by themselves authorize peers unless filesystem permissions/ACLs are correctly configured;
- the reference executor is a path sandbox, not a VM/container security boundary;
- production deployments should consider TPM/KMS/HSM key custody, monotonic counters or transparency logs, and a stronger executor sandbox.
