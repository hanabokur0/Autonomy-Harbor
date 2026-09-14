# v0.9 Appliance Profile

v0.9 turns the reference runtime into a local multi-process appliance profile. It does **not** replace Linux or Windows. The host OS remains responsible for users, filesystem ACLs, process supervision, time, networking, and device access.

## Process topology

```text
Planner (no private key)
  |
  | ActionRequest
  v
Gate (registry + review public key + gate signing key)
  | REVIEW                         ^
  +------------------------------> Review Signer
  |                                 human approval + review private key
  | signed review lease             |
  <---------------------------------+
  |
  | signed ExecutionPermit (30 s, one-shot)
  v
Executor (sandbox + gate public key + executor signing key)
  |
  | signed ExecutionResult
  v
Verifier (gate/executor public keys + receipt signing key)
  |
  v
Signed Action Receipt
```

The critical change from an in-process architecture is that the Executor no longer trusts a raw `ActionRequest`. It requires an Ed25519-signed `execution_permit` issued by the Gate. The permit binds the exact request digest, capability, action, resource, actor, registry version, gate reason, expiry, and one-shot semantics.

## Reference commands

```bash
par-runtime appliance-init /var/lib/par/reference
par-runtime appliance-demo /tmp/par-demo
par-runtime appliance-service --role gate --profile /etc/par/appliance_profile.json
```

The demo starts five distinct OS processes over Unix-domain sockets and verifies:

- all five roles use different PIDs;
- the Planner has no private signing key;
- the Executor rejects raw requests without a Gate permit;
- REVIEW requires a signed human-review lease;
- the Gate cannot execute actions itself;
- the Executor cannot change the Capability Registry;
- the Gate permit is short-lived and one-shot;
- permit replay is blocked by SQLite across Executor restarts;
- execution evidence is signed by the Executor;
- the Verifier independently checks Gate and Executor signatures before issuing the final signed Action Receipt.

## Host OS boundary

For an actual appliance, create separate service users such as:

```text
par-planner
par-review
par-gate
par-executor
par-verifier
```

Private keys should be readable only by their owning process user. The Planner should read none. The Executor should not be able to read the review or gate private keys, and the Gate should not be able to write the Executor sandbox.

The systemd files in `deploy/systemd/` are hardening examples, not an installer. Production deployments still need explicit ownership/ACL setup, trusted time, backup/rollback protections for replay ledgers, key rotation, and ideally KMS/HSM-backed signing.

## Windows mapping

The contracts are transport-agnostic. On Windows, replace Unix-domain socket/service-user isolation with named pipes or localhost IPC plus dedicated service accounts and ACLs. `execution_permit`, signed evidence, registry separation, and one-shot replay ledgers remain unchanged.

## Non-goals

v0.9 does not claim:

- VM or hardware isolation;
- resistance to a compromised root/Administrator account;
- production key management;
- rollback-proof SQLite storage;
- trusted time;
- an actual GitHub write adapter inside the local Executor.

It provides a testable process boundary that can later be strengthened by OS sandboxes, containers, VMs, TPM/KMS/HSM keys, and dedicated machines without changing the protocol contracts.
