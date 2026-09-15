# Personal Agent Runtime

> **The agent may learn protocols. It may not grant itself authority.**

`personal-agent-runtime` is a minimal execution boundary for autonomous or semi-autonomous AI agents.
It treats models as replaceable planners and keeps authority, execution policy, and receipts outside the model.

The project is designed as the execution trust boundary inside a wider LoPAS-derived ecosystem. v0.9 adds an **Appliance Profile**: planner, review signer, gate, executor, and verifier run as distinct OS processes, with role-scoped keys and a Gate-signed one-shot `ExecutionPermit` required before the Executor will act.

See **`ARCHITECTURE.md`** for the end-to-end cognitive/execution loop and **`component_manifest.yaml`** for repository responsibilities, status, and authority boundaries.

## Why

Most agent stacks mix three different things:

1. what the agent knows;
2. what the agent wants to do;
3. what the agent is actually allowed to do.

This runtime separates them.

```text
Observation / task
      ↓
LoPAS Protocol Foundry
      ↓ promoted protocol / shadow plan
Planner / model
      ↓ ActionRequest
Personal Agent Runtime
      ├─ Capability Registry
      ├─ Deterministic Gate
      ├─ Sandboxed Executor
      └─ Receipt
      ↓
PRSP / regression / audit
```

## Core safety invariants

- **Default deny.** Unknown capability, action, or resource does not execute.
- **DENY > REVIEW > ALLOW.** A permissive grant cannot override a matching deny.
- **Control plane is not an agent capability.** Requests under `runtime.permission.*`, `runtime.registry.*`, `runtime.gate.*`, and `runtime.policy.*` are hard-denied.
- **Knowledge != authority.** A protocol may declare a required capability; that declaration never creates the grant.
- **REVIEW is non-executing.** Human review routes never fall through to the executor.
- **Sandboxed file access.** Built-in file actions cannot escape the configured sandbox root.
- **Immutable in-process policy.** Registry and grant objects are frozen and stored as tuples.
- **Receipt for every attempt.** Allowed, denied, review-routed, and failed actions all produce receipts.
- **Trust roots are outside learning.** Trusted signer keys, trust-store membership, and signature-role assignment are control-plane configuration, never learned state.
- **Signatures attest; they do not expand scope.** A valid signature proves who attested an exact payload. It cannot turn `DENY` into `ALLOW` or add grants absent from the signed registry.

Python object immutability is not an OS security boundary. v0.9 includes a Linux reference appliance profile with distinct process roles, but production still requires real service users, ACLs, protected key custody, trusted time, and rollback-resistant state.

## Quick start

```bash
python -m pip install -e .
python -m pytest -q
par-runtime demo
par-runtime review-demo
par-runtime signed-review-demo
par-runtime promotion-demo
par-runtime appliance-demo /tmp/par-demo
```

Example:

```python
from pathlib import Path
from personal_agent_runtime import (
    ActionRequest,
    CapabilityGrant,
    CapabilityRegistry,
    PersonalAgentRuntime,
)

registry = CapabilityRegistry(
    registry_id="local-default",
    version="1",
    grants=(
        CapabilityGrant(
            grant_id="echo-only",
            capability="tool.echo",
            effect="ALLOW",
            actions=("echo",),
            resources=("console",),
        ),
    ),
)

runtime = PersonalAgentRuntime(registry=registry, sandbox_root=Path("sandbox"))
receipt = runtime.run(
    ActionRequest(
        request_id="req-001",
        capability="tool.echo",
        action="echo",
        resource="console",
        payload={"text": "hello"},
    )
)

assert receipt.gate == "ALLOW"
assert receipt.outcome == "SUCCEEDED"
```


## v1.2 MCP Inbound Adapter

MCP clients can connect to Autonomy Harbor without becoming an authority source.
The MCP surface is an inbound adapter: it proposes ActionRequests, while real
execution still requires the existing Appliance path and a Gate-signed one-shot
ExecutionPermit.

```text
MCP host -> Planner -> Gate -> ExecutionPermit -> Executor -> Adapter -> Verifier
```

Install the optional MCP dependency and start the stdio server:

```bash
pip install -e ".[mcp]"
PAR_MCP_APPLIANCE_PROFILE=.par-appliance/config/appliance_profile.json par-mcp
```

MCP cannot issue review leases, mutate the registry, manage trust roots, or
choose its own human-looking audit identity. See `docs/MCP.md`.


## v0.5 Repo Maintainer Agent

The first application profile turns the runtime into a small, inspectable work system. It consumes a normalized repository snapshot and returns no more than three maintenance proposals. Ranking is deterministic and evidence-bearing; it is not an authorization mechanism.

```bash
par-runtime maintain examples/repo_snapshot_35.json
```

A selected candidate can be transformed into a `github.issue.create` ActionRequest. Under the default v0.5 capability profile, that request routes to `REVIEW`, so the reference runtime records the attempt but does not create the issue. Merge, repository deletion, and permission changes remain `DENY`.

```text
repo snapshot -> top 3 candidates -> review ActionRequest -> Runtime Gate -> REVIEW
```

The GitHub observer and scorer do not hold a GitHub write credential. Actual GitHub writes belong in a separate human-approved adapter/broker.


## v0.6 Review Broker

`REVIEW` is no longer only a stopping state. v0.6 adds a trusted control-plane broker that can release exactly one execution attempt after explicit human approval. The lease is not a durable capability grant.

```text
ActionRequest
  -> Gate = REVIEW
  -> trusted human approval
  -> ReviewLease(request SHA-256, exact scope, expiry, max_uses=1)
  -> redeem BEFORE execution
  -> one attempt
  -> replay / expiry / cancellation => REVIEW + NOT_EXECUTED
```

Key properties:

- the complete request payload is hashed, so post-approval edits invalidate the lease;
- the same REVIEW grant IDs must still match at redemption time;
- `DENY` can never be overridden by a review lease;
- the lease is consumed before the executor is called, so executor failure does not make it reusable;
- issue/file/PR writes remain review-routed by default;
- the planner must not receive lease issuance or cancellation APIs.

For GitHub, the recommended deployment is still split: the Runtime approves the exact action, while a separate credential-holding adapter performs the external mutation.

## v0.7 Verifiable Capability & Signed Receipts

v0.7 removes the requirement that the Runtime share a process or private key with the human Review Broker. The broker can sign an exact one-shot `ReviewLease`; the Runtime needs only the corresponding public trust record.

```text
Human / Review Broker process
  private Ed25519 key
  -> signed ReviewLease
           |
           v
Personal Agent Runtime
  public TrustStore only
  -> verify signer role
  -> verify exact request digest / scope / expiry
  -> atomically consume lease in SQLite Replay Ledger
  -> execute once
  -> emit signed Action Receipt
```

The same envelope format is used for three trust statements:

- `capability_registry` — a `capability_authority` attests the exact registry snapshot;
- `review_lease` — a `review_issuer` attests one exact, expiring REVIEW release;
- `action_receipt` — a `runtime_receipt_signer` attests the exact execution receipt.

Every envelope contains canonical JSON, a SHA-256 payload hash, signer/key identifiers, an Ed25519 signature, an optional previous-envelope hash, and its own envelope hash. Receipt-envelope chains can be independently verified without access to a private key.

A signed review lease still cannot override `DENY`. A signed registry attestation does not invent new grants; it only proves which exact registry snapshot a trusted capability authority attested. Trust-store membership and role assignment are explicitly forbidden learning targets.

The reference implementation keeps private keys in memory only for demos/tests. Production deployments should use KMS/HSM-backed signing keys, key rotation, issuer policy, and an external trust-root provisioning process.

## v0.8 PRSP Promotion Gate

v0.8 turns PRSP into a formal gate for **capability-registry promotion**, not an action-time permission source. A proposed registry is diffed against the current signed registry, creating a deterministic `PromotionRequest`. PRSP evidence is then signed by a separate `promotion_evidence_issuer` and bound to that exact request digest.

```text
Current Registry
  -> Proposed Registry
  -> Capability Delta
  -> PromotionRequest
  -> PRSP simulation / evidence
  -> signed PRSP Promotion Evidence
  -> PRSPPromotionGate
       PASS / REVIEW / HOLD / REJECT
  -> Capability Authority MAY sign proposed registry
```

The gate independently recomputes PRSP precedence (`REJECT > HOLD > REVIEW > PASS`) from scenario results. A declared `PASS` containing a hidden `HOLD` is rejected as inconsistent. For possible authority expansion, the default profile also requires non-SKIP coverage in `authorization`, `failure`, `observability`, and `security`; missing coverage produces `HOLD`.

Most importantly:

```text
PRSP PASS != capability grant
PRSP PASS != signed registry
PRSP PASS != execution permission
```

A PASS means only that the exact proposed capability delta is **eligible for separate control-plane promotion consideration**. The PRSP gate never mutates the Capability Registry and does not hold the capability-authority signing key.

Try the reference flow:

```bash
par-runtime promotion-demo
par-runtime appliance-demo /tmp/par-demo
```

`examples/prsp_app_manifest_v08.yaml` is also included for running the Runtime itself through the upstream PRSP. It intentionally leaves unverified production controls false; a resulting HOLD is useful evidence, not a failure to hide.

## v0.9 Appliance Profile

v0.9 turns the trust boundary into a five-process reference appliance:

```text
Planner (no private key)
   -> Gate
      -> REVIEW -> Review Signer (human approval key)
      -> ALLOW
      -> signed ExecutionPermit (30 s, one-shot)
   -> Executor (permit required, sandbox only)
   -> signed ExecutionResult
   -> Verifier
   -> signed Action Receipt
```

The Executor no longer accepts a raw `ActionRequest`. It must receive an Ed25519-signed permit from a trusted `execution_permit_issuer`. The permit binds the exact request digest, capability, action, resource, actor, registry ID/version, gate reason, expiry, and `max_uses=1`. A SQLite permit ledger consumes it before execution and blocks replay across Executor restarts.

Run the complete process-isolation demo:

```bash
par-runtime appliance-demo /tmp/par-demo
```

The demo asserts five distinct PIDs, a REVIEW -> signed human approval -> Gate permit transition, rejection of direct Executor calls, successful sandbox execution, replay rejection, signed Executor evidence, and independent Verifier finalization.

`deploy/systemd/` contains hardened Linux service examples. The Review Signer is a privileged human-control-plane endpoint: its socket must be protected by a dedicated service account/ACL and must **not** be exposed to the Planner. The demo's `approved=true` message stands in for that trusted human UI boundary; it is not itself an authentication protocol. See `docs/APPLIANCE.md` and `SECURITY.md`.

## What this reference runtime is not

- not an OS replacement;
- not a model host;
- not a credential manager;
- not proof that an agent is production-safe;
- not a substitute for OS sandboxing, IAM, security review, or legal review.

It is the narrow boundary where an agent proposal becomes an authorized action — or stops.

## Repository layout

```text
src/personal_agent_runtime/
  models.py      immutable request / grant / receipt models
  gate.py        deterministic capability gate
  executor.py    sandboxed reference executor
  receipt.py       canonical hashing and receipt creation
  review_broker.py trusted one-shot review lease broker
  verifiable.py    Ed25519 envelopes, trust store, attestations, replay ledger
  promotion.py       registry delta + signed PRSP promotion gate
  appliance.py       permits, IPC, replay ledger, appliance initialization
  appliance_services.py process-specific planner/signer/gate/executor/verifier services
  appliance_demo.py  five-process reference demo
  runtime.py         in-process reference gate -> execute -> receipt path
  cli.py             local demos, appliance services, and maintainer command
schemas/         transport contracts
examples/        small capability/request examples
integrations/    Foundry/PRSP/CHD/DRM/LCA/GitHub boundary notes
examples/        capability examples plus a 35-repository maintainer snapshot
tests/           regression tests for safety and application-profile invariants
```

## Roadmap

### v0.1 — deterministic local boundary
Capability registry, gate, sandboxed reference executor, hash receipts, tests.

### v0.2 — ecosystem contracts + adapter boundary
Freeze component responsibilities in `ARCHITECTURE.md` and `component_manifest.yaml`, then add Foundry/MCCP/LPTM/DDA transport contracts and first read-only adapters. No credentials in the model process.

### v0.3 — cognitive safety contract
Add LoPAS-CHD as a replaceable pre-deliberation and post-execution hazard monitor. CHD may restrict or reroute cognition but never create authority.

### v0.4 — decision and learning contracts
Integrate LoPAS-DRM as the decision/responsibility contract layer and LoPAS-LCA as the learning-claim gate. Resolve the DDA naming collision locally by calling DRM's dependency function `DDM` while retaining `LoPAS-DDA` for Deliberative Decision Architecture. Add machine-readable Decision Contract and Learning Claim/Validation schemas.

### v0.5 — Repo Maintainer Agent
Observe a normalized GitHub repository snapshot, deterministically select at most three maintenance candidates, emit a Maintenance Receipt, and route any proposed GitHub mutation through the capability gate.

### v0.6 — review broker
Human approval leases bound to the exact request digest, with expiration, one-shot scope, explicit cancellation, replay prevention, review-event receipts, and no DENY override.

### v0.7 — signed receipts & verifiable capability
Implemented: Ed25519 signed envelopes for capability registries, one-shot review leases, and action receipts; trust-role verification; independent chain verification; tamper detection; and SQLite replay protection across runtime restarts.

### v0.8 — PRSP promotion gate
Implemented: deterministic capability-registry deltas, exact PromotionRequest digests, signed PRSP evidence, independent gate recomputation, required-domain coverage checks, and non-authoritative PASS/REVIEW/HOLD/REJECT promotion decisions.

### v0.9 — appliance profile
Separate OS identities for planner/gate/executor and a low-cost mini-PC reference deployment.
