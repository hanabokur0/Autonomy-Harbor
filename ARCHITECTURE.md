# Personal Agent Runtime — Ecosystem Architecture

## Purpose

This document fixes the current LoPAS-derived architecture around `personal-agent-runtime` without merging every repository into one monolith.

The runtime is intentionally narrow:

> Intelligence may propose, learn, reframe, and compile protocols. Authority remains outside the intelligence plane.

Existing repositories are treated as independently testable components connected by explicit contracts.

---

## End-to-end loop

```text
REALITY / EXTERNAL STREAMS
        |
        v
+-----------------------------+
| Observation                 |
| Meta-Observer               |
| "what is happening?"        |
+--------------+--------------+
               |
               v
+-----------------------------+
| Context Entry               |
| LoPAS-MCCP                  |
| DoQ -> L-Tag -> min context |
+--------------+--------------+
               |
               v
+-----------------------------+
| Phase Sensing               |
| lopas-lptm-minimal          |
| PST / dPST / d2PST / HI2    |
+--------------+--------------+
               |
               v
+-----------------------------+
| Cognitive Hazard Monitor    |
| LoPAS-CHD                   |
| detect / contain / redesign |
+--------------+--------------+
               |
               v
+-----------------------------+
| Decision Contract           |
| LoPAS-DRM                   |
| MCCP + DDM + RNC            |
| dependencies + ownership    |
+--------------+--------------+
               |
               v
+-----------------------------+
| Deliberation                |
| LoPAS-DDA                   |
| (Deliberative DDA)          |
| EXECUTE / PILOT / HOLD      |
| REFRAME / REJECT / OBSERVE  |
+--------------+--------------+
               |
               v
+-----------------------------+
| Protocol Formation          |
| lopas-protocol-foundry      |
| observe -> candidate        |
| simulate -> grade -> shadow |
+--------------+--------------+
               |
               v
+-----------------------------+
| Operating Simulation       |
| classification-simulation  |
| AUTO/REVIEW/HOLD boundaries|
+--------------+--------------+
               |
               v
+============================================================+
||                     TRUST BOUNDARY                        ||
||                                                          ||
||  Personal Agent Runtime                                  ||
||  +--------------------+   +----------------------------+ ||
||  | Capability Registry|-->| Deterministic Policy Gate  | ||
||  +--------------------+   +-------------+--------------+ ||
||                                | REVIEW                   ||
||                                v                          ||
||                       +---------------------+             ||
||                       | Review Broker       |             ||
||                       | one-shot lease only |             ||
||                       +----------+----------+             ||
||                                  | redeemed               ||
||                                  +-----------+            ||
||                                              | ALLOW only ||
||                                           v               ||
||                                  +---------------------+  ||
||                                  | Executor / Adapter  |  ||
||                                  +----------+----------+  ||
||                                             |             ||
||                                             v             ||
||                                  +---------------------+  ||
||                                  | Verify + Receipt    |  ||
||                                  +---------------------+  ||
+============================================================+
               |
               v
          REAL-WORLD EFFECT
               |
               v
+-----------------------------+
| Post-Execution CHD          |
| drift / false success /     |
| collapse propagation check  |
+--------------+--------------+
               |
               v
+-----------------------------+
| Evidence / Reflection       |
| information-compost         |
| trace -> receipt -> pause   |
+--------------+--------------+
               |
               v
+-----------------------------+
| Learning Claim Gate         |
| LoPAS-LCA                   |
| classify != validate        |
+--------------+--------------+
               | validated only
               v
+-----------------------------+
| Slow Structural Learning    |
| ProtocolMemory              |
| delayed/minimal adjustment  |
+--------------+--------------+
               |
               +-------------------------> observation / foundry

Cross-cutting verification/security:
  - MVPL — minimal verification boundary
  - LoPAS-CHD — cognitive hazard monitoring before deliberation and after execution
  - Dynamic Schema Defense — adaptive outer-frame defense (defense in depth)
  - Verifiable Capability Exchange — signed capability / receipt semantics
  - PRSP — production promotion simulation and evidence gate
```

---

## Responsibility rule

No component should silently absorb the responsibility of another component.

| Question | Owner |
|---|---|
| What is happening? | Meta-Observer |
| What context should exist for this task? | MCCP |
| Is the system stable, oscillating, accelerating, or breaking out? | LPTM |
| Is reasoning drifting toward a cognitive hazard or silent collapse? | CHD |
| What conditions and responsibility stamps make a decision structurally valid? | DRM (MCCP + DDM + RNC) |
| Should judgment/action occur now? | Deliberative DDA |
| Can observations become a reusable protocol? | Protocol Foundry |
| Under what operating conditions is automation justified? | Classification Simulation Pack |
| Is the requested capability actually authorized? | Personal Agent Runtime Gate |
| Has a human released this exact REVIEW request for one attempt? | Review Broker |
| Did the action execute and what evidence exists? | Executor + Receipt |
| What should be retained without premature interpretation? | Information Compost |
| Is an apparent learning event a validated structural change? | LCA |
| What may change slowly after repeated validated evidence? | ProtocolMemory |
| Is the artifact ready to be promoted? | PRSP |

---

## CHD position: cognitive safety monitor, not authority

LoPAS-CHD sits between phase sensing and deliberation, with a second observation point after execution.

```text
MCCP -> LPTM -> Pre-CHD -> DRM -> Deliberative DDA -> Foundry -> Runtime -> Receipt -> Post-CHD -> Compost -> LCA
```

Pre-CHD asks whether the current reasoning trajectory shows signs such as silent failure, pattern drift, fragility under stress, or emergent hazard. It may recommend containment, reframing, or safer exploration. Post-CHD compares the resulting receipt and observed outcome against the trajectory that produced the action and can route anomalies back into evidence, compost, or protocol-candidate generation.

CHD is deliberately not a truth oracle. It does not certify factual correctness, and it does not own permission. Its strongest effect is negative or routing-oriented: it may block, hold, reframe, or request more observation. It can never create an ALLOW grant.

```text
CHD: SAFE
DDA: EXECUTE
Capability Gate: DENY
=> DENY

CHD: HAZARD
DDA: HOLD
Capability Gate: ALLOW
=> NO EXECUTION
```

This preserves two independent safety dimensions:

1. **cognitive safety** — should this reasoning trajectory proceed?
2. **authority safety** — is this action actually permitted?

## Review Broker position: one-shot human release, not durable authority

A `REVIEW` result is a non-executing stop. v0.6 adds a trusted Review Broker that can release only the exact reviewed request after explicit human approval.

```text
Gate = REVIEW
   -> human approves exact request
   -> lease(request_digest, capability, action, resource, review_grant_ids, expiry, max_uses=1)
   -> redeem
   -> consume lease BEFORE executor call
   -> one execution attempt
```

The broker cannot rescue a `DENY`. If the underlying policy changes from REVIEW to DENY, no lease can be issued or redeemed to bypass it. A payload change also changes the request digest and invalidates the approval. Expired, cancelled, or already-used leases return to non-executing REVIEW.

This creates a third safety distinction:

```text
cognitive permission  = should we act?
authority permission  = is the capability allowed/reviewable?
human release         = may this exact REVIEW request run once?
```

The lease is not written back into the Capability Registry and does not become a learned permission. v0.7 adds an optional signed-lease path: the Review Broker may live in a separate process and sign the exact lease with Ed25519; the Runtime holds only public trust records and a durable replay ledger.

## v0.7 verifiable evidence boundary

The cryptographic profile adapts the Verifiable Capability Exchange pattern to personal-agent authority. It does **not** make cryptography a new source of ambient permission. Instead, signatures bind identity to exact already-defined authority artifacts.

```text
Capability authority private key      Review issuer private key
        |                                      |
        v                                      v
Signed Capability Registry            Signed one-shot ReviewLease
        |                                      |
        +---------------+----------------------+
                        v
                 Runtime TrustStore
                 (public keys only)
                        |
                        v
                 Capability Gate
                        |
                        v
                     Execute
                        |
                        v
              Signed Action Receipt
                        |
                        v
              Independent Verifier
```

Three signer roles are intentionally separate:

- `capability_authority` — attests an exact Capability Registry snapshot;
- `review_issuer` — releases one exact REVIEW request for one attempt;
- `runtime_receipt_signer` — attests what the Runtime actually decided and observed.

The Runtime can be configured to require a signed Capability Registry. In that mode, startup fails if the registry payload differs from the trusted attestation. A signature does not add grants outside the signed payload, and a signed review lease still cannot override a current `DENY`.

Signed review redemption uses a SQLite Replay Ledger. Consumption happens before executor invocation and is keyed by both lease identity and envelope hash, so executor failure or Runtime restart does not make the approval reusable.

Signed Action Receipts add a second chain above the existing plain receipt chain:

```text
ActionReceipt hash chain
        +
SignedEnvelope hash chain
```

The first preserves deterministic execution evidence. The second proves signer identity and tamper resistance. Independent verification checks payload hash, envelope hash, signer trust, signer role, signer subject, signature validity, payload type, and chain continuity.

Trust-store membership, trusted public keys, signer-role assignment, and private signing keys are control-plane concerns and are explicitly outside the learning loop. Production deployments should use KMS/HSM-backed keys, rotation/revocation policy, and separately provisioned trust roots.

## Two different gates

A central invariant is that cognitive judgment and authority are separate.

```text
Deliberative DDA verdict: EXECUTE
       |
       v
Capability Gate: DENY
       |
       v
NO EXECUTION
```

DDA may become more capable over time. It still cannot create authority.

Likewise, Protocol Foundry may emit:

```yaml
requires:
  - github.issue.write
```

That declaration means only "this protocol requires this capability." It does not create a grant.

---

## MCCP position: context admission, not retrieval ranking

MCCP runs before large context activation.

```text
Input
  -> DoQ measurement
  -> L-Tag classification
  -> minimum relevant context activation
  -> downstream reasoning
```

This prevents the runtime from treating every task as a reason to load the entire personal archive. Non-active context remains stored but absent from the current cognitive working set.

For a personal runtime this is both an efficiency mechanism and a safety boundary: less context exposed to a planner means less irrelevant or sensitive material available to influence an action proposal.

MCCP must not grant capabilities. Context visibility and execution authority remain separate.

---

## LPTM position: motion-aware observation

LPTM consumes current and historical transition signals and emits phase interpretation such as:

- `stable_or_noise`
- `cob_oscillation`
- `phase_rising`
- `false_peak`
- `breakout`

The important distinction is:

```text
state snapshot != trajectory
```

A high value that is decelerating can be treated differently from a lower value that is rapidly accelerating. HI2-style hysteresis also prevents repeated route flipping near thresholds.

LPTM may influence whether DDA chooses `OBSERVE_MORE`, `PILOT`, or another judgment mode, but it never bypasses the execution gate.

---

## Memory speeds

Not all memory should update at the same speed.

```text
working context      immediate / disposable
execution receipt    immediate / immutable evidence
information compost  delayed interpretation
protocol candidate   evidence-dependent
ProtocolMemory       slow bounded adjustment
permission registry  human/admin controlled only
```

This prevents a single anomalous event from instantly becoming a durable preference, policy, or authority change.

---

## Dynamic Schema Defense position

Dynamic Schema Defense is defense-in-depth around verification and challenge construction.
It is not the root of trust.

```text
Adaptive / changing verification frame
                |
                v
          MVPL verification
                |
                v
       Capability / Policy Gate   <- root execution boundary
```

Randomization, moving schemas, or live anchors may increase attack cost, but cannot substitute for identity, capability grants, cryptographic provenance, revocation, or OS isolation.

---

## Repository strategy

Do **not** merge the ecosystem into one repository.

Preferred structure:

```text
personal-agent-runtime/
  core runtime contracts
  trust boundary
  adapters
  receipts
  component_manifest.yaml

external repositories/
  Meta-Observer
  LoPAS-MCCP
  lopas-lptm-minimal
  LoPAS-DDA
  lopas-protocol-foundry
  classification-simulation-pack
  information-compost
  ProtocolMemory-v0.2
  Dynamic-Schema-Defense
  MVPL-Minimal-Verification-Protocol-Layer
  Verifiable-Capability-Exchange
  production-readiness-simulation-pack
```

Integration should occur through versioned schemas, receipts, adapters, and explicit promotion gates.

---

## Core invariant

> The agent can learn how to do more things without acquiring the right to do more things.

That invariant is the architectural center of the Personal Agent Runtime.


---

## DRM position: decision contract and responsibility, not permission

LoPAS-DRM is treated as the contract layer that packages the minimum active context, decision dependencies, and responsibility stamps before deliberation reaches the execution boundary. The upstream DRM repository uses the name **Decision Dependency Architecture** for its DDA sub-layer. To avoid collision with `LoPAS-DDA` (**Deliberative Decision Architecture**), this runtime vocabulary calls the dependency function **DDM — Decision Dependency Mapper**.

```text
MCCP
  -> DDM (dependency map / root condition / downstream impact)
  -> RNC (AI-Prop / Human-App / Auto-Exec responsibility stamps)
  -> Decision Contract
  -> Deliberative DDA
```

The rename is local terminology only; it does not claim to rename the upstream repository.

A Decision Contract may describe preconditions and ownership. It may not create a capability grant. `[Human-App]` records responsibility/approval state in the decision artifact; it is not equivalent to a runtime authorization token or capability lease.

```text
DRM: [Human-App]
Capability Gate: DENY
=> DENY
```

This prevents accountability metadata from becoming ambient authority.

---

## LCA position: learning-claim gate

LoPAS-LCA separates two claims that must remain distinct:

```text
learning classification != structural validation
```

The runtime uses LCA after post-execution evidence has been retained and before durable structural learning is promoted.

```text
Receipt
  -> Post-CHD
  -> Information Compost
  -> LCP / learning classification
  -> structural validation
       |
       +-> VALIDATED -> Foundry / ProtocolMemory candidate
       +-> UNRESOLVED -> retain / observe more
       +-> REJECTED -> do not promote
```

A failed validation does not automatically mean that no learning signal exists. It may remain unresolved. But unresolved or rejected learning cannot silently mutate durable protocol state.

Most importantly, even validated learning cannot modify authority. LCA may validate a protocol, preference, threshold, routing heuristic, or observation rule; it cannot validate a self-grant.

```text
validated learning
  != capability grant
  != credential scope change
  != deny-rule deletion
```

This creates two independent promotion boundaries:

1. **Learning boundary** — LCA decides whether a learning claim may become a durable learning candidate.
2. **Authority boundary** — Personal Agent Runtime decides whether an action is actually permitted.

PRSP remains a third, deployment-level promotion boundary for production readiness.

## v0.5 application profile: Repo Maintainer Agent

The first concrete application profile is intentionally narrow: maintain the user's repository ecosystem without granting the agent ambient GitHub write access.

```text
GitHub read adapter / exported metadata
          ↓
     Repo Snapshot
          ↓
 Deterministic Repo Maintainer
          ↓
 rank explicit maintenance signals
          ↓
   top 3 candidates only
          ↓
 Maintenance Receipt
          ↓
 optional ActionRequest
 github.issue.create
          ↓
 ===== Runtime Gate =====
          ↓
        REVIEW
          ↓
     human decision
```

The reference scorer uses explicit repository class and maintenance signals such as `runtime_integration_gap`, `spec_only`, `missing_tests`, `missing_adapter`, `production_blocker`, and `legacy`. It does not infer write authority from ranking score, repository importance, model confidence, or responsibility tags.

The observer/scorer path intentionally carries no GitHub write credential. Mutation is a separate path through the runtime trust boundary.

### Bootstrap objective

Given the current 35-repository snapshot, the reference profile returns at most three maintenance candidates with rationale and evidence. A candidate may be turned into a `github.issue.create` ActionRequest, but the default v0.5 capability profile routes issue creation to `REVIEW`. Merge, repository deletion, and permission changes remain `DENY`.

```text
maintenance priority != authorization
review recommendation != approval
repository ownership != agent ownership
```

This is the first end-to-end use of the runtime as a real work system rather than only a control-plane reference.


## v0.8 PRSP capability-promotion boundary

PRSP is a deployment/promotion gate, not an action-time authorization source. v0.8 binds readiness evidence to an exact proposed Capability Registry change.

```text
Current Capability Registry
        ↓
Proposed Capability Registry
        ↓
Deterministic Capability Delta
        ↓
PromotionRequest digest
        ↓
PRSP scenario run / evidence
        ↓
Signed Promotion Evidence
        ↓
PRSPPromotionGate
  REJECT > HOLD > REVIEW > PASS
        ↓
Capability Authority MAY separately attest the proposed registry
```

The Promotion Gate has no registry-mutation API and no capability-authority private key. It only emits an authority-neutral decision.

A signed PRSP receipt is not trusted merely because it declares `overall_gate: PASS`. The Runtime adapter reconstructs the gate from individual scenario results. If the declared and computed gates disagree, the evidence is rejected as internally inconsistent.

For any possible authority expansion, the default profile requires active PRSP evidence coverage in:

- authorization;
- failure;
- observability;
- security.

Missing a required domain yields `HOLD`. `SKIP` does not count as coverage. This prevents a narrow passing scenario set from silently promoting a broader authority surface.

The evidence envelope is signed by a `promotion_evidence_issuer` and contains the exact `PromotionRequest` digest. Therefore evidence generated for one capability delta cannot be replayed against a different proposed registry. The promotion-evidence issuer and capability authority are intentionally separate roles.

```text
PRSP PASS
  != capability grant
  != registry mutation
  != capability-authority signature
  != runtime ALLOW
```

This creates a fourth explicit safety boundary alongside cognition, judgment, learning, and authority: **deployment/promotion safety**.

---

# v0.9 Appliance Profile — Process Isolation

v0.9 changes the trust boundary from a set of Python objects inside one process into a reference multi-process appliance.

```text
+------------------+        ActionRequest        +------------------+
| Planner          | --------------------------> | Gate             |
| no private key   |                             | registry owner   |
+------------------+                             +--------+---------+
                                                          |
                                                   REVIEW | ALLOW
                                                          |
                     +----------------------+             |
                     | Review Signer        |<------------+
                     | human approval key   |             |
                     +----------+-----------+             |
                                | signed review lease      |
                                +------------------------->|
                                                          |
                                              signed ExecutionPermit
                                                          |
                                                          v
                                                +---------+--------+
                                                | Executor         |
                                                | sandbox only     |
                                                +---------+--------+
                                                          |
                                                signed ExecutionResult
                                                          |
                                                          v
                                                +---------+--------+
                                                | Verifier         |
                                                | independent check|
                                                +---------+--------+
                                                          |
                                                signed ActionReceipt
```

## New invariant: raw requests cannot reach execution

Process separation is meaningless if the Planner can bypass the Gate and call the Executor directly. Therefore v0.9 adds an `execution_permit` signed by the Gate. The Executor accepts an action only when all of the following hold:

1. signer has the `execution_permit_issuer` role;
2. signature and envelope hashes verify;
3. request digest, capability, action, resource, actor, and request ID match exactly;
4. permit contains an `ALLOW` gate result;
5. registry ID/version and matched grant IDs are bound into the permit;
6. permit has not expired;
7. `max_uses == 1`;
8. the SQLite permit replay ledger has not already consumed the permit.

The permit is consumed **before** execution. Executor failure does not make it reusable.

## Key separation

```text
Planner        private keys: none
Review Signer  private key:  review approval only
Gate           private key:  execution permits only
Executor       private key:  execution evidence only
Verifier       private key:  final Action Receipts only
```

No role's signature is treated as another role's authority. A signed execution result cannot create a permit; a signed receipt cannot create a capability; a review lease cannot override DENY.

## Host boundary

The reference transport is Unix-domain sockets. `deploy/systemd/` contains hardened unit examples for separate Linux service accounts. These units are examples rather than a production installer. Root/Administrator compromise, trusted time, rollback-proof replay storage, and production KMS/HSM key custody remain outside the v0.9 claim.
