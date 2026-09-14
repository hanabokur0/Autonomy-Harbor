# PRSP Promotion Gate — v0.8 integration

Personal Agent Runtime treats PRSP as an external **promotion evidence generator**, not as an execution authority.

```text
Current signed Capability Registry
        ↓
Proposed Capability Registry
        ↓
Capability Delta
        ↓
PromotionRequest
        ↓
PRSP scenarios / grader
        ↓
Simulation Receipt
        ↓
Signed Promotion Evidence
        ↓
PRSPPromotionGate
  PASS / REVIEW / HOLD / REJECT
        ↓
Capability Authority may decide whether to sign the proposed registry
```

The gate follows PRSP's fail-closed precedence:

```text
REJECT > HOLD > REVIEW > PASS
```

and independently recomputes the overall gate from scenario results instead of trusting the declared `overall_gate` field.

## Mandatory separation

`PASS` means **eligible for promotion consideration**. It does not mutate the registry, mint a capability, sign the proposed registry, or bypass the normal Runtime gate.

For a possible authority expansion, the default v0.8 profile requires non-SKIP evidence coverage in:

- `authorization`
- `failure`
- `observability`
- `security`

Missing coverage produces `HOLD`, not `PASS`.

The PRSP evidence is bound to the exact `PromotionRequest` digest and signed by a trusted key carrying the `promotion_evidence_issuer` role. A receipt for one capability delta cannot be replayed to promote another.

## Compatibility note

The adapter accepts the PRSP v0.1 simulation receipt fields (`receipt_version`, `run_id`, `app_id`, `overall_gate`, `results`) and tolerates the additional result fields emitted by the current PRSP engine. No claim is made that PRSP simulation alone certifies production safety.
