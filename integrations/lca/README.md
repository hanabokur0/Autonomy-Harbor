# LoPAS-LCA integration contract

## Runtime role

LCA is the **learning-claim gate**. It prevents a trace, preference event, failed action, or model assertion from silently becoming durable learning.

```text
Receipt -> Compost -> Learning Classification -> Structural Validation
```

Classification and validation must remain separate artifacts.

## Routes

- `VALIDATED`: may become a Foundry / ProtocolMemory candidate.
- `UNRESOLVED`: retain evidence and observe more; do not promote.
- `REJECTED`: do not promote.

Validation does not grant authority. Even a validated protocol update may only declare required capabilities; it cannot create or widen grants.

## Handoff

Transport contracts:

- `schemas/learning_claim.schema.json`
- `schemas/learning_validation.schema.json`
