# LoPAS-DRM integration contract

## Runtime role

DRM produces a **Decision Contract** before Deliberative DDA and before the authority boundary.

Runtime terminology resolves the upstream DDA naming collision as follows:

- `LoPAS-DRM` upstream DDA: **Decision Dependency Architecture**
- Personal Agent Runtime alias: **DDM — Decision Dependency Mapper**
- `LoPAS-DDA`: **Deliberative Decision Architecture**

This is a local vocabulary rule only.

## Required invariants

1. MCCP context visibility is not authority.
2. A dependency marked satisfied is not authority.
3. `[Human-App]` is a responsibility/approval stamp, not a capability token.
4. `[Auto-Exec]` is valid only when the independent Capability Gate also returns `ALLOW`.
5. DRM cannot write the Capability Registry, credential store, DENY rules, or gate policy.

## Handoff

```text
MCCP -> DDM -> RNC -> decision_contract.json -> Deliberative DDA
```

The runtime transport contract is `schemas/decision_contract.schema.json`.
