# LoPAS-CHD integration contract

LoPAS-CHD is integrated as a **cognitive hazard monitor**, not as an execution gate and not as a truth-verification oracle.

## Placement

```text
compressed context
  -> phase state
  -> Pre-CHD
  -> DDA
  -> protocol / action proposal
  -> capability gate
  -> execution
  -> receipt
  -> Post-CHD
  -> evidence / compost / learning
```

## Pre-CHD contract

Input may include:

- compressed context from MCCP;
- phase state from LPTM;
- current reasoning/proposal trace;
- declared task/domain;
- uncertainty and missing-evidence markers.

Output is normalized into `cognitive_hazard_signal.schema.json`.

Allowed downstream effects:

- continue;
- contain / reduce scope;
- reframe;
- observe more;
- hold;
- reject the reasoning trajectory.

Forbidden effect:

- granting, widening, or persisting execution authority.

## Post-CHD contract

Post-CHD receives the immutable action Receipt plus observed outcome evidence. It looks for patterns such as:

- claimed success despite contradictory evidence;
- repeated reasoning drift;
- failure propagation across layers;
- brittle recovery behavior;
- unexpected emergent effects.

A post-execution hazard may create an evidence item, a compost trace, or a Foundry protocol candidate. It cannot rewrite the receipt or capability registry.

## Hard invariants

```text
CHD SAFE != permission
CHD risk != proof of falsehood
CHD output != credential
CHD output != capability grant
CHD may restrict/reroute, never expand authority
```

The runtime therefore remains safe if CHD is disabled, replaced, or wrong: the deterministic capability gate is still the execution trust boundary.
