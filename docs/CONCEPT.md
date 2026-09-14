# Autonomy Harbor — Concept

## Thesis

Autonomous intelligence should be free to observe, reason, propose, and form learning candidates without also owning the authority to act in the world.

Autonomy Harbor separates those two domains.

```text
Autonomous Observer
        ↓
 observe / infer / propose
        ↓
==========================
      AUTONOMY HARBOR
==========================
 identity
 capability declaration
 cognitive / decision gates
 human review when required
 production-readiness evidence
 signed one-shot permit
        ↓
      execution
        ↓
       world
        ↓
 receipt / verification
        ↓
 learning claim / validation
        ↓
Autonomous Observer
```

## The Observer

The observer may be GPT, Claude, Gemini, a local model, a future model, or a composition of models. Models are replaceable intelligence providers.

The observer may learn that an action requires a capability. It may not therefore grant itself that capability.

```text
knowledge != authority
```

## The Harbor

The harbor is the point where autonomous cognition becomes externally consequential action.

Routes are intentionally distinct:

```text
AUTO   = policy permits the exact request
REVIEW = human clearance is required
HOLD   = remain docked pending evidence or resolution
DENY   = departure prohibited
```

Human review is not a universal manual approval loop. Humans own the authority boundary; policy may still allow low-risk actions automatically.

## Departure and return

A granted action leaves the harbor with narrowly scoped authority:

- exact request digest;
- exact capability;
- exact action;
- exact resource;
- short expiry;
- one-shot use where appropriate;
- signed provenance.

On return, the system unloads evidence:

- execution result;
- signed receipt;
- verification state;
- anomaly / CHD signals;
- learning candidates.

A receipt may inform learning. It does not itself change authority.

## Safety separation

```text
CHD            cognitive safety
DDA            judgment safety
LCA            learning safety
Runtime Gate   authority safety
Review Broker  human approval safety
PRSP           promotion safety
```

No one layer substitutes for another.

## Independence

Autonomy Harbor is designed to be:

- **model-independent** — models may be replaced without moving authority state;
- **SaaS-independent** — GitHub, mail, browsers, and other services are capability providers, not the agent's home;
- **OS-portable in architecture** — Linux is the current reference appliance, but the authority contracts are not Linux-specific;
- **local-first** — personal state, receipts, capability policy, and learning history can remain under user control.

The OS still provides the final enforcement substrate. OS-independence here means the authority model is portable, not that the runtime can exist without an operating system.

## One sentence

> **Observe freely. Act through authority. Return with evidence.**

An even shorter form:

> **Intelligence may roam. Authority stays home.**
