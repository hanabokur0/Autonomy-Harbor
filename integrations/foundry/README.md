# LoPAS Protocol Foundry integration

Foundry remains upstream of authority.

```text
Observation
→ Proxy
→ Protocol Candidate
→ Simulation / Independent Grading
→ Promotion
→ Shadow Execution Plan
→ normalize to ActionRequest
→ Personal Agent Runtime
```

A Foundry protocol may state `requires: [filesystem.read]`. That field is a dependency declaration, not a grant.
The runtime must independently resolve the request against its Capability Registry.

Recommended first adapter contract:

```text
promoted protocol / shadow action
    ↓
FoundryActionAdapter
    ↓
ActionRequest
```

Do not let the adapter copy authority fields from model/protocol output into the registry.
