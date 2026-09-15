# MCP integration - v1.2

Role: **Inbound Adapter**.

MCP translates model/tool requests into Harbor `ActionRequest` proposals. It
does not execute provider APIs itself and it does not own authority.

```text
MCP host -> MCP Inbound Adapter -> Planner -> Gate -> Permit -> Executor -> Execution Adapter
```

The MCP server intentionally excludes:

- review-lease issuance/cancellation;
- capability-registry mutation/promotion;
- signer/trust-store management;
- provider credentials;
- direct Executor calls without a Gate permit.

The audit actor is operator-configured (`PAR_MCP_ACTOR`), not supplied by the
model as a tool argument.

See `docs/MCP.md` for setup and security boundaries.
