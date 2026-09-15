# MCP Inbound Adapter - v1.2

The MCP server is an **inbound adapter** to Autonomy Harbor. It is not an
Executor and it is not an authority surface.

```text
Claude / GPT / Gemini / local model / MCP host
                    |
                    v
              MCP Inbound Adapter
                    |
                    v
                  Planner
                    |
                    v
                   Gate
              / REVIEW | ALLOW \
             /         |         \
       stop here       |      signed ExecutionPermit
                        |              |
                        |              v
                        |           Executor
                        |              |
                        |       Execution Adapter
                        |      (GitHub / Sandbox / ...)
                        |              |
                        |              v
                        +----------> Verifier
                                       |
                                       v
                                  signed Receipt
```

## Core invariants

- **MCP != Authority**
- MCP cannot issue or cancel review leases.
- MCP cannot mutate the Capability Registry, Trust Store, or signer roles.
- MCP does not receive a tool argument that can choose the audit `actor`.
  The operator sets `PAR_MCP_ACTOR`; the model cannot impersonate a human by
  supplying `actor="human:owner"`.
- External execution occurs only after the Gate issues a signed, exact-request,
  short-lived, one-shot `ExecutionPermit`.
- The MCP process does not load the review-signer private key.
- A pre-existing **signed** review lease may be passed as data. The Gate still
  independently verifies signer role, exact request digest, scope, expiry, and replay state.
- Adapter availability and MCP tool availability never create a capability grant.

## Why this differs from the original MCP draft

The first draft called `PersonalAgentRuntime.run()` directly. v1.2 instead
connects to the v1.1 Appliance services so MCP cannot become an alternate path
around the process-separated Gate/Permit/Executor boundary.

`REVIEW` also no longer accepts a bare `review_lease_id`. The appliance profile
uses cryptographically signed Review Leases. Lease issuance stays on the
separate human control plane.

## Requirements

Initialize an appliance and start its services first:

```bash
par-runtime appliance-init .par-appliance

par-runtime appliance-service --role planner --profile .par-appliance/config/appliance_profile.json
par-runtime appliance-service --role review_signer --profile .par-appliance/config/appliance_profile.json
par-runtime appliance-service --role gate --profile .par-appliance/config/appliance_profile.json
par-runtime appliance-service --role executor --profile .par-appliance/config/appliance_profile.json
par-runtime appliance-service --role verifier --profile .par-appliance/config/appliance_profile.json
```

For a real deployment, run these as separate services/users. In particular,
the MCP process should not have filesystem or socket permission to the Review
Signer private key/control surface merely because the reference developer
profile stores everything under one directory.

## Install

The MCP dependency is optional:

```bash
pip install -e ".[mcp]"
```

The project uses the current MCP Python SDK v2 API (`MCPServer`).

## Run

```bash
PAR_MCP_APPLIANCE_PROFILE=.par-appliance/config/appliance_profile.json \
PAR_MCP_ACTOR=mcp-agent \
par-mcp
```

The default transport is stdio.

Optional variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PAR_MCP_APPLIANCE_PROFILE` | `.par-appliance/config/appliance_profile.json` | Existing Harbor appliance profile |
| `PAR_MCP_ACTOR` | `mcp-agent` | Operator-controlled audit identity |
| `PAR_MCP_RECEIPTS_LOG` | `.par-appliance/state/mcp/finalized_receipts.jsonl` | Local mirror of finalized verified receipts |

## MCP tools

### `list_capability_grants`

Read-only view of the active registry. Knowing a grant does not grant it.

### `check_capability`

Local dry-run of the deterministic Capability Gate. It does not issue an
ExecutionPermit and does not execute anything.

### `submit_action_request`

Converts a tool call into an ActionRequest and sends it through:

```text
Planner -> Gate -> ExecutionPermit -> Executor -> Adapter -> Verifier
```

- `DENY`: stop; nothing executes.
- `REVIEW`: stop; nothing executes unless a separately issued signed review
  lease is presented on a later exact request.
- `ALLOW`: Gate signs a one-shot permit; Executor verifies/consumes it before
  dispatch; Verifier independently finalizes the signed receipt.

### `list_receipts` / `get_receipt`

These expose only **finalized verified action receipts** mirrored after the
Verifier succeeds. REVIEW and DENY attempts do not pretend to be final action
receipts in this log.

## Client configuration example

```json
{
  "mcpServers": {
    "autonomy-harbor": {
      "command": "par-mcp",
      "env": {
        "PAR_MCP_APPLIANCE_PROFILE": "/absolute/path/.par-appliance/config/appliance_profile.json",
        "PAR_MCP_ACTOR": "claude-desktop"
      }
    }
  }
}
```

## Security note

The reference profile proves the architecture and protocol boundaries; it is
not a production isolation proof. A process running under the same privileged
OS identity may be able to reach files/sockets that the Python API does not
expose. Production deployment still needs OS ACLs/service users, least-
privilege provider credentials, protected key custody, trusted time, and
rollback-resistant state where required.
