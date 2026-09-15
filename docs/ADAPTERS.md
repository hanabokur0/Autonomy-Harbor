# Adapter Layer - v1.1

## Core rule

**Adapter != Authority**

An adapter knows how to translate an already-authorized `ActionRequest` into an external operation. It does not decide whether that operation is allowed.

```text
Model / Agent
    -> ActionRequest
    -> Harbor Gate
    -> REVIEW / DENY / ALLOW
    -> signed ExecutionPermit
    -> Executor
    -> Adapter Registry
    -> selected Adapter
    -> External Service
    -> signed Execution Result
    -> Verifier / Receipt
```

The Executor verifies and consumes the signed ExecutionPermit before adapter dispatch. A direct call to the Executor without a permit is rejected. A consumed permit cannot be replayed.

## Adapter manifest

Adapters declare only deterministic dispatch metadata:

- adapter id
- capability
- action
- `authority_effect: NONE`

Adapters do not contain capability grants, review rules, or durable authority.

## Built-in adapters

### SandboxAdapter

Reference local adapter for:

- `tool.echo / echo`
- `filesystem.read / read_text`
- `filesystem.write / write_text`

Filesystem access remains confined to the configured sandbox root.

### GitHubAdapter

v1.1 reference adapter for:

- `github.repo.read / get_repo`
- `github.issue.create / create_issue`

GitHub write credentials are resolved only inside the Executor process from an environment variable. The reference default is:

```text
AUTONOMY_HARBOR_GITHUB_TOKEN
```

The token is not stored in the capability registry, ActionRequest, ExecutionPermit, signed execution result, or receipt.

Example executor adapter configuration:

```json
{
  "adapters": [
    {
      "type": "github",
      "token_env": "AUTONOMY_HARBOR_GITHUB_TOKEN"
    }
  ]
}
```

This configuration makes the API mechanics available. It does **not** authorize GitHub writes. The Capability Registry and Harbor Gate remain the authority source.

## Security boundary

A compromised Executor process can potentially access credentials assigned to that process. Therefore production deployments should use provider-specific least-privilege credentials, short-lived credentials where available, OS isolation, and separate adapter/executor identities when risk warrants it.

Adapter availability must never be interpreted as permission.
