# GitHub Adapter - v1.1

The GitHub integration now includes an executor-side reference adapter.

## Authority model

```text
GitHub capability knowledge != GitHub authority
Adapter availability          != permission
GitHub token possession       != Gate ALLOW
```

The GitHub adapter translates an already-authorized request into GitHub API mechanics. It cannot issue an ExecutionPermit or alter the Capability Registry.

## Supported bindings

- `github.repo.read / get_repo`
- `github.issue.create / create_issue`

The resource is normalized as:

```text
owner/repository
```

Issue creation accepts `title`, optional `body`, optional `labels`, and optional `assignees` in the request payload.

## Credential path

The adapter resolves the token inside the Executor process from `AUTONOMY_HARBOR_GITHUB_TOKEN` by default. The token is never placed in an ActionRequest, ExecutionPermit, execution result, or receipt.

## Reference flow

```text
Candidate
  -> ActionRequest(github.issue.create)
  -> Runtime Gate
  -> REVIEW
  -> signed human ReviewLease
  -> Gate ALLOW
  -> signed one-shot ExecutionPermit
  -> Executor verifies + consumes permit
  -> GitHubAdapter.create_issue()
  -> signed ExecutionResult
  -> Verifier
  -> signed Receipt
```

Default policy should keep issue creation and other GitHub mutations at REVIEW unless the human authority explicitly chooses a narrower AUTO profile. Merge, repository deletion, and permission changes remain DENY in the reference policy.
