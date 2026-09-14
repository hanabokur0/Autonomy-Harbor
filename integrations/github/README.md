# GitHub Repo Maintainer integration — v0.5

v0.5 treats GitHub observation and GitHub mutation as two different trust paths.

## Observation path

A GitHub adapter may collect repository metadata and normalize it into `repo_snapshot.schema.json`.
The reference `RepoMaintainer` consumes that snapshot locally. The scoring engine has no credentials and cannot call GitHub.

```text
GitHub read adapter
  -> Repo Snapshot
  -> deterministic RepoMaintainer
  -> top 3 Maintenance Candidates
  -> Maintenance Receipt
```

## Mutation path

A selected candidate can be converted into an `ActionRequest` for `github.issue.create`.
In the v0.5 default profile this capability is **REVIEW**, not ALLOW. Therefore the Personal Agent Runtime emits a non-executing review receipt. A separate human-approved broker may later execute the GitHub action.

```text
Candidate
  -> ActionRequest(github.issue.create)
  -> Runtime Gate
  -> REVIEW
  -> NOT_EXECUTED
```

The reference runtime does not store a GitHub token and does not implement a GitHub write executor.

## Default authority profile

- repository/issue/commit observation: adapter-side read only
- issue create: REVIEW
- file write: REVIEW
- pull request create: REVIEW
- merge: DENY
- repository delete: DENY
- permission changes: DENY

No maintenance score or model output can change these effects.
