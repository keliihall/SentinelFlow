# SentinelFlow Codex Workflow

Codex must not claim completion unless all evidence checks pass.

## Delivery Rules

Every SentinelFlow Codex task must first confirm:

- branch
- HEAD
- origin/main
- git status
- allowed files

Every task must only modify files explicitly allowed by the task contract.

Every task must run the required local commands before delivery.

Every task must commit and push to `origin/main` with the exact required commit message.

After push, every task must run:

- `git fetch origin main`
- `git rev-parse HEAD`
- `git rev-parse origin/main`
- confirm `HEAD == origin/main`

Every task must use `git show origin/main:<path>` to inspect the real file contents on remote `main`.

Every task must wait for GitHub Actions:

- `gh run list --branch main --limit 5`
- `gh run watch <run-id> --exit-status`
- `gh run view <run-id> --json status,conclusion,headSha,workflowName,url`

Codex may only declare completion when the GitHub Actions run has `conclusion == success` and `headSha == HEAD`.

## Completion Substitutes Are Forbidden

The following must never be used as completion evidence:

- local pass only
- commit title only
- README updates
- old CI success records
- unpushed local changes
- changes on another branch

## Security Boundary

- Do not add real scanning, probing, exploitation, brute force, bypass, stealth, persistence, or attack-chain capability.
- P5.6 does not allow real asset discovery or real scanning.
- Web Quick Run must be fixture-only.
