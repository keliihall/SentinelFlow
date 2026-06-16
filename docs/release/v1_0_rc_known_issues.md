# SentinelFlow v1.0-rc Known Issues

Generated: 2026-06-15T05:13:31Z

This register classifies unresolved items after the v1.0-rc release gate. The
classification is scoped to a controlled single-node pilot with trusted
operators, safe plugins, synthetic examples, and no public target execution.

## Release Blockers

None for the controlled v1.0-rc pilot scope.

If the scope changes to broad production, public network exposure, untrusted
operators, or real security validation targets, the Known Issues below must be
re-reviewed and several should become blockers.

## Known Issues

| ID | Severity | Issue | Pilot Mitigation | Next Required Action |
| --- | --- | --- | --- | --- |
| KI-01 | High | API still contains some application orchestration glue and calls CLI/Core paths instead of a clean shared Core service facade. | Keep CLI/API/Web consistency E2E as a release gate; do not add duplicate API business logic. | Introduce a shared application service layer used by CLI and API. |
| KI-02 | High | Policy gates are strong for task execution, but not every read/export/report visibility path has a dedicated shared policy preflight. | Restrict pilot to trusted operators and local/private workspaces; keep API RBAC and report redaction enabled. | Add central operation-level policy checks for report/export/audit visibility. |
| KI-03 | High | SSE log streaming accepts a bearer-like token in the URL query because browser `EventSource` cannot set Authorization headers. | Use only local/private trusted deployments; avoid reverse proxy access logs that record query strings; do not expose the API publicly. | Replace query tokens with short-lived stream tickets or cookie-backed sessions. |
| KI-04 | High | Report/export redaction exists, but a full sensitivity classification gate before persistence/export is not complete. | Use synthetic data and safe examples only; do not import real secrets or production evidence. | Add sensitivity labels and redaction policy before persistence and rendering/export. |
| KI-05 | Medium | OpenAPI is useful but not release-grade for every schema, standard error, SSE detail, and role requirement. | Treat docs and E2E tests as the source of truth for pilot users. | Expand OpenAPI request/response schemas and add route-to-spec tests. |
| KI-06 | Medium | Development identity provider uses static local tokens and needs stronger non-local startup guardrails. | Use only local/private trials; do not bind demo auth to public interfaces. | Require explicit production-like auth config for non-local binding. |
| KI-07 | Medium | Scheduler concurrency and rate-limit state is process-local and not crash-proof. | Run a single API process per workspace; keep pilot workloads low and backed up. | Persist recovery state and add restart/recovery tests. |
| KI-08 | Medium | Docker runtime image is not yet optimized or hardened as a final production image. | Use it for local single-node trials only; mount volumes as documented and keep host controls in place. | Slim the image, run as non-root, and add container smoke coverage. |

## Deferred Items

| ID | Item | Reason Deferred |
| --- | --- | --- |
| D-01 | Browser-level Web automation with stable selectors | API-backed Web workflow is covered by full-flow E2E, but a real browser suite is still a polish item. |
| D-02 | `result normalize` user-facing implementation | Not required for the current safe trial flow; normalizer is exercised through `tool run` and `task run`. |
| D-03 | Full standard error matrix across every endpoint | Core error codes and key API/CLI negative paths are tested; exhaustive matrix can follow in hardening. |
| D-04 | Release docs consolidation into a single index | Current docs are linked from README and release docs; structure can be simplified later. |
| D-05 | Web testability hooks for every control | Not needed for current API-backed E2E, useful for future browser automation. |
| D-06 | PostgreSQL runtime backend | Documented as reserved/not active in v1.0-rc to avoid silent fallback. |

## Resolved During P5.5

| Item | Evidence |
| --- | --- |
| CLI/API/Web consistency release gate | `tests/e2e/p5_5_consistency.sh`, `docs/release/p5_5_consistency_report.md` |
| Full API/Web/CLI business loop | `tests/e2e/p5_5_full_flow/run.sh`, `docs/release/p5_5_e2e_report.md` |
| Security hardening coverage | `tests/e2e/p5_5_security/run.sh`, `docs/release/p5_5_security_hardening_report.md` |
| Reliability and exception coverage | `tests/e2e/p5_5_reliability/run.sh`, `docs/release/p5_5_reliability_report.md` |
| Deployment and migration validation | `tests/e2e/p5_5_deployment/run.sh`, `docs/release/p5_5_deployment_report.md` |
| Documentation usability | `docs/release/p5_5_docs_usability_report.md` |
| Performance baseline | `tests/performance/run.sh`, `docs/release/p5_5_performance_baseline_metrics.json` |

## Risk Acceptance

For v1.0-rc controlled pilot, the Known Issues are accepted only under these
conditions:

- Deployment remains local or private and operated by trusted users.
- Demo static tokens are not exposed on a public network.
- Only safe example plugins and internally reviewed mock plugins are installed.
- High-risk mock tasks require approval.
- Audit, Policy, Schema validation, Normalizer, and report redaction remain
  enabled.
- Real credentials, public targets, production addresses, and real attack
  capabilities are not used.

If any condition cannot be met, the release should be treated as not releasable
until the relevant Known Issues are fixed.
