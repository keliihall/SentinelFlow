# SentinelFlow P5.6 Scope

- Phase: P5.6 architecture convergence and quality hardening
- Baseline date: 2026-06-18
- Applies to: all P5.6 implementation and acceptance tasks

## Objective

P5.6 turns the v1.0-rc codebase into a trustworthy refactoring baseline. It
converges delivery-layer boundaries, strengthens regression coverage, and
improves the existing Web product experience without expanding SentinelFlow
into a scanner or internet asset-discovery product.

## In Scope

- Converge CLI and API on shared application/Core services.
- Remove duplicated orchestration, Policy, Audit, normalization, and report
  behavior from delivery layers.
- Preserve the Manifest + Adapter + Parser integration contract.
- Strengthen Schema validation, default-deny Policy, Approval, Audit Event,
  Normalizer, report redaction, and standard-error coverage.
- Add CLI/API/Web consistency and Web smoke regression gates.
- Improve Web usability, accessibility, testability, and API-backed product
  workflows.
- Clarify crate ownership, dependency direction, documentation, and release
  evidence.
- Refactor internally while preserving documented external behavior.

## Explicitly Out of Scope

**P7 之前不实现真实资产发现和真实扫描。**

P5.6 therefore does not add or expand:

- Real internet asset discovery, public-domain enumeration, or public-IP
  discovery.
- Real active scanning, broad port scanning, vulnerability scanning,
  exploitation, brute force, stealth probing, authentication bypass,
  persistence, or attack-chain automation.
- New Web entry points that turn a user-supplied real target into the above
  capabilities.
- Production distributed scheduling, multi-node workers, a plugin marketplace,
  AI finding analysis, or a PostgreSQL runtime backend.

Existing fixture, import, mock, and bounded validation paths may remain for
compatibility during P5.6, but they must not be expanded or claimed as P5.6
delivery of real asset discovery or real scanning. Any current real-target or
active-verification path requires an explicit scope review before release and
must remain default-deny.

## Architecture Constraints

1. The product name is `SentinelFlow`; the CLI binary is `sentinelflow`.
2. Local state remains under `.sentinelflow/`; protocol resources use
   `sentinelflow.io`.
3. Tools enter through Manifest + Adapter + Parser. Adding a tool must not
   modify Core.
4. Every execution passes Policy before process or network activity.
5. Every critical action emits an Audit Event.
6. Only Schema-validated, normalized output may be persisted or reported.
7. Untrusted plugins run out of process; no untrusted in-process dynamic
   libraries are allowed.
8. Web and API are delivery layers. They must reuse shared behavior rather than
   reimplementing Core logic.
9. Security boundaries default to deny and errors use the standard error model.

## Change Control

A P5.6 task is acceptable only when it:

- stays within this scope;
- includes tests, documentation, and runnable acceptance commands;
- passes `scripts/p5_6_gates.sh`;
- records any intentional external behavior, protocol, CLI, or database change;
- does not silently weaken Policy, Audit, Approval, Schema, Normalizer, or
  redaction enforcement.

Any proposal that introduces real asset discovery or real scanning is a P7
scope proposal and must not be implemented as P5.6 work.
