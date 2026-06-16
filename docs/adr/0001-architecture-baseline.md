# ADR 0001: Architecture Baseline

- Status: Accepted
- Date: 2026-06-14

## Context

SentinelFlow is a management framework for external security validation tools. It is
not a scanner, exploit framework, or attack platform. The project needs a stable
engineering baseline before protocol or execution behavior is implemented.

P0 establishes package boundaries, shared identifiers, quality gates, documentation,
and security constraints without implementing business capabilities.

## Decision

SentinelFlow uses a Cargo workspace with Rust 2024 edition, a minimum supported Rust
version of 1.85, and resolver version 2.

The workspace contains the following crates:

| Crate | Baseline responsibility |
| --- | --- |
| `sentinelflow-cli` | CLI delivery layer and the `sentinelflow` binary |
| `sentinelflow-core` | Shared foundations and canonical product constants |
| `sentinelflow-schema` | Protocol schema types and validation boundaries |
| `sentinelflow-runtime` | Controlled out-of-process execution abstractions |
| `sentinelflow-registry` | Manifest-based tool discovery and registration |
| `sentinelflow-adapter-command` | Command Adapter implementation boundary |
| `sentinelflow-store` | Persistence abstractions |
| `sentinelflow-policy` | Authorization and policy enforcement |
| `sentinelflow-report` | Normalized reporting abstractions |
| `sentinelflow-orchestrator` | Task coordination using Core contracts |
| `sentinelflow-api` | API delivery layer that reuses Core behavior |

The canonical identifiers live in `sentinelflow-core::constants`:

- Product name: `SentinelFlow`
- CLI binary: `sentinelflow`
- Local workspace directory: `.sentinelflow`
- Protocol API group: `sentinelflow.io`
- Environment variable prefix: `SENTINELFLOW_`

All crates inherit workspace package metadata and lint configuration. Unsafe Rust is
forbidden. Formatting, build, tests, and Clippy are required CI gates.

## Dependency Direction

Delivery layers such as CLI and API may depend on Core-facing abstractions. They must
not reimplement policy, execution, normalization, or audit behavior.

Tool integrations are introduced through Manifest, Adapter, and Parser contracts.
Adding a tool must not require modification of Core. Untrusted plugins are never
loaded as in-process dynamic libraries.

The precise dependency graph will be introduced with the contracts that justify each
edge. P0 deliberately adds only the CLI-to-Core dependency needed to prove shared
constant reuse.

## Consequences

- Crate ownership boundaries exist before feature work begins.
- Product identifiers cannot silently diverge between components.
- CI rejects formatting, compilation, test, and lint regressions.
- Empty crates provide extension points without prematurely fixing internal APIs.
- Later milestones must record material protocol, CLI, persistence, and architecture
  changes in documentation and, when appropriate, additional ADRs.

## Non-Goals

P0 does not define protocol resources, CLI commands, database schemas, plugin
discovery, process execution, orchestration, API endpoints, scanners, exploits, or
other security validation behavior.

