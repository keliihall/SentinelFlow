# SentinelFlow Security Boundary

## P3 Adapter Boundary

Command, Docker, HTTP, and File Import all enter through shared Policy and Audit
boundaries, then pass through a trusted Parser and the Normalizer. Adapter
selection cannot bypass those controls.

Docker defaults to no network and bounded resources. HTTP authentication values
must use environment-backed `secretRef` declarations; sensitive literal headers
are rejected. File Import accepts bounded request content and never follows a
caller-provided path. The Python SDK is an out-of-process protocol helper and
does not load untrusted Python or native libraries into Core.

## Purpose

SentinelFlow manages external security validation tools under explicit policy,
execution, output, and audit controls. It does not provide native scanning,
exploitation, credential attacks, persistence, stealth probing, authentication
bypass, or automated attack chains.

## DAG and Approval Boundary

Planning never executes tools and rejects malformed graphs before scheduling.
Downstream nodes consume only Schema-validated normalized output, never raw
stdout. Every node independently re-enters Policy and Audit boundaries.

High and critical risk remain denied without an approved request. Approval
records are bound to the Task name and may transition only once. Resume uses
persisted Task Spec and Plan snapshots, so source YAML edits cannot alter an
active task.

## API and Web Console Boundary

The Web Console is an API client only. Browser code must not start adapters,
invoke runners, load plugin code, read workspace artifacts directly, or duplicate
Policy decisions. It may submit requests only to the API service.

The API service authenticates each protected request through a replaceable
identity provider and applies RBAC before reaching workspace operations. Mutating
plugin, task, report, approval, and policy-inspection operations write Audit
Events. Task execution through the API reuses the existing SentinelFlow
orchestration path; it must not create a second tool runner in the Web layer.

Real-time task logs are exposed as server-sent audit events with reconnect
cursors. A reconnect cursor only resumes viewing persisted audit data; it does
not grant new execution authority or bypass RBAC.

## Default Deny

Every operation that can cause an external tool to execute must be denied unless a
policy decision explicitly authorizes it. Missing policy, incomplete context,
unknown capability, invalid input, unsupported adapter, and failed validation are
denial conditions.

No delivery layer may bypass this rule. CLI, API, and future interfaces must invoke
the same Core-controlled policy path.

## Authorization Boundary

Authorization is evaluated before execution. A decision must bind the requested
tool, declared capability, adapter, normalized arguments, execution context, and
applicable constraints. Authorization for one request must not be reused for a
different request.

All critical actions and decisions must produce Audit Events, including registration,
policy evaluation, execution lifecycle changes, output validation, normalization,
task cancellation requests, and failures. Audit failures must not silently permit
execution.

## Plugin Isolation

Tools enter SentinelFlow only through declared Manifest, Adapter, and Parser
contracts. A new tool must not require Core changes.

Untrusted plugin code must never be loaded as an in-process dynamic library. The
initial implementation permits only separately managed operating-system processes;
container isolation may be added in a later phase. Process execution must eventually
apply explicit executable, argument, environment, working-directory, timeout,
resource, and output controls.

Plugin discovery and installation reject symbolic links, parent path traversal,
absolute dependency paths, unsupported runtime modes, and unsafe install names.
Discovery or registration never executes runner or parser content.

The Command Adapter never invokes a shell. It uses a canonical runner path and fixed
argument array, clears the child environment, applies a Manifest allowlist, uses an
isolated temporary working directory, bounds combined output, enforces timeout and
cancellation, and terminates the child process group. Only JSON output that passes
the declared output Schema is returned; stderr and invalid raw output are discarded.

Policy permits execution only for explicitly allowlisted repository example
plugins carrying the repository example label, plus generated scaffold fixtures.
The example catalog is limited to local, synthetic, bounded fixtures, including
echo, mock DNS, file import, adapter contracts, approval, failure, delay, and
invalid-parser negative tests. Other registered tools remain discoverable but
cannot execute.

Task execution is also default deny. Every target name must appear in the Task
Spec's `policy.allowedTargets`; one authorized target does not authorize another.
P2-4 permits exactly one step and runs it independently for each target.

## Input and Output Boundary

Manifest and task inputs are untrusted. They must be validated against versioned
schemas before use. Tool output is also untrusted and must pass Parser, Schema
validation, and Normalizer stages before it can be stored, reported, or consumed by
other components.

Raw tool output must not be treated as a trusted SentinelFlow result.
It is held only long enough for the trusted Parser invocation. Only normalized
protocol resources and non-sensitive structured evidence may be persisted. Reports
and exports read normalized artifacts rather than runner output.

## Prohibited Capabilities

The repository must not contain or implement:

- Real scanners or exploit implementations
- Weak-password or credential brute force
- Persistence mechanisms
- Covert or stealth probing
- Authentication or authorization bypass
- Automated attack-chain execution
- Real targets, credentials, secrets, or operational attack payloads

Tests and examples must use synthetic, non-sensitive data and isolated local
environments. Any future capability outside this boundary requires explicit project
authorization and a new security review; it is not implicitly allowed by an adapter
interface.

`example-dns-resolve` uses only an embedded mock table with documentation-range
addresses and never performs DNS or network access. `example-file-import` accepts
bounded structured records over stdin and never opens an arbitrary host path.

## Failure Handling

Security-relevant failures use the project's standard error model once introduced.
Production paths must not rely on panics for expected errors. Ambiguous state,
validation failure, policy failure, isolation failure, and audit failure must resolve
to a denied or failed operation.
