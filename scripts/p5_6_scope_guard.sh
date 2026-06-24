#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

node <<'NODE'
"use strict";

const assert = require("node:assert/strict");
const Simple = require("./crates/sentinelflow-api/web/simple-check.js");

function build(domain, mode = "quick") {
  return Simple.buildSimpleCheckTaskSpec(
    {domain, mode, authorizationConfirmed: true},
    {timestamp: "20260624000000", operator: "p5_6_scope_guard"}
  );
}

function textOf(task) {
  return JSON.stringify(task).toLowerCase();
}

for (const domain of Simple.P5_6_FIXTURE_TARGETS) {
  const task = build(domain);
  const text = textOf(task);
  assert.equal(task.spec.authorizationScope, "fixture:local-only");
  assert.equal(task.spec.targets[0].input.target.value, domain);
  assert.equal(task.spec.targets[0].input.target.metadata.fixture, true);
  assert.equal(task.spec.targets[0].input.target.metadata.p5_6_status, "fixture-only");
  assert.equal(task.spec.steps.length, 1);
  assert.equal(task.spec.steps[0].toolRef, "example-echo");
  assert.equal(task.spec.steps[0].capability, "echo");
  assert.equal(task.extensions["sentinelflow.io/web-console"].allowActiveVerify, false);
  assert.match(text, /fixture:local-only/);
  assert.match(text, /p5_6_fixture_quick_run/);
  assert.match(text, /fixture-only/);
  for (const token of Simple.P5_6_FORBIDDEN_MARKERS) {
    assert.equal(text.includes(String(token).toLowerCase()), false, `forbidden P5.6 token leaked: ${token}`);
  }
  assert.equal(Simple.assertP56FixtureOnlyTaskSpec(task), true);
}

for (const domain of ["weikan.net.cn", "company.com", "internal.corp", "customer.invalid"]) {
  assert.throws(
    () => build(domain),
    /P5\.6 quick run only supports local fixtures/
  );
}

for (const mode of ["standard", "deep"]) {
  assert.throws(
    () => build("example.com", mode),
    /disabled until P7/
  );
}

console.log(JSON.stringify({
  status: "ok",
  gate: "P56-G10",
  allowedTargets: Simple.P5_6_FIXTURE_TARGETS,
  toolRef: "example-echo"
}, null, 2));
NODE
