#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const Simple = require("../crates/sentinelflow-api/web/simple-check.js");

const REQUIRED_FIXTURE_MARKERS = [
  "fixture:local-only",
  "p5_6_fixture_quick_run",
  "fixture-only"
];

const FORBIDDEN_TASKSPEC_TOKENS = [
  "real:",
  "weikan.net.cn",
  "public_resolver",
  "1.1.1.1",
  "8.8.8.8",
  "tcp_connect",
  "fofa",
  "shodan",
  "censys",
  "crtsh",
  "virustotal",
  "active_dns",
  "active_resolver",
  "active_verify",
  "authorized-asset-discovery",
  "authorized_assessment",
  "port-probe-plus",
  "service-detect-plus",
  "dns-resolve-plus",
  "subdomain-discovery-plus",
  "tcp_banner",
  "tls_hello",
  "http_head",
  "http_get_root"
];

const task = Simple.buildSimpleCheckTaskSpec(
  {domain: "example.com", mode: "quick", authorizationConfirmed: true},
  {timestamp: "20260624000000", operator: "p5_6_scope_guard"}
);
const text = JSON.stringify(task).toLowerCase();

for (const marker of REQUIRED_FIXTURE_MARKERS) {
  assert.equal(text.includes(marker), true, `missing P5.6 fixture marker: ${marker}`);
}

for (const token of FORBIDDEN_TASKSPEC_TOKENS) {
  assert.equal(text.includes(token.toLowerCase()), false, `forbidden P7 token leaked: ${token}`);
}

assert.equal(task.spec.authorizationScope, "fixture:local-only");
assert.equal(task.metadata.labels.purpose, "p5_6_fixture_quick_run");
assert.equal(task.metadata.labels.p5_6_status, "fixture-only");
assert.equal(task.spec.targets[0].input.target.value, "example.com");
assert.equal(task.spec.targets[0].input.target.metadata.fixture, true);
assert.equal(task.spec.targets[0].input.target.metadata.p5_6_status, "fixture-only");
assert.equal(task.spec.steps[0].toolRef, "example-echo");
assert.equal(task.extensions["sentinelflow.io/web-console"].allowActiveVerify, false);
assert.equal(task.extensions["sentinelflow.io/web-console"].allowHighRisk, false);
assert.equal(Simple.assertP56FixtureOnlyTaskSpec(task), true);

console.log(JSON.stringify({
  status: "ok",
  gate: "P56-G10",
  target: "example.com",
  authorizationScope: task.spec.authorizationScope,
  toolRef: task.spec.steps[0].toolRef,
  forbiddenTokenMatches: []
}, null, 2));
