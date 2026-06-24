#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const SimpleCheck = require("../crates/sentinelflow-api/web/simple-check.js");

const REQUIRED_EXPORTS = [
  "buildSimpleCheckTaskSpec",
  "validateDomain",
  "authorizationScopeFor"
];

const FIXTURE_TARGETS = [
  "example.com",
  "example.test",
  "fixture.local",
  "fixture.example"
];

const REAL_TARGETS = [
  "weikan.net.cn",
  "company.com",
  "internal.corp"
];

const REQUIRED_TASKSPEC_MARKERS = [
  "fixture:local-only",
  "example.com",
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

const P56_ERROR = "P5.6 quick run only supports local fixtures";

for (const name of REQUIRED_EXPORTS) {
  assert.equal(typeof SimpleCheck[name], "function", `missing simple-check export: ${name}`);
}

if (SimpleCheck.assertP56FixtureOnlyTaskSpec !== undefined) {
  assert.equal(
    typeof SimpleCheck.assertP56FixtureOnlyTaskSpec,
    "function",
    "assertP56FixtureOnlyTaskSpec must be a function when exported"
  );
}

for (const target of FIXTURE_TARGETS) {
  const validation = SimpleCheck.validateDomain(target);
  assert.equal(validation.valid, true, `${target} must be accepted as a P5.6 fixture target`);
  assert.equal(
    SimpleCheck.authorizationScopeFor(target),
    "fixture:local-only",
    `${target} must use fixture-only authorization scope`
  );
}

for (const target of REAL_TARGETS) {
  const validation = SimpleCheck.validateDomain(target);
  assert.equal(validation.valid, false, `${target} must be rejected by validateDomain`);
  assert.match(
    String(validation.message || ""),
    /P5\.6 quick run only supports local fixtures/,
    `${target} rejection must explain the P5.6 fixture-only boundary`
  );
  assert.throws(
    () => SimpleCheck.buildSimpleCheckTaskSpec(
      {domain: target, mode: "quick", authorizationConfirmed: true},
      {timestamp: "20260624000000", operator: "operator"}
    ),
    (error) => String(error && error.message).includes(P56_ERROR),
    `${target} must not produce a TaskSpec`
  );
}

const task = SimpleCheck.buildSimpleCheckTaskSpec(
  {domain: "example.com", mode: "quick", authorizationConfirmed: true},
  {timestamp: "20260624000000", operator: "operator"}
);

if (SimpleCheck.assertP56FixtureOnlyTaskSpec !== undefined) {
  assert.equal(SimpleCheck.assertP56FixtureOnlyTaskSpec(task), true);
}

const taskText = JSON.stringify(task);
const lowerTaskText = taskText.toLowerCase();

for (const marker of REQUIRED_TASKSPEC_MARKERS) {
  assert.equal(
    taskText.includes(marker),
    true,
    `generated TaskSpec is missing required P5.6 marker: ${marker}`
  );
}

for (const token of FORBIDDEN_TASKSPEC_TOKENS) {
  assert.equal(
    lowerTaskText.includes(token.toLowerCase()),
    false,
    `generated TaskSpec leaked forbidden P7 token: ${token}`
  );
}

console.log(JSON.stringify({
  status: "ok",
  check: "P5.6 Web Quick Run boundary",
  fixtureTargets: FIXTURE_TARGETS,
  rejectedTargets: REAL_TARGETS,
  requiredMarkers: REQUIRED_TASKSPEC_MARKERS,
  forbiddenTokenMatches: []
}, null, 2));
