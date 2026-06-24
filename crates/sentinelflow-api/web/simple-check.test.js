"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  WEB_BOUNDARY,
  P56_FORBIDDEN_TASKSPEC_TOKENS,
  P5_6_FIXTURE_TARGETS,
  buildSimpleCheckTaskSpec,
  assertP56FixtureOnlyTaskSpec,
  validateDomain,
  qualityPresentation,
  taskAndReportMessage,
  skippedStageMessage,
  isSpecialAddress,
  navigationForRole
} = require("./simple-check.js");

function serialized(task) {
  return JSON.stringify(task);
}

test("Web 边界声明固定为 API-only 核心工作流", () => {
  assert.equal(WEB_BOUNDARY.statement, "browser only calls the API service");
  assert.deepEqual(WEB_BOUNDARY.coreWorkflowEndpoints, [
    "/api/tasks/validate",
    "/api/tasks/plan",
    "/api/policy/explain",
    "/api/tasks/run",
    "/api/findings",
    "/api/reports/generate",
    "/api/audit"
  ]);
});

test("Quick Run 只生成 P5.6 fixture-only TaskSpec", () => {
  const task = buildSimpleCheckTaskSpec(
    {domain: "example.com", mode: "quick", authorizationConfirmed: true},
    {timestamp: "20260618090000", operator: "operator"}
  );
  const text = serialized(task);
  assert.equal(task.spec.authorizationScope, "fixture:local-only");
  assert.equal(task.spec.policy.allowedTargets[0], "example.com");
  assert.deepEqual(task.spec.policy.targetPatterns, ["domain:example.com", "domain:*.example.com"]);
  assert.equal(task.spec.targets[0].input.target.value, "example.com");
  assert.equal(task.spec.targets[0].input.target.metadata.fixture, true);
  assert.equal(task.spec.targets[0].input.target.metadata.p5_6_status, "fixture-only");
  assert.equal(task.spec.steps.length, 1);
  assert.equal(task.spec.steps[0].toolRef, "example-echo");
  assert.equal(task.spec.steps[0].capability, "echo");
  assert.equal(task.metadata.labels.purpose, "p5_6_fixture_quick_run");
  assert.equal(task.metadata.labels.p5_6_status, "fixture-only");
  assert.equal(task.extensions["sentinelflow.io/web-console"].allowActiveVerify, false);
  assert.equal(task.extensions["sentinelflow.io/web-console"].allowHighRisk, false);
  assert.equal(task.extensions["sentinelflow.io/web-console"].p5_6_status, "fixture-only");
  assert.deepEqual(task.extensions["sentinelflow.io/web-console"].allowedTargets, P5_6_FIXTURE_TARGETS);
  assert.match(text, /fixture:local-only/i);
  assert.match(text, /p5_6_fixture_quick_run/i);
  assert.match(text, /fixture-only/i);
  assert.equal(assertP56FixtureOnlyTaskSpec(task), true);
});

test("Quick Run 不生成 P7 真实发现和主动探测字段", () => {
  const task = buildSimpleCheckTaskSpec(
    {domain: "example.test", mode: "quick", authorizationConfirmed: true},
    {timestamp: "20260618090000"}
  );
  const text = serialized(task);
  for (const token of P56_FORBIDDEN_TASKSPEC_TOKENS) {
    assert.doesNotMatch(text.toLowerCase(), new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").toLowerCase()), token);
  }
});

test("Quick Run 拒绝真实目标", () => {
  for (const domain of ["weikan.net.cn", "company.com", "internal.corp", "customer.invalid"]) {
    assert.throws(
      () => buildSimpleCheckTaskSpec({domain, mode: "quick", authorizationConfirmed: true}),
      /P5\.6 quick run only supports local fixtures/
    );
  }
});

test("standard 和 deep 在 P5.6 禁用到 P7", () => {
  assert.throws(
    () => buildSimpleCheckTaskSpec({domain: "example.com", mode: "standard", authorizationConfirmed: true}),
    /standard mode is disabled until P7/
  );
  assert.throws(
    () => buildSimpleCheckTaskSpec({domain: "example.com", mode: "deep", authorizationConfirmed: true}),
    /deep mode is disabled until P7/
  );
});

test("Quick Run 支持的 target 仅限本地 fixture allowlist", () => {
  for (const domain of P5_6_FIXTURE_TARGETS) {
    const validation = validateDomain(domain);
    assert.equal(validation.valid, true, domain);
    const task = buildSimpleCheckTaskSpec({domain, mode: "quick", authorizationConfirmed: true}, {timestamp: "20260618090000"});
    assert.equal(task.spec.authorizationScope, "fixture:local-only");
    assert.equal(task.spec.targets[0].input.target.value, domain);
    assert.equal(task.spec.targets[0].input.target.metadata.p5_6_status, "fixture-only");
    assert.equal(assertP56FixtureOnlyTaskSpec(task), true);
  }
});

test("表单校验提供普通用户可读提示", () => {
  assert.equal(validateDomain("").valid, false);
  assert.match(validateDomain("").message, /请输入/);
  assert.equal(validateDomain("https://example.com/path").valid, false);
  assert.match(validateDomain("https://example.com/path").message, /不需要填写/);
  assert.equal(validateDomain("customer.invalid").valid, false);
  assert.match(validateDomain("customer.invalid").message, /P5\.6 quick run only supports local fixtures/);
  assert.equal(validateDomain("example.com").valid, true);
  assert.equal(validateDomain("example.test").valid, true);
  assert.equal(validateDomain("fixture.local").valid, true);
  assert.equal(validateDomain("fixture.example").valid, true);
  assert.throws(
    () => buildSimpleCheckTaskSpec({domain: "example.com", mode: "quick", authorizationConfirmed: false}),
    /确认/
  );
  assert.throws(
    () => buildSimpleCheckTaskSpec({domain: "example.com", mode: "standard", authorizationConfirmed: true}),
    /standard mode is disabled until P7/
  );
});

test("任务完成与报告未确认分开表达", () => {
  assert.equal(qualityPresentation("unconfirmed", "Passed").label, "未确认");
  assert.equal(taskAndReportMessage("completed", "unconfirmed", "Passed"), "任务已完成，报告未确认");
  assert.doesNotMatch(taskAndReportMessage("completed", "unconfirmed", "Passed"), /检查成功/);
});

test("skipped 阶段不误写为没有发现", () => {
  assert.equal(skippedStageMessage("ports", "no_public_routable_targets"), "端口检查已跳过：没有可检查的公网 IP。");
  assert.equal(skippedStageMessage("services", "no_confirmed_open_ports"), "服务识别已跳过：没有确认开放的端口。");
  assert.doesNotMatch(skippedStageMessage("ports"), /未发现开放端口/);
});

test("特殊地址会被识别", () => {
  for (const address of ["198.18.0.1", "10.1.2.3", "172.16.5.1", "192.168.1.2", "127.0.0.1", "169.254.2.3"]) {
    assert.equal(isSpecialAddress(address), true, address);
  }
  assert.equal(isSpecialAddress("93.184.216.34"), false);
});

test("角色只看到与职责匹配的入口", () => {
  assert.equal(navigationForRole("viewer").includes("advanced"), false);
  assert.equal(navigationForRole("viewer").includes("new-check"), false);
  assert.equal(navigationForRole("operator").includes("new-check"), true);
  assert.equal(navigationForRole("admin").includes("advanced"), true);
});
