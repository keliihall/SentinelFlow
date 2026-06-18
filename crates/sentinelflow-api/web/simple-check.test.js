"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  WEB_BOUNDARY,
  buildSimpleCheckTaskSpec,
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

test("快速检查为真实目标生成安全 TaskSpec", () => {
  const task = buildSimpleCheckTaskSpec(
    {domain: "weikan.net.cn", mode: "quick", authorizationConfirmed: true},
    {timestamp: "20260618090000", operator: "operator"}
  );
  const text = serialized(task);
  assert.equal(task.spec.authorizationScope, "real:weikan-net-cn");
  assert.equal(task.spec.policy.allowedTargets[0], "weikan.net.cn");
  assert.deepEqual(task.spec.policy.targetPatterns, ["domain:weikan.net.cn", "domain:*.weikan.net.cn"]);
  assert.equal(task.extensions["sentinelflow.io/web-console"].allowActiveVerify, false);
  assert.equal(task.extensions["sentinelflow.io/web-console"].allowHighRisk, false);
  assert.doesNotMatch(text, /fixture:local-only/i);
  assert.doesNotMatch(text, /example\.com/i);
  assert.doesNotMatch(text, /fixture\.passive\.example\.com\.json/i);
  assert.doesNotMatch(text, /"sources":\["fixture"\]/i);
  assert.match(text, /"mode":"passive_intel"/);
});

test("标准检查仅启用低影响主动能力", () => {
  const task = buildSimpleCheckTaskSpec(
    {domain: "weikan.net.cn", mode: "standard", authorizationConfirmed: true},
    {timestamp: "20260618090000"}
  );
  const text = serialized(task);
  assert.equal(task.extensions["sentinelflow.io/web-console"].allowActiveVerify, true);
  assert.equal(task.extensions["sentinelflow.io/web-console"].allowHighRisk, false);
  assert.match(text, /"probe_engine":"tcp_connect"/);
  assert.doesNotMatch(text, /syn_probe/i);
  assert.doesNotMatch(text, /deep fingerprint/i);
  assert.doesNotMatch(text, /deep_fingerprint/i);
});

test("表单校验提供普通用户可读提示", () => {
  assert.equal(validateDomain("").valid, false);
  assert.match(validateDomain("").message, /请输入/);
  assert.equal(validateDomain("https://weikan.net.cn/path").valid, false);
  assert.match(validateDomain("https://weikan.net.cn/path").message, /不需要填写/);
  assert.throws(
    () => buildSimpleCheckTaskSpec({domain: "weikan.net.cn", mode: "quick", authorizationConfirmed: false}),
    /确认/
  );
  assert.throws(
    () => buildSimpleCheckTaskSpec({domain: "example.com", mode: "quick", authorizationConfirmed: true}),
    /示例域名/
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
  assert.equal(isSpecialAddress("8.8.8.8"), false);
});

test("角色只看到与职责匹配的入口", () => {
  assert.equal(navigationForRole("viewer").includes("advanced"), false);
  assert.equal(navigationForRole("viewer").includes("new-check"), false);
  assert.equal(navigationForRole("operator").includes("new-check"), true);
  assert.equal(navigationForRole("admin").includes("advanced"), true);
});
