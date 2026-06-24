"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const Platform = require("./plugin-platform.js");

test("插件卡片声明 P5.6 fixture-only 或 disabled placeholder", () => {
  const plugin = Platform.pluginPresentation({
    name: "subdomain-discovery-plus",
    manifest: {
      spec: {capabilities: [{risk: "low"}]},
      extensions: {"sentinelflow.io/p5_6_status": "fixture-only"}
    }
  });
  assert.equal(plugin.name, "子域名发现");
  assert.equal(plugin.standalone, true);
  assert.equal(plugin.workflow, false);
  assert.equal(plugin.disabled, false);
  assert.equal(plugin.p5_6_status, "fixture-only");

  const dns = Platform.pluginPresentation({
    name: "dns-resolve-plus",
    manifest: {
      spec: {capabilities: [{risk: "low"}]},
      extensions: {"sentinelflow.io/p5_6_status": "disabled-p7-placeholder"}
    }
  });
  assert.equal(dns.disabled, true);
  assert.equal(dns.standalone, false);
  assert.equal(dns.p5_6_status, "disabled-p7-placeholder");
});

test("subdomain 插件只生成 fixture-only 单插件 TaskSpec", () => {
  const task = Platform.buildStandalonePluginTaskSpec(
    "subdomain-discovery-plus",
    {domain: "example.com", mode: "quick", authorizationConfirmed: true},
    {timestamp: "20260618120000"}
  );
  const text = JSON.stringify(task);
  assert.equal(task.spec.steps.length, 1);
  assert.equal(task.spec.steps[0].toolRef, "subdomain-discovery-plus");
  assert.equal(task.spec.steps[0].capability, "passive.subdomain.discovery");
  assert.equal(task.spec.authorizationScope, "fixture:local-only");
  assert.equal(task.metadata.labels.taskType, "plugin");
  assert.match(text, /fixture\.passive\.example\.com\.json/i);
  assert.doesNotMatch(text, /real:/i);
  assert.doesNotMatch(text, /tcp_connect/i);
  assert.doesNotMatch(text, /public_resolver/i);
  assert.doesNotMatch(text, /shodan|fofa|censys|crtsh/i);
  assert.doesNotMatch(text, /"active":\{[^}]*"enabled":true/i);
});

test("公网资产工作流保留为 P7 disabled placeholder", () => {
  const workflow = Platform.workflowTemplate("public-asset-discovery");
  assert.equal(workflow.disabled, true);
  assert.equal(workflow.p5_6_status, "disabled-p7-placeholder");
  assert.deepEqual(
    workflow.steps.map(([id]) => id),
    ["subdomain-discovery-plus", "dns-resolve-plus", "port-probe-plus", "service-detect-plus"]
  );
});

test("P5.6 自定义工作流不能加入 P7 placeholder 插件", () => {
  assert.throws(
    () => Platform.addPluginToWorkflow(null, "dns-resolve-plus"),
    /P5\.6/
  );
  assert.throws(
    () => Platform.addPluginToWorkflow(null, "subdomain-discovery-plus"),
    /P5\.6/
  );
  assert.throws(
    () => Platform.buildStandalonePluginTaskSpec(
      "port-probe-plus",
      {domain: "example.com", mode: "quick", authorizationConfirmed: true, rawInput: {}, capability: "asset.port.probe.passive"},
      {timestamp: "20260618120000"}
    ),
    /P5\.6/
  );
});
