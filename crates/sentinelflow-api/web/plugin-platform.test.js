"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const Platform = require("./plugin-platform.js");

test("插件卡片声明 P5.6 fixture-only 或 disabled placeholder", () => {
  const plugin = Platform.pluginPresentation({
    name: "subdomain-discovery-plus",
    manifest: {
      spec: {capabilities: [{risk: "low"}]},
      extensions: {"sentinelflow.io/p5_6_status": "disabled-future"}
    }
  });
  assert.equal(plugin.name, "子域名发现");
  assert.equal(plugin.standalone, false);
  assert.equal(plugin.workflow, false);
  assert.equal(plugin.disabled, true);
  assert.equal(plugin.p5_6_status, "disabled-future");

  const dns = Platform.pluginPresentation({
    name: "dns-resolve-plus",
    manifest: {
      spec: {capabilities: [{risk: "low"}]},
      extensions: {"sentinelflow.io/p5_6_status": "disabled-future"}
    }
  });
  assert.equal(dns.disabled, true);
  assert.equal(dns.standalone, false);
  assert.equal(dns.p5_6_status, "disabled-future");
});

test("subdomain plus 插件入口在 P5.6 禁用为 future placeholder", () => {
  assert.throws(
    () => Platform.buildStandalonePluginTaskSpec(
      "subdomain-discovery-plus",
      {domain: "example.com", mode: "quick", authorizationConfirmed: true},
      {timestamp: "20260618120000"}
    ),
    /P5\.6/
  );
});

test("公网资产工作流保留为 P7 disabled placeholder", () => {
  const workflow = Platform.workflowTemplate("public-asset-discovery");
  assert.equal(workflow.disabled, true);
  assert.equal(workflow.p5_6_status, "disabled-future");
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
