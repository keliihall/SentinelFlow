(function (root, factory) {
  const api = factory(root.SentinelFlowSimpleCheck);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SentinelFlowPluginPlatform = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (Simple) {
  "use strict";

  if (!Simple && typeof require === "function") {
    Simple = require("./simple-check.js");
  }

  const PLUGIN_COPY = {
    "subdomain-discovery-plus": {
      name: "子域名发现",
      purpose: "P5.6 仅使用 example.com / example.test 本地 fixture；真实子域名发现是 P7 placeholder。",
      audience: "交付人员、安全工程师",
      standalone: true,
      workflow: false,
      p5_6_status: "fixture-only"
    },
    "dns-resolve-plus": {
      name: "DNS 解析",
      purpose: "P5.6 禁用真实 DNS 解析；保留为 P7 placeholder。",
      audience: "交付人员、安全工程师",
      standalone: false,
      workflow: false,
      disabled: true,
      p5_6_status: "disabled-p7-placeholder"
    },
    "port-probe-plus": {
      name: "端口检查",
      purpose: "P5.6 禁用端口探测；保留为 P7 placeholder。",
      audience: "安全工程师",
      standalone: false,
      workflow: false,
      disabled: true,
      p5_6_status: "disabled-p7-placeholder"
    },
    "service-detect-plus": {
      name: "服务识别",
      purpose: "P5.6 禁用服务探测；保留为 P7 placeholder。",
      audience: "安全工程师",
      standalone: false,
      workflow: false,
      disabled: true,
      p5_6_status: "disabled-p7-placeholder"
    },
    "http-probe-plus": {
      name: "网站探活",
      purpose: "P5.6 禁用真实 HTTP 探活；保留为 P7 placeholder。",
      audience: "交付人员、安全工程师",
      standalone: false,
      workflow: false,
      disabled: true,
      p5_6_status: "disabled-p7-placeholder"
    },
    "web-fingerprint-plus": {
      name: "网站指纹识别",
      purpose: "P5.6 仅可消费本地 fixture 或上游导入结果；真实探测是 P7 placeholder。",
      audience: "安全工程师",
      standalone: false,
      workflow: false,
      disabled: true,
      p5_6_status: "disabled-p7-placeholder"
    },
    "tls-certificate-check-plus": {
      name: "TLS 证书检查",
      purpose: "P5.6 禁用真实 TLS 握手；保留为 P7 placeholder。",
      audience: "交付人员、安全工程师",
      standalone: false,
      workflow: false,
      disabled: true,
      p5_6_status: "disabled-p7-placeholder"
    },
    "markdown-report-plus": {
      name: "报告生成",
      purpose: "将已有检查结果汇总为可交付的 Markdown 报告。",
      audience: "项目经理、交付人员",
      standalone: true,
      workflow: false,
      p5_6_status: "fixture-only"
    }
  };

  const WORKFLOW_TEMPLATES = [
    {
      id: "public-asset-discovery",
      name: "公网资产发现（P7 placeholder）",
      description: "P5.6 不提供真实公网资产发现、DNS 主动解析、端口探测或服务探测。",
      duration: "约 3–10 分钟",
      risk: "P5.6 disabled",
      disabled: true,
      p5_6_status: "disabled-p7-placeholder",
      steps: [
        ["subdomain-discovery-plus", "查找子域名"],
        ["dns-resolve-plus", "确认域名解析"],
        ["port-probe-plus", "检查开放端口"],
        ["service-detect-plus", "识别服务类型"]
      ]
    },
    {
      id: "website-baseline",
      name: "网站基础检查（P7 placeholder）",
      description: "P5.6 不进行真实 HTTP/TLS 访问或服务识别，仅保留未来工作流占位。",
      duration: "约 1–5 分钟",
      risk: "P5.6 disabled",
      disabled: true,
      p5_6_status: "disabled-p7-placeholder",
      steps: [
        ["http-probe-plus", "网站探活"],
        ["web-fingerprint-plus", "识别网站技术"],
        ["tls-certificate-check-plus", "检查 TLS 证书"]
      ]
    },
    {
      id: "report-generation",
      name: "报告生成",
      description: "将本地 fixture、mock 或导入结果汇总分析并生成交付报告。",
      duration: "约 1 分钟",
      risk: "只读",
      disabled: false,
      p5_6_status: "fixture-only",
      steps: [["markdown-report-plus", "汇总并生成报告"]]
    }
  ];

  function pluginPresentation(tool) {
    const id = tool && (tool.name || (tool.metadata || {}).name) || "unknown";
    const copy = PLUGIN_COPY[id] || {};
    const manifest = tool && tool.manifest || {};
    const spec = manifest.spec || {};
    const capabilities = spec.capabilities || [];
    const extensions = manifest.extensions || {};
    const p56 = extensions["sentinelflow.io/p5_6_status"] || copy.p5_6_status || "disabled-p7-placeholder";
    const risks = capabilities.map((capability) => String(capability.risk || "low"));
    const riskOrder = ["info", "low", "medium", "high", "critical"];
    risks.sort((a, b) => riskOrder.indexOf(b) - riskOrder.indexOf(a));
    return {
      id,
      name: copy.name || spec.displayName || id,
      purpose: copy.purpose || capabilities[0]?.description || "通过 SentinelFlow 统一运行和审计。",
      audience: copy.audience || "安全工程师",
      standalone: copy.standalone !== false,
      workflow: copy.workflow !== false,
      disabled: Boolean(copy.disabled || p56 === "disabled-p7-placeholder"),
      p5_6_status: p56,
      risk: risks[0] || "low",
      manifest
    };
  }

  function buildStandalonePluginTaskSpec(pluginId, input, options) {
    if (pluginId === "subdomain-discovery-plus") {
      const workflowTask = Simple.buildSimpleCheckTaskSpec(input, options);
      const step = workflowTask.spec.steps[0];
      workflowTask.metadata.name = workflowTask.metadata.name.replace("web-", "plugin-subdomain-");
      workflowTask.metadata.labels.taskType = "plugin";
      workflowTask.metadata.labels.pluginId = pluginId;
      workflowTask.spec.steps = [step];
      workflowTask.spec.policy.maxConcurrency = 1;
      workflowTask.extensions["sentinelflow.io/web-console"].taskType = "plugin";
      workflowTask.extensions["sentinelflow.io/web-console"].pluginId = pluginId;
      Simple.assertP56FixtureOnly(workflowTask);
      return workflowTask;
    }

    throw new Error("P5.6 中该插件运行入口为 disabled P7 placeholder；请使用 fixture-only Quick Run 或导入型本地 fixture。");
  }

  function workflowTemplate(id) {
    const template = WORKFLOW_TEMPLATES.find((item) => item.id === id);
    return template ? JSON.parse(JSON.stringify(template)) : null;
  }

  function addPluginToWorkflow(workflow, pluginId) {
    const next = workflow ? JSON.parse(JSON.stringify(workflow)) : {
      id: `custom-${Date.now()}`,
      name: "自定义工作流",
      description: "由插件中心创建的检查流程。",
      duration: "按步骤而定",
      risk: "按插件而定",
      steps: []
    };
    if (!next.steps.some(([id]) => id === pluginId)) {
      const copy = PLUGIN_COPY[pluginId] || {};
      if (copy.disabled || copy.p5_6_status === "disabled-p7-placeholder" || copy.workflow === false) {
        throw new Error("P5.6 工作流不能加入真实发现、主动探测或外部情报 P7 placeholder 插件。");
      }
      next.steps.push([pluginId, (PLUGIN_COPY[pluginId] || {}).name || pluginId]);
    }
    return next;
  }

  function taskType(task) {
    const labels = (((task || {}).specSnapshot || {}).metadata || {}).labels || {};
    return labels.taskType === "plugin" ? "插件任务" : "工作流任务";
  }

  return {
    PLUGIN_COPY,
    WORKFLOW_TEMPLATES,
    pluginPresentation,
    buildStandalonePluginTaskSpec,
    workflowTemplate,
    addPluginToWorkflow,
    taskType
  };
});
