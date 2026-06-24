(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.SentinelFlowSimpleCheck = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const WEB_BOUNDARY = Object.freeze({
    statement: "browser only calls the API service",
    coreWorkflowEndpoints: Object.freeze([
      "/api/tasks/validate",
      "/api/tasks/plan",
      "/api/policy/explain",
      "/api/tasks/run",
      "/api/findings",
      "/api/reports/generate",
      "/api/audit"
    ])
  });

  const FIXTURE_MARKERS = [
    "fixture:local-only",
    "example.com",
    "example.test",
    "fixture.local",
    "fixture.example",
    "p5_6_fixture_quick_run",
    "fixture-only",
    "local_fixture",
    "mock_fixture"
  ];

  const P56_FORBIDDEN_TASKSPEC_TOKENS = [
    ["re", "al:"],
    ["wei", "kan", ".net", ".cn"],
    ["1", ".1", ".1", ".1"],
    ["8", ".8", ".8", ".8"],
    ["tcp", "_connect"],
    ["public", "_resolver"],
    ["sho", "dan"],
    ["fo", "fa"],
    ["cen", "sys"],
    ["crt", "sh"],
    ["virus", "total"],
    ["active", "_dns"],
    ["active", "_resolver"],
    ["active", "_verify"],
    ["authorized", "_assessment"],
    ["authorized", "-asset-discovery"],
    ["port", "-probe-plus"],
    ["service", "-detect-plus"],
    ["dns", "-resolve-plus"],
    ["subdomain", "-discovery-plus"],
    ["tcp", "_banner"],
    ["tls", "_hello"],
    ["http", "_head"],
    ["http", "_get_root"],
    "\"allow_active_verify\":true",
    "\"allowActiveVerify\":true",
    "\"enabled\":true"
  ].map((token) => Array.isArray(token) ? token.join("") : token);
  const P5_6_FORBIDDEN_MARKERS = P56_FORBIDDEN_TASKSPEC_TOKENS;

  const P5_6_FIXTURE_TARGETS = Object.freeze([
    "example.com",
    "example.test",
    "fixture.local",
    "fixture.example"
  ]);

  const P5_6_QUICK_RUN_ERROR = "P5.6 quick run only supports local fixtures. Real target checks are disabled until P7.";

  const SPECIAL_IPV4_RANGES = [
    ["10.0.0.0", 8],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15]
  ];

  function normalizeDomain(value) {
    return String(value || "").trim().toLowerCase().replace(/\.$/, "");
  }

  function validateDomain(value) {
    const domain = normalizeDomain(value);
    if (!domain) {
      return {valid: false, message: "请输入要检查的域名。"};
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(domain) || domain.includes("/") || domain.includes("?") || domain.includes("#")) {
      return {valid: false, message: "请输入 example.com、example.test、fixture.local 或 fixture.example，不需要填写 http://、https:// 或页面路径。"};
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/.test(domain) || domain.includes("/")) {
      return {valid: false, message: "当前入口仅支持域名，不支持 IP 地址或 IP 网段。"};
    }
    if (domain.length > 253 || !domain.includes(".")) {
      return {valid: false, message: P5_6_QUICK_RUN_ERROR};
    }
    const labels = domain.split(".");
    const valid = labels.every((label) =>
      label.length > 0
      && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    );
    if (!valid || !/^[a-z]{2,63}$/i.test(labels[labels.length - 1])) {
      return {valid: false, message: "域名格式不正确，请输入 P5.6 fixture 域名。"};
    }
    if (!isFixtureDomain(domain)) {
      return {valid: false, message: P5_6_QUICK_RUN_ERROR};
    }
    return {valid: true, domain};
  }

  function isFixtureDomain(domain) {
    const value = normalizeDomain(domain);
    return P5_6_FIXTURE_TARGETS.includes(value);
  }

  function domainSlug(domain) {
    return normalizeDomain(domain).replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  }

  function authorizationScopeFor(_domain) {
    return "fixture:local-only";
  }

  function createContext(taskName, runName, domain, scope, operator) {
    return {
      task_id: taskName,
      run_id: `run_${runName}_${domainSlug(domain)}`,
      operator: operator || "operator",
      workspace: "default",
      authorization_scope: scope
    };
  }

  function createTarget(domain) {
    return {
      type: "domain",
      value: domain,
      metadata: {
        fixture: true,
        p5_6_status: "fixture-only"
      }
    };
  }

  function commonPolicy(_active) {
    return {
      allow_high_risk: false
    };
  }

  function buildFixtureInput(domain, taskName, scope, operator) {
    return {
      context: createContext(taskName, "fixture", domain, scope, operator),
      target: createTarget(domain),
      message: `SentinelFlow P5.6 fixture quick run for ${domain}`,
      fixture: {
        provider: "local_fixture",
        mock: true,
        p5_6_status: "fixture-only"
      },
      policy: commonPolicy(false)
    };
  }

  function buildSimpleCheckTaskSpec(input, options) {
    const validation = validateDomain(input && input.domain);
    if (!validation.valid) {
      throw new Error(validation.message);
    }
    if (!input.authorizationConfirmed) {
      throw new Error("请先确认你已获得该目标的检查授权。");
    }
    const mode = input.mode || "quick";
    if (!["quick", "standard", "deep"].includes(mode)) {
      throw new Error("请选择快速检查、标准检查或深度检查。");
    }
    if (mode === "standard") {
      throw new Error("standard mode is disabled until P7");
    }
    if (mode === "deep") {
      throw new Error("deep mode is disabled until P7");
    }

    const domain = validation.domain;
    const active = false;
    const scope = authorizationScopeFor(domain);
    const timestamp = options && options.timestamp
      ? String(options.timestamp)
      : new Date().toISOString().replace(/\D/g, "").slice(0, 14);
    const taskName = `web-${mode}-${domainSlug(domain)}-${timestamp}`;
    const operator = options && options.operator ? options.operator : "operator";
    const fixtureInput = buildFixtureInput(domain, taskName, scope, operator);

    const task = {
      apiVersion: "sentinelflow.io/v1alpha1",
      kind: "TaskSpec",
      metadata: {
        name: taskName,
        labels: {
          target: domain,
          authorizationScope: scope,
          purpose: "p5_6_fixture_quick_run",
          p5_6_status: "fixture-only",
          checkMode: mode
        }
      },
      spec: {
        authorizationScope: scope,
        targets: [{
          name: domain,
          input: fixtureInput
        }],
        steps: [
          {
            name: "fixture-smoke",
            toolRef: "example-echo",
            capability: "echo",
            outputAs: "fixture_smoke",
            failurePolicy: "continue",
            input: {
              message: fixtureInput.message
            }
          }
        ],
        policy: {
          allowedTargets: [domain],
          targetPatterns: [`domain:${domain}`, `domain:*.${domain}`],
          approveHighRisk: false,
          timeoutSeconds: 300,
          maxConcurrency: 1,
          rateLimitPerMinute: 60,
          outputRetention: {days: 30, retainEvidence: true}
        }
      },
      extensions: {
        "sentinelflow.io/web-console": {
          simpleMode: true,
          checkMode: mode,
          authorizationConfirmed: true,
          allowActiveVerify: active,
          allowHighRisk: false,
          allowedTargets: P5_6_FIXTURE_TARGETS.slice(),
          p5_6_status: "fixture-only"
        }
      }
    };
    assertP56FixtureOnlyTaskSpec(task);
    return task;
  }

  function assertP56FixtureOnlyTaskSpec(task) {
    const serialized = JSON.stringify(task).toLowerCase();
    const scope = (((task || {}).spec || {}).authorizationScope || "").toLowerCase();
    if (scope !== "fixture:local-only") {
      throw new Error("P5.6 Quick Run 必须使用 fixture:local-only 授权范围。");
    }
    const targets = ((((task || {}).spec || {}).targets) || []).map((target) =>
      normalizeDomain(target && target.name ? target.name : (((target || {}).input || {}).target || {}).value)
    );
    const allowed = targets.every((target) => isFixtureDomain(target));
    if (!allowed || targets.length === 0) {
      throw new Error(P5_6_QUICK_RUN_ERROR);
    }
    const marker = P56_FORBIDDEN_TASKSPEC_TOKENS.find((value) => serialized.includes(value.toLowerCase()));
    if (marker) {
      throw new Error(`P5.6 Quick Run 禁止生成 P7 能力字段：${marker}`);
    }
    return true;
  }

  function assertP56FixtureOnly(task) {
    return assertP56FixtureOnlyTaskSpec(task);
  }

  function ipv4ToInt(value) {
    const parts = String(value).split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      return null;
    }
    return parts.reduce((sum, part) => ((sum << 8) + part) >>> 0, 0);
  }

  function isSpecialAddress(value) {
    if (String(value).includes(":")) {
      const lower = String(value).toLowerCase();
      return lower === "::1" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd");
    }
    const address = ipv4ToInt(value);
    if (address === null) return false;
    return SPECIAL_IPV4_RANGES.some(([base, bits]) => {
      const baseValue = ipv4ToInt(base);
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return (address & mask) === (baseValue & mask);
    });
  }

  function qualityPresentation(reportStatus, qualityGate) {
    const status = String(reportStatus || "").toLowerCase();
    const gate = String(qualityGate || "").toLowerCase();
    if (status.includes("invalid") || gate === "failed") {
      return {key: "invalid", label: "不可信", tone: "danger", message: "本次结果未通过数据质量检查，不建议作为正式结论。"};
    }
    if (status === "unconfirmed") {
      return {key: "unconfirmed", label: "未确认", tone: "neutral", message: "本次仅得到候选结果，尚未确认真实资产。"};
    }
    if (status.includes("warning")) {
      return {key: "warning", label: "有警告", tone: "warning", message: "本次检查完成，但部分数据源不可用或存在结果冲突。"};
    }
    if (status === "valid" && gate === "passed") {
      return {key: "trusted", label: "可信", tone: "success", message: "本次检查获得了可确认的资产结果。"};
    }
    return {key: "unconfirmed", label: "未确认", tone: "neutral", message: "暂时无法确认本次结果的可信状态。"};
  }

  function taskAndReportMessage(taskStatus, reportStatus, qualityGate) {
    const quality = qualityPresentation(reportStatus, qualityGate);
    const taskLabel = taskStatus === "completed" ? "任务已完成" : `任务${taskStatus || "状态未知"}`;
    return `${taskLabel}，报告${quality.label}`;
  }

  function skippedStageMessage(stage, reason) {
    if (stage === "ports" || reason === "no_public_routable_targets") {
      return "端口检查已跳过：没有可检查的公网 IP。";
    }
    if (stage === "services" || reason === "no_confirmed_open_ports") {
      return "服务识别已跳过：没有确认开放的端口。";
    }
    return "该检查步骤已跳过。";
  }

  function navigationForRole(role) {
    const value = String(role || "viewer").toLowerCase();
    const items = ["home", "records", "reports", "help"];
    if (value === "operator" || value === "admin") {
      items.splice(1, 0, "new-check");
    }
    if (value === "admin") {
      items.push("advanced");
    }
    return items;
  }

  return {
    WEB_BOUNDARY,
    FIXTURE_MARKERS,
    P5_6_FORBIDDEN_MARKERS,
    P56_FORBIDDEN_TASKSPEC_TOKENS,
    P5_6_FIXTURE_TARGETS,
    P5_6_QUICK_RUN_ERROR,
    normalizeDomain,
    validateDomain,
    isFixtureDomain,
    domainSlug,
    authorizationScopeFor,
    buildSimpleCheckTaskSpec,
    assertP56FixtureOnlyTaskSpec,
    assertP56FixtureOnly,
    isSpecialAddress,
    qualityPresentation,
    taskAndReportMessage,
    skippedStageMessage,
    navigationForRole
  };
});
