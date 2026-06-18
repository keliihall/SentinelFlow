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
    "fixture.passive.example.com.json",
    "fixture.ports.example.com.json",
    "fixture.web.example.com.json",
    "passive_fixture",
    "fixture_resolver",
    "mock_resolver"
  ];

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
      return {valid: false, message: "请输入域名，例如 weikan.net.cn，不需要填写 http://、https:// 或页面路径。"};
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/.test(domain) || domain.includes("/")) {
      return {valid: false, message: "当前入口仅支持域名，不支持 IP 地址或 IP 网段。"};
    }
    if (domain === "example.com" || domain.endsWith(".example.com")) {
      return {valid: false, message: "普通检查不能使用 example.com 示例域名，请填写已获得授权的真实域名。"};
    }
    if (domain.length > 253 || !domain.includes(".")) {
      return {valid: false, message: "请输入完整域名，例如 weikan.net.cn。"};
    }
    const labels = domain.split(".");
    const valid = labels.every((label) =>
      label.length > 0
      && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    );
    if (!valid || !/^[a-z]{2,63}$/i.test(labels[labels.length - 1])) {
      return {valid: false, message: "域名格式不正确，请输入类似 weikan.net.cn 的完整域名。"};
    }
    return {valid: true, domain};
  }

  function domainSlug(domain) {
    return normalizeDomain(domain).replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  }

  function authorizationScopeFor(domain) {
    return `real:${domainSlug(domain)}`;
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
      metadata: {authorization: "user-confirmed"}
    };
  }

  function commonPolicy(active) {
    return {
      allow_active_verify: active,
      allow_high_risk: false
    };
  }

  function buildSubdomainInput(domain, taskName, scope, mode, operator) {
    const active = mode === "standard";
    return {
      context: createContext(taskName, "subdomains", domain, scope, operator),
      target: createTarget(domain),
      options: {
        mode: active ? "hybrid" : "passive_intel",
        passive: {
          enabled: true,
          sources: ["crtsh", "local_cache", "passive_dns_cache"],
          crtsh_enabled: true,
          crtsh_timeout_seconds: 10
        },
        active: {
          enabled: active,
          dry_run: !active,
          wordlist_file: "examples/wordlist.small.txt",
          resolvers: ["1.1.1.1", "8.8.8.8"],
          record_types: ["A", "AAAA"],
          timeout_seconds: 3,
          concurrency: 5,
          rate_limit_per_second: 5,
          max_candidates: active ? 500 : 100,
          detect_wildcard: true
        },
        output: {include_unresolved: true, include_sources: true}
      },
      policy: commonPolicy(active)
    };
  }

  function buildDnsInput(domain, taskName, scope, mode, operator) {
    const active = mode === "standard";
    return {
      context: createContext(taskName, "dns", domain, scope, operator),
      target: createTarget(domain),
      inputs: {domains: [], findings: []},
      options: {
        mode: active ? "hybrid" : "passive_intel",
        record_types: ["A", "AAAA", "CNAME", "MX", "NS", "TXT"],
        passive_intel: {
          enabled: true,
          sources: ["local_cache", "passive_dns_cache"],
          api_timeout_seconds: 10,
          api_rate_limit_per_second: 1,
          max_queries: 100,
          allow_missing_secrets: true,
          local_cache_file: "examples/cache.empty.json",
          passive_dns_cache_file: "examples/cache.empty.json"
        },
        active: {
          enabled: active,
          resolver_mode: "public_resolver",
          resolvers: ["1.1.1.1", "8.8.8.8"],
          authoritative_trace: false,
          timeout_seconds: 3,
          concurrency: 10,
          rate_limit_per_second: 10,
          max_domains: 1000,
          max_queries: 5000
        },
        merge: {
          deduplicate: true,
          conflict_policy: "preserve_all_sources",
          mark_source_disagreement: true,
          confidence_strategy: "weighted_sources",
          stale_after_days: 30
        },
        output: {
          include_unresolved: true,
          include_source_details: true,
          include_conflicts: true
        },
        risk_acknowledged: false,
        execution_profile: "authorized_assessment"
      },
      policy: commonPolicy(active)
    };
  }

  function buildPortInput(domain, taskName, scope, mode, operator) {
    const active = mode === "standard";
    return {
      context: createContext(taskName, "ports", domain, scope, operator),
      target: createTarget(domain),
      inputs: {addresses: [], findings: []},
      options: {
        mode: active ? "hybrid" : "passive_intel",
        passive_intel: {
          enabled: true,
          sources: ["fofa", "shodan", "local_cache"],
          allow_missing_secrets: true,
          api_timeout_seconds: 10,
          api_rate_limit_per_second: 1,
          max_queries: 100,
          local_cache_file: "examples/cache.empty.json"
        },
        active: {
          enabled: active,
          probe_engine: "tcp_connect",
          port_profile: "custom",
          ports: [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
          timeout_seconds: 2,
          concurrency: 10,
          rate_limit_per_second: 10,
          max_targets: 100,
          max_ports: 20
        },
        merge: {
          deduplicate: true,
          conflict_policy: "preserve_all_sources",
          mark_source_disagreement: true,
          confidence_strategy: "weighted_sources",
          stale_after_days: 30
        },
        output: {
          include_closed: false,
          include_filtered: false,
          include_source_details: true,
          include_conflicts: true
        },
        execution_profile: "authorized_assessment"
      },
      policy: commonPolicy(active)
    };
  }

  function buildServiceInput(domain, taskName, scope, mode, operator) {
    const active = mode === "standard";
    return {
      context: createContext(taskName, "services", domain, scope, operator),
      target: {type: "service", value: `${domain}:443`, metadata: {authorization: "user-confirmed"}},
      inputs: {services: [], findings: []},
      options: {
        mode: active ? "hybrid" : "passive_intel",
        detection_depth: "safe",
        passive_intel: {
          enabled: true,
          sources: ["upstream_port_result", "upstream_dns_result", "local_cache", "fofa_enrichment", "shodan_enrichment"],
          prefer_sources: ["upstream_port_result", "local_cache", "fofa_enrichment", "shodan_enrichment"],
          api_timeout_seconds: 10,
          api_rate_limit_per_second: 1,
          max_queries: 100,
          allow_missing_secrets: true,
          local_cache_file: "examples/cache.empty.json"
        },
        active: {
          enabled: active,
          probe_profiles: ["tcp_banner", "tls_hello", "http_head", "http_get_root"],
          timeout_seconds: 3,
          concurrency: 5,
          rate_limit_per_second: 5,
          max_services: 100,
          max_probes_per_service: 4,
          max_response_bytes: 4096
        },
        merge: {
          deduplicate: true,
          conflict_policy: "preserve_all_sources",
          mark_source_disagreement: true,
          confidence_strategy: "weighted_sources",
          stale_after_days: 30
        },
        output: {
          include_unknown: false,
          include_source_details: true,
          include_conflicts: true,
          mask_sensitive_headers: true,
          truncate_banner_bytes: 512
        },
        risk_acknowledged: false,
        execution_profile: "authorized_assessment"
      },
      policy: commonPolicy(active)
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
    const mode = input.mode || "standard";
    if (!["quick", "standard", "deep"].includes(mode)) {
      throw new Error("请选择快速检查、标准检查或深度检查。");
    }
    if (mode === "deep") {
      throw new Error("深度检查需要进入高级模式，并在审批后配置。");
    }

    const domain = validation.domain;
    const active = mode === "standard";
    const scope = authorizationScopeFor(domain);
    const timestamp = options && options.timestamp
      ? String(options.timestamp)
      : new Date().toISOString().replace(/\D/g, "").slice(0, 14);
    const taskName = `web-${mode}-${domainSlug(domain)}-${timestamp}`;
    const operator = options && options.operator ? options.operator : "operator";
    const subdomainInput = buildSubdomainInput(domain, taskName, scope, mode, operator);

    const task = {
      apiVersion: "sentinelflow.io/v1alpha1",
      kind: "TaskSpec",
      metadata: {
        name: taskName,
        labels: {
          target: domain,
          authorizationScope: scope,
          purpose: "authorized-asset-discovery",
          checkMode: mode
        }
      },
      spec: {
        authorizationScope: scope,
        targets: [{
          name: domain,
          input: subdomainInput
        }],
        steps: [
          {
            name: "discover-subdomains",
            toolRef: "subdomain-discovery-plus",
            capability: active ? "asset.subdomain.discovery" : "passive.subdomain.discovery",
            outputAs: "subdomains",
            failurePolicy: "continue",
            input: subdomainInput
          },
          {
            name: "resolve-dns",
            toolRef: "dns-resolve-plus",
            capability: active ? "asset.dns.resolve.active_public_resolver" : "asset.dns.resolve.passive",
            dependsOn: ["discover-subdomains"],
            outputAs: "dns_records",
            failurePolicy: "continue",
            input: buildDnsInput(domain, taskName, scope, mode, operator),
            inputFrom: [{from: "subdomains", pointer: "/spec/findings", target: "/inputs/findings"}]
          },
          {
            name: "probe-ports",
            toolRef: "port-probe-plus",
            capability: active ? "asset.port.probe.hybrid" : "asset.port.probe.passive",
            dependsOn: ["resolve-dns"],
            outputAs: "open_ports",
            failurePolicy: "continue",
            input: buildPortInput(domain, taskName, scope, mode, operator),
            inputFrom: [{from: "dns_records", pointer: "/spec/findings", target: "/inputs/findings"}]
          },
          {
            name: "detect-services",
            toolRef: "service-detect-plus",
            capability: active ? "asset.service.detect.safe" : "asset.service.detect.passive",
            dependsOn: ["probe-ports"],
            outputAs: "services",
            failurePolicy: "continue",
            input: buildServiceInput(domain, taskName, scope, mode, operator),
            inputFrom: [{from: "open_ports", pointer: "/spec/findings", target: "/inputs/findings"}]
          }
        ],
        policy: {
          allowedTargets: [domain],
          targetPatterns: [`domain:${domain}`, `domain:*.${domain}`],
          approveHighRisk: false,
          timeoutSeconds: 300,
          maxConcurrency: active ? 3 : 1,
          rateLimitPerMinute: active ? 300 : 60,
          outputRetention: {days: 30, retainEvidence: true}
        }
      },
      extensions: {
        "sentinelflow.io/web-console": {
          simpleMode: true,
          checkMode: mode,
          authorizationConfirmed: true,
          allowActiveVerify: active,
          allowHighRisk: false
        }
      }
    };
    assertNoFixtureForRealTarget(task);
    return task;
  }

  function assertNoFixtureForRealTarget(task) {
    const serialized = JSON.stringify(task).toLowerCase();
    const scope = (((task || {}).spec || {}).authorizationScope || "").toLowerCase();
    if (!scope.startsWith("real:")) {
      throw new Error("真实域名必须使用自动生成的真实授权范围。");
    }
    const marker = FIXTURE_MARKERS.find((value) => serialized.includes(value));
    const hasFixtureSource = /"sources"\s*:\s*\[[^\]]*"fixture"/.test(serialized);
    const hasExampleDomain = /(^|[^a-z0-9-])example\.com([^a-z0-9-]|$)/.test(serialized);
    if (marker || hasFixtureSource || hasExampleDomain) {
      throw new Error("当前目标是真实域名，不能使用本地示例数据。请切换为快速检查或标准检查。");
    }
    return true;
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
    normalizeDomain,
    validateDomain,
    domainSlug,
    authorizationScopeFor,
    buildSimpleCheckTaskSpec,
    assertNoFixtureForRealTarget,
    isSpecialAddress,
    qualityPresentation,
    taskAndReportMessage,
    skippedStageMessage,
    navigationForRole
  };
});
