//! Default-deny execution policy for `SentinelFlow`.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use sentinelflow_schema::v1alpha1::{
    OutputRetentionPolicy, PolicyTimeWindow, RiskLevel, TaskExecutionPolicy,
};
use serde::{Deserialize, Serialize};
use url::Url;

/// Parsed authorization scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationScope {
    namespace: String,
    permission: String,
}

impl AuthorizationScope {
    /// Parses `namespace:permission`.
    ///
    /// # Errors
    ///
    /// Rejects missing or blank scope components.
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        let Some((namespace, permission)) = value.trim().split_once(':') else {
            return Err(PolicyError {
                field: "$.authorizationScope",
                message: "authorization scope must use namespace:permission",
            });
        };
        if namespace.is_empty() || permission.is_empty() {
            return Err(PolicyError {
                field: "$.authorizationScope",
                message: "authorization scope components cannot be blank",
            });
        }
        Ok(Self {
            namespace: namespace.to_owned(),
            permission: permission.to_owned(),
        })
    }

    /// Scope namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Scope permission.
    #[must_use]
    pub fn permission(&self) -> &str {
        &self.permission
    }
}

/// Approval lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalStatus {
    /// Awaiting a decision.
    Pending,
    /// Explicitly approved.
    Approved,
    /// Explicitly rejected.
    Rejected,
    /// No longer valid.
    Expired,
}

/// Core approval record used by CLI or future APIs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    /// Stable approval identifier.
    pub approval_id: String,
    /// Task or run resource requesting approval.
    pub resource_ref: String,
    /// Requested risk.
    pub risk: RiskLevel,
    /// Current lifecycle state.
    pub status: ApprovalStatus,
    /// Actor that made the latest decision.
    pub actor: String,
}

impl ApprovalRecord {
    /// Approves a pending request.
    ///
    /// # Errors
    ///
    /// Rejects transitions from a terminal state.
    pub fn approve(&mut self, actor: impl Into<String>) -> Result<(), PolicyError> {
        self.transition(ApprovalStatus::Approved, actor)
    }

    /// Rejects a pending request.
    ///
    /// # Errors
    ///
    /// Rejects transitions from a terminal state.
    pub fn reject(&mut self, actor: impl Into<String>) -> Result<(), PolicyError> {
        self.transition(ApprovalStatus::Rejected, actor)
    }

    /// Expires a pending request.
    ///
    /// # Errors
    ///
    /// Rejects transitions from a terminal state.
    pub fn expire(&mut self, actor: impl Into<String>) -> Result<(), PolicyError> {
        self.transition(ApprovalStatus::Expired, actor)
    }

    fn transition(
        &mut self,
        status: ApprovalStatus,
        actor: impl Into<String>,
    ) -> Result<(), PolicyError> {
        if self.status != ApprovalStatus::Pending {
            return Err(PolicyError {
                field: "$.approval.status",
                message: "only pending approvals may transition",
            });
        }
        self.status = status;
        self.actor = actor.into();
        Ok(())
    }
}

/// Inputs for an explainable task policy decision.
pub struct TaskPolicyRequest<'a> {
    /// Authorization scope.
    pub authorization_scope: &'a str,
    /// Target name, domain, URL, IP, or CIDR candidate.
    pub target: &'a str,
    /// Capability risk.
    pub risk: RiskLevel,
    /// Approval state, when available.
    pub approval: Option<ApprovalStatus>,
    /// Current UTC minute after midnight.
    pub utc_minute: u16,
    /// Current running node count.
    pub running_nodes: usize,
    /// Starts observed in the current minute.
    pub starts_this_minute: u32,
    /// Task policy.
    pub policy: &'a TaskExecutionPolicy,
}

/// Explainable policy outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    /// Whether execution is allowed.
    pub allowed: bool,
    /// Ordered decision reasons.
    pub reasons: Vec<String>,
    /// Effective output retention.
    pub retention: OutputRetentionPolicy,
}

/// Evaluates task policy constraints with default deny.
#[must_use]
pub fn evaluate_task(request: &TaskPolicyRequest<'_>) -> PolicyDecision {
    let mut reasons = Vec::new();
    if AuthorizationScope::parse(request.authorization_scope).is_err() {
        reasons.push("authorization scope is invalid".to_owned());
    }
    if !target_allowed(
        request.target,
        &request.policy.allowed_targets,
        &request.policy.target_patterns,
    ) {
        reasons.push(format!(
            "target is outside the authorization boundary: {}",
            request.target
        ));
    }
    if request.risk.requires_approval()
        && request.approval != Some(ApprovalStatus::Approved)
        && !request.policy.approve_high_risk
    {
        reasons.push("high or critical risk requires an approved request".to_owned());
    }
    if !request.policy.time_windows.is_empty()
        && !request
            .policy
            .time_windows
            .iter()
            .any(|window| time_window_contains(window, request.utc_minute))
    {
        reasons.push("current UTC time is outside every allowed window".to_owned());
    }
    if request.running_nodes >= request.policy.max_concurrency {
        reasons.push("task concurrency limit is exhausted".to_owned());
    }
    if request.starts_this_minute >= request.policy.rate_limit_per_minute {
        reasons.push("task rate limit is exhausted".to_owned());
    }
    PolicyDecision {
        allowed: reasons.is_empty(),
        reasons,
        retention: request.policy.output_retention.clone(),
    }
}

/// Tests a target against explicit names and typed patterns.
#[must_use]
pub fn target_allowed(target: &str, names: &[String], patterns: &[String]) -> bool {
    names.iter().any(|candidate| candidate == target)
        || patterns.iter().any(|pattern| match_target(pattern, target))
}

fn match_target(pattern: &str, target: &str) -> bool {
    if let Some(expected) = pattern.strip_prefix("domain:") {
        let domain = Url::parse(target)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_else(|| target.to_owned());
        return wildcard_domain(expected, &domain);
    }
    if let Some(expected) = pattern.strip_prefix("url:") {
        return wildcard_text(expected, target);
    }
    if let Some(expected) = pattern.strip_prefix("ip:") {
        return target.parse::<IpAddr>().ok() == expected.parse::<IpAddr>().ok();
    }
    if let Some(expected) = pattern.strip_prefix("cidr:") {
        return expected
            .parse::<IpNet>()
            .ok()
            .zip(target.parse::<IpAddr>().ok())
            .is_some_and(|(network, address)| network.contains(&address));
    }
    false
}

fn wildcard_domain(pattern: &str, domain: &str) -> bool {
    pattern
        .strip_prefix("*.")
        .is_some_and(|suffix| domain != suffix && domain.ends_with(&format!(".{suffix}")))
        || pattern.eq_ignore_ascii_case(domain)
}

fn wildcard_text(pattern: &str, value: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or_else(|| pattern == value, |prefix| value.starts_with(prefix))
}

/// Returns whether a UTC minute falls inside a possibly cross-midnight window.
#[must_use]
pub fn time_window_contains(window: &PolicyTimeWindow, minute: u16) -> bool {
    let Some(start) = parse_minute(&window.start) else {
        return false;
    };
    let Some(end) = parse_minute(&window.end) else {
        return false;
    };
    match start.cmp(&end) {
        std::cmp::Ordering::Equal => true,
        std::cmp::Ordering::Less => minute >= start && minute < end,
        std::cmp::Ordering::Greater => minute >= start || minute < end,
    }
}

fn parse_minute(value: &str) -> Option<u16> {
    let (hour, minute) = value.split_once(':')?;
    let hour = hour.parse::<u16>().ok()?;
    let minute = minute.parse::<u16>().ok()?;
    (hour < 24 && minute < 60).then_some(hour * 60 + minute)
}

/// Inputs evaluated before an adapter prepares a process.
#[derive(Clone, Debug)]
pub struct ExecutionPolicyRequest<'a> {
    /// Whether the tool is explicitly allowlisted as a safe repository example.
    pub example_plugin: bool,
    /// Explicit authorization scope.
    pub authorization_scope: Option<&'a str>,
    /// Requested capability risk.
    pub risk: RiskLevel,
    /// Explicit approval for high or critical risk.
    pub approved: bool,
    /// Caller-requested timeout.
    pub requested_timeout: Duration,
    /// Maximum timeout declared by the Manifest.
    pub maximum_timeout: Duration,
}

/// Proof that the default-deny policy accepted a request.
#[derive(Clone, Debug)]
pub struct AuthorizationGrant {
    authorization_scope: String,
}

impl AuthorizationGrant {
    /// Scope bound to this authorization.
    #[must_use]
    pub fn authorization_scope(&self) -> &str {
        &self.authorization_scope
    }
}

/// Minimal policy denial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyError {
    /// Field responsible for denial.
    pub field: &'static str,
    /// Non-sensitive denial reason.
    pub message: &'static str,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for PolicyError {}

/// Evaluates the minimum P2-2 execution policy.
///
/// # Errors
///
/// Denies missing authorization scope, unapproved high/critical risk, zero timeout,
/// and requests above the Manifest timeout ceiling.
pub fn authorize(request: &ExecutionPolicyRequest<'_>) -> Result<AuthorizationGrant, PolicyError> {
    if !request.example_plugin {
        return Err(PolicyError {
            field: "$.toolId",
            message: "execution is limited to allowlisted example plugins",
        });
    }
    let scope = request
        .authorization_scope
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .ok_or(PolicyError {
            field: "$.authorizationScope",
            message: "authorization scope is required",
        })?;
    AuthorizationScope::parse(scope)?;

    if matches!(request.risk, RiskLevel::High | RiskLevel::Critical) && !request.approved {
        return Err(PolicyError {
            field: "$.approved",
            message: "high and critical risk capabilities require explicit approval",
        });
    }
    if request.requested_timeout.is_zero() {
        return Err(PolicyError {
            field: "$.timeout",
            message: "timeout must be greater than zero",
        });
    }
    if request.requested_timeout > request.maximum_timeout {
        return Err(PolicyError {
            field: "$.timeout",
            message: "requested timeout exceeds the Manifest limit",
        });
    }

    Ok(AuthorizationGrant {
        authorization_scope: scope.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sentinelflow_schema::v1alpha1::{
        OutputRetentionPolicy, PolicyTimeWindow, RiskLevel, TaskExecutionPolicy,
    };

    use super::{
        ApprovalRecord, ApprovalStatus, ExecutionPolicyRequest, TaskPolicyRequest, authorize,
        evaluate_task, target_allowed, time_window_contains,
    };

    #[test]
    fn default_deny_rules_are_enforced() {
        let base = ExecutionPolicyRequest {
            example_plugin: true,
            authorization_scope: Some("local:echo"),
            risk: RiskLevel::Low,
            approved: false,
            requested_timeout: Duration::from_secs(1),
            maximum_timeout: Duration::from_secs(5),
        };
        assert!(authorize(&base).is_ok());
        assert!(
            authorize(&ExecutionPolicyRequest {
                example_plugin: false,
                ..base.clone()
            })
            .is_err()
        );
        assert!(
            authorize(&ExecutionPolicyRequest {
                authorization_scope: None,
                ..base.clone()
            })
            .is_err()
        );
        assert!(
            authorize(&ExecutionPolicyRequest {
                risk: RiskLevel::High,
                ..base.clone()
            })
            .is_err()
        );
        assert!(
            authorize(&ExecutionPolicyRequest {
                requested_timeout: Duration::from_secs(6),
                ..base
            })
            .is_err()
        );
    }

    fn task_policy() -> TaskExecutionPolicy {
        TaskExecutionPolicy {
            allowed_targets: vec!["fixture".to_owned()],
            target_patterns: vec![
                "domain:*.example.com".to_owned(),
                "url:https://api.example.net/v1/*".to_owned(),
                "ip:192.0.2.10".to_owned(),
                "cidr:198.51.100.0/24".to_owned(),
            ],
            approve_high_risk: false,
            approval_ref: None,
            timeout_seconds: Some(5),
            max_concurrency: 2,
            rate_limit_per_minute: 10,
            time_windows: vec![PolicyTimeWindow {
                start: "23:00".to_owned(),
                end: "02:00".to_owned(),
            }],
            output_retention: OutputRetentionPolicy {
                days: 7,
                retain_evidence: false,
            },
        }
    }

    #[test]
    fn target_matchers_cover_domain_url_ip_and_cidr() {
        let policy = task_policy();
        assert!(target_allowed(
            "host.example.com",
            &policy.allowed_targets,
            &policy.target_patterns
        ));
        assert!(target_allowed(
            "https://api.example.net/v1/items",
            &policy.allowed_targets,
            &policy.target_patterns
        ));
        assert!(target_allowed(
            "192.0.2.10",
            &policy.allowed_targets,
            &policy.target_patterns
        ));
        assert!(target_allowed(
            "198.51.100.42",
            &policy.allowed_targets,
            &policy.target_patterns
        ));
        assert!(!target_allowed(
            "203.0.113.1",
            &policy.allowed_targets,
            &policy.target_patterns
        ));
    }

    #[test]
    fn cross_midnight_window_and_explainable_decisions_are_correct() {
        let policy = task_policy();
        assert!(time_window_contains(&policy.time_windows[0], 23 * 60 + 30));
        assert!(time_window_contains(&policy.time_windows[0], 60));
        assert!(!time_window_contains(&policy.time_windows[0], 12 * 60));
        let denied = evaluate_task(&TaskPolicyRequest {
            authorization_scope: "fixture:local-only",
            target: "203.0.113.1",
            risk: RiskLevel::High,
            approval: Some(ApprovalStatus::Pending),
            utc_minute: 12 * 60,
            running_nodes: 2,
            starts_this_minute: 10,
            policy: &policy,
        });
        assert!(!denied.allowed);
        assert_eq!(denied.reasons.len(), 5);
        let allowed = evaluate_task(&TaskPolicyRequest {
            authorization_scope: "fixture:local-only",
            target: "198.51.100.42",
            risk: RiskLevel::High,
            approval: Some(ApprovalStatus::Approved),
            utc_minute: 60,
            running_nodes: 0,
            starts_this_minute: 0,
            policy: &policy,
        });
        assert!(allowed.allowed);
        assert_eq!(allowed.retention.days, 7);
    }

    #[test]
    fn approval_state_machine_is_terminal_after_a_decision() {
        let mut approval = ApprovalRecord {
            approval_id: "approval-1".to_owned(),
            resource_ref: "task-1".to_owned(),
            risk: RiskLevel::High,
            status: ApprovalStatus::Pending,
            actor: "requester".to_owned(),
        };
        approval.approve("reviewer").unwrap();
        assert_eq!(approval.status, ApprovalStatus::Approved);
        assert!(approval.reject("other").is_err());
        assert!(approval.expire("system").is_err());

        for expected in [ApprovalStatus::Rejected, ApprovalStatus::Expired] {
            let mut record = ApprovalRecord {
                approval_id: format!("{expected:?}"),
                resource_ref: "task-1".to_owned(),
                risk: RiskLevel::High,
                status: ApprovalStatus::Pending,
                actor: "requester".to_owned(),
            };
            match expected {
                ApprovalStatus::Rejected => record.reject("reviewer").unwrap(),
                ApprovalStatus::Expired => record.expire("system").unwrap(),
                ApprovalStatus::Pending | ApprovalStatus::Approved => unreachable!(),
            }
            assert_eq!(record.status, expected);
        }
    }
}
