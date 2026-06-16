//! HTTP API and Web Console delivery layer for `SentinelFlow`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sentinelflow_cli::{
    Cli, Command, PathArgument, PluginCommand, TaskCommand, TaskIdArgument, TaskRunArguments,
};
use sentinelflow_core::constants::{API_GROUP, CLI_BINARY, PRODUCT_NAME, WORKSPACE_DIR};
use sentinelflow_orchestrator::plan;
use sentinelflow_policy::{ApprovalRecord, ApprovalStatus, TaskPolicyRequest, evaluate_task};
use sentinelflow_registry::{ToolRegistry, discover_plugins, install_plugin, validate_plugin};
use sentinelflow_report::{generate_markdown, generate_task_markdown};
use sentinelflow_schema::v1alpha1::{
    AuditOutcome, RiskLevel, TaskSpec, Validate, ValidationContext,
};
use sentinelflow_store::{WorkspaceStore, now_rfc3339};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::sleep;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

const CONSOLE_HTML: &str = include_str!("../web/console.html");
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 500;
const DEFAULT_LOG_LIMIT: usize = 200;
const MAX_LOG_LIMIT: usize = 1_000;
const DEFAULT_REPORT_MAX_FINDINGS: usize = 5_000;

/// API service configuration.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// Local `SentinelFlow` workspace.
    pub workspace_dir: PathBuf,
    /// Schema root used for protocol validation.
    pub schema_root: PathBuf,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            workspace_dir: PathBuf::from(WORKSPACE_DIR),
            schema_root: PathBuf::from("."),
        }
    }
}

/// Authenticated principal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    /// Stable actor identifier.
    pub actor_id: String,
    /// Assigned RBAC role.
    pub role: Role,
}

/// Minimal `SentinelFlow` API roles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    /// Read-only access to workspace resources.
    Viewer,
    /// May validate/install plugins and operate tasks.
    Operator,
    /// May approve, reject, or expire approvals.
    Approver,
    /// Full administrative access.
    Admin,
}

impl Role {
    const fn can(self, required: Self) -> bool {
        matches!(self, Self::Admin)
            || matches!(
                (self, required),
                (Self::Viewer, Self::Viewer)
                    | (Self::Operator, Self::Viewer | Self::Operator)
                    | (Self::Approver, Self::Viewer | Self::Approver)
            )
    }
}

/// Replaceable identity provider boundary.
pub trait IdentityProvider: Send + Sync {
    /// Authenticates an existing bearer token.
    fn authenticate_token(&self, token: &str) -> Option<Identity>;

    /// Issues a session token for a login request.
    fn issue_session(&self, username: &str, password: &str) -> Option<Session>;
}

/// Session response returned by the development identity provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// Bearer token to send on future API requests.
    pub token: String,
    /// Authenticated identity.
    pub identity: Identity,
}

/// Static token identity provider for local development and tests.
#[derive(Clone, Debug)]
pub struct StaticIdentityProvider {
    tokens: BTreeMap<String, Identity>,
}

impl StaticIdentityProvider {
    /// Creates a provider with the built-in development tokens.
    #[must_use]
    pub fn development() -> Self {
        let mut tokens = BTreeMap::new();
        for (token, actor_id, role) in [
            ("viewer-token", "viewer", Role::Viewer),
            ("operator-token", "operator", Role::Operator),
            ("approver-token", "approver", Role::Approver),
            ("admin-token", "admin", Role::Admin),
        ] {
            tokens.insert(
                token.to_owned(),
                Identity {
                    actor_id: actor_id.to_owned(),
                    role,
                },
            );
        }
        Self { tokens }
    }
}

impl Default for StaticIdentityProvider {
    fn default() -> Self {
        Self::development()
    }
}

impl IdentityProvider for StaticIdentityProvider {
    fn authenticate_token(&self, token: &str) -> Option<Identity> {
        self.tokens.get(token).cloned()
    }

    fn issue_session(&self, username: &str, password: &str) -> Option<Session> {
        if password != "sentinelflow" {
            return None;
        }
        let token = format!("{username}-token");
        let identity = self.authenticate_token(&token)?;
        Some(Session { token, identity })
    }
}

#[derive(Clone)]
struct AppState {
    config: ApiConfig,
    identity_provider: Arc<dyn IdentityProvider>,
}

/// Builds the API and Web Console router.
pub fn router(config: ApiConfig, identity_provider: Arc<dyn IdentityProvider>) -> Router {
    let state = AppState {
        config,
        identity_provider,
    };
    Router::new()
        .route("/", get(console))
        .route("/console", get(console))
        .route("/health", get(health))
        .route("/openapi.json", get(openapi))
        .route("/api/session/login", post(login))
        .route("/api/session", get(session))
        .route("/api/tools", get(list_tools))
        .route("/api/tools/:name", get(get_tool))
        .route("/api/plugins", get(list_plugins))
        .route("/api/plugins/validate", post(validate_plugin_endpoint))
        .route("/api/plugins/install", post(install_plugin_endpoint))
        .route("/api/plugins/test", post(test_plugin_endpoint))
        .route("/api/tasks", get(list_tasks))
        .route("/api/tasks/validate", post(validate_task_endpoint))
        .route("/api/tasks/plan", post(plan_task_endpoint))
        .route("/api/tasks/run", post(run_task_endpoint))
        .route("/api/tasks/:task_id", get(get_task))
        .route("/api/tasks/:task_id/cancel", post(cancel_task_endpoint))
        .route("/api/tasks/:task_id/logs", get(task_logs))
        .route("/api/tasks/:task_id/logs/stream", get(task_logs_stream))
        .route("/api/runs", get(list_runs))
        .route("/api/runs/:run_id", get(get_run))
        .route("/api/findings", get(list_findings))
        .route("/api/reports", get(list_reports))
        .route("/api/reports/generate", post(generate_report_endpoint))
        .route("/api/reports/:report_id", get(get_report))
        .route("/api/audit", get(list_audit))
        .route("/api/approvals", get(list_approvals))
        .route("/api/approvals/request", post(request_approval_endpoint))
        .route(
            "/api/approvals/:approval_id/approve",
            post(approve_endpoint),
        )
        .route("/api/approvals/:approval_id/reject", post(reject_endpoint))
        .route("/api/approvals/:approval_id/expire", post(expire_endpoint))
        .route("/api/policy/explain", post(policy_explain_endpoint))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Builds a router with local development authentication.
pub fn development_router(config: ApiConfig) -> Router {
    router(config, Arc::new(StaticIdentityProvider::development()))
}

async fn console() -> Html<&'static str> {
    Html(CONSOLE_HTML)
}

async fn health() -> Json<Value> {
    Json(json!({
        "product": PRODUCT_NAME,
        "cliBinary": CLI_BINARY,
        "apiGroup": API_GROUP,
        "status": "ok"
    }))
}

async fn openapi() -> Json<Value> {
    Json(openapi_document())
}

async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<Session>, ApiError> {
    let username = request.username.clone();
    if let Some(session) = state
        .identity_provider
        .issue_session(&request.username, &request.password)
    {
        let mut store = store(&state)?;
        store.record_audit(
            "api.session.login",
            AuditOutcome::Succeeded,
            None,
            Some(session.identity.actor_id.clone()),
        )?;
        Ok(Json(session))
    } else {
        let mut store = store(&state)?;
        store.record_audit(
            "api.session.login",
            AuditOutcome::Denied,
            None,
            Some(username),
        )?;
        Err(ApiError::unauthorized("invalid username or password"))
    }
}

async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Identity>, ApiError> {
    Ok(Json(require_identity(&state, &headers, Role::Viewer)?))
}

async fn list_tools(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let tools = load_registry(&state.config.workspace_dir)?
        .list()
        .map(|(name, tool)| {
            json!({
                "name": name,
                "enabled": tool.enabled,
                "pluginRoot": tool.plugin_root,
                "manifest": tool.manifest,
            })
        })
        .collect::<Vec<_>>();
    audit_api(
        &state,
        &identity,
        "api.tools.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!(tools)))
}

async fn get_tool(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let registry = load_registry(&state.config.workspace_dir)?;
    let tool = registry
        .get(&name)
        .ok_or_else(|| ApiError::not_found("tool not found"))?;
    audit_api(
        &state,
        &identity,
        "api.tools.get",
        AuditOutcome::Allowed,
        Some(name),
    )?;
    Ok(Json(json!({
        "enabled": tool.enabled,
        "pluginRoot": tool.plugin_root,
        "manifest": tool.manifest,
    })))
}

async fn list_plugins(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let discovery = discover_plugins([state.config.workspace_dir.join("plugins")])
        .map_err(|error| ApiError::system(error.to_string()))?;
    audit_api(
        &state,
        &identity,
        "api.plugins.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!({
        "plugins": discovery.plugins,
        "ignored": discovery.ignored,
    })))
}

async fn validate_plugin_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PathRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Operator)?;
    let report =
        validate_plugin(&request.path).map_err(|error| ApiError::system(error.to_string()))?;
    audit_api(
        &state,
        &identity,
        "api.plugins.validate",
        if report.is_valid() {
            AuditOutcome::Succeeded
        } else {
            AuditOutcome::Failed
        },
        Some(request.path.display().to_string()),
    )?;
    Ok(Json(serde_json::to_value(report)?))
}

async fn install_plugin_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PathRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity_audited(
        &state,
        &headers,
        Role::Operator,
        "api.plugins.install",
        Some(request.path.display().to_string()),
    )?;
    let outcome = install_plugin(&request.path, state.config.workspace_dir.join("plugins"))
        .map_err(|error| ApiError::system(error.to_string()))?;
    audit_api(
        &state,
        &identity,
        "api.plugins.install",
        AuditOutcome::Succeeded,
        Some(request.path.display().to_string()),
    )?;
    Ok(Json(json!({"outcome": format!("{outcome:?}")})))
}

async fn test_plugin_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PathRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Operator)?;
    let cli = Cli {
        workspace: Some(state.config.workspace_dir.clone()),
        schema_root: Some(state.config.schema_root.clone()),
        log_level: None,
        api_endpoint: None,
        auth_token: None,
        command: Command::Plugin {
            command: PluginCommand::Test(PathArgument {
                path: request.path.clone(),
            }),
        },
    };
    sentinelflow_cli::execute(cli)
        .await
        .map_err(|error| ApiError::from_cli(&error, "plugin test failed"))?;
    audit_api(
        &state,
        &identity,
        "api.plugins.test",
        AuditOutcome::Succeeded,
        Some(request.path.display().to_string()),
    )?;
    Ok(Json(json!({"status": "passed"})))
}

async fn list_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let page = query.page(DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    let tasks = store(&state)?.list_tasks_page(page.limit, page.offset)?;
    audit_api(
        &state,
        &identity,
        "api.tasks.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!(tasks)))
}

async fn get_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity_audited(
        &state,
        &headers,
        Role::Viewer,
        "api.tasks.get",
        Some(task_id.clone()),
    )?;
    let task = store(&state)?.load_task(&task_id)?;
    audit_api(
        &state,
        &identity,
        "api.tasks.get",
        AuditOutcome::Allowed,
        Some(task_id),
    )?;
    Ok(Json(json!(task)))
}

async fn validate_task_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TaskDocumentRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Operator)?;
    let task = parse_task_request(&request, &state.config.schema_root)?;
    plan(&task).map_err(|error| ApiError::from_plan(&error))?;
    audit_api(
        &state,
        &identity,
        "api.tasks.validate",
        AuditOutcome::Succeeded,
        Some(task.metadata.name.clone()),
    )?;
    Ok(Json(json!({"valid": true, "task": task})))
}

async fn plan_task_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TaskDocumentRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let task = parse_task_request(&request, &state.config.schema_root)?;
    let plan = plan(&task).map_err(|error| ApiError::from_plan(&error))?;
    audit_api(
        &state,
        &identity,
        "api.tasks.plan",
        AuditOutcome::Succeeded,
        Some(task.metadata.name.clone()),
    )?;
    Ok(Json(serde_json::to_value(plan)?))
}

async fn run_task_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TaskDocumentRequest>,
) -> Result<Json<Value>, ApiError> {
    let task = parse_task_request(&request, &state.config.schema_root)?;
    let identity = require_identity_audited(
        &state,
        &headers,
        Role::Operator,
        "api.tasks.run",
        Some(task.metadata.name.clone()),
    )?;
    if let Some(active) = store(&state)?.find_active_task_by_name(&task.metadata.name)? {
        audit_api(
            &state,
            &identity,
            "api.tasks.run",
            AuditOutcome::Denied,
            Some(active.task_id.clone()),
        )?;
        return Err(ApiError::conflict(format!(
            "task {} already has active run {} in state {:?}",
            task.metadata.name, active.task_id, active.status
        )));
    }
    let task_path = persist_api_task(&state.config.workspace_dir, &task)?;
    let cli = Cli {
        workspace: Some(state.config.workspace_dir.clone()),
        schema_root: Some(state.config.schema_root.clone()),
        log_level: None,
        api_endpoint: None,
        auth_token: None,
        command: Command::Task {
            command: TaskCommand::Run(TaskRunArguments {
                file: task_path,
                actor_id: identity.actor_id.clone(),
            }),
        },
    };
    sentinelflow_cli::execute(cli)
        .await
        .map_err(|error| ApiError::from_cli(&error, "task run failed"))?;
    let task_artifact = store(&state)?
        .latest_task_by_name(&task.metadata.name)?
        .ok_or_else(|| ApiError::system("task completed but no task artifact was persisted"))?;
    audit_api(
        &state,
        &identity,
        "api.tasks.run",
        AuditOutcome::Succeeded,
        Some(task_artifact.task_id.clone()),
    )?;
    Ok(Json(json!(task_artifact)))
}

async fn cancel_task_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Operator)?;
    let cli = Cli {
        workspace: Some(state.config.workspace_dir.clone()),
        schema_root: Some(state.config.schema_root.clone()),
        log_level: None,
        api_endpoint: None,
        auth_token: None,
        command: Command::Task {
            command: TaskCommand::Cancel(TaskIdArgument {
                task_id: task_id.clone(),
            }),
        },
    };
    sentinelflow_cli::execute(cli)
        .await
        .map_err(|error| ApiError::from_cli(&error, "task cancel failed"))?;
    audit_api(
        &state,
        &identity,
        "api.tasks.cancel",
        AuditOutcome::Succeeded,
        Some(task_id),
    )?;
    Ok(Json(json!({"status": "cancelling"})))
}

async fn task_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_id): AxumPath<String>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let page = query.page(DEFAULT_LOG_LIMIT, MAX_LOG_LIMIT);
    let events = store(&state)?.task_audit_page(&task_id, page.limit, page.offset)?;
    audit_api(
        &state,
        &identity,
        "api.tasks.logs",
        AuditOutcome::Allowed,
        Some(task_id),
    )?;
    Ok(Json(json!(events)))
}

async fn task_logs_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_id): AxumPath<String>,
    Query(query): Query<StreamQuery>,
) -> Result<Sse<impl futures_core::Stream<Item = Result<Event, std::convert::Infallible>>>, ApiError>
{
    let identity =
        require_identity_or_query_token(&state, &headers, query.token.as_deref(), Role::Viewer)?;
    audit_api(
        &state,
        &identity,
        "api.tasks.logs.stream",
        AuditOutcome::Allowed,
        Some(task_id.clone()),
    )?;
    let start = query.cursor.unwrap_or(0);
    let limit = usize::from(
        query
            .limit
            .unwrap_or(u16::try_from(DEFAULT_LOG_LIMIT).unwrap_or(u16::MAX))
            .min(u16::try_from(MAX_LOG_LIMIT).unwrap_or(u16::MAX)),
    );
    let workspace = state.config.workspace_dir.clone();
    let stream = stream! {
        let mut cursor = start;
        let mut emitted = 0usize;
        for _ in 0..120 {
            let remaining = limit.saturating_sub(emitted);
            let events = WorkspaceStore::open(&workspace)
                .and_then(|store| store.task_audit_page(&task_id, remaining, cursor))
                .unwrap_or_default();
            for event in &events {
                cursor += 1;
                let data = serde_json::to_string(&json!({"cursor": cursor, "event": event}))
                    .unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_owned());
                yield Ok(Event::default().event("audit").id(cursor.to_string()).data(data));
                emitted += 1;
                if emitted >= limit {
                    return;
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn list_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let page = query.page(DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    let runs = store(&state)?.list_runs_page(page.limit, page.offset)?;
    audit_api(
        &state,
        &identity,
        "api.runs.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!(runs)))
}

async fn get_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let bundle = store(&state)?.load_bundle(&run_id)?;
    audit_api(
        &state,
        &identity,
        "api.runs.get",
        AuditOutcome::Allowed,
        Some(run_id),
    )?;
    Ok(Json(bundle_as_json(&bundle)))
}

async fn list_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let page = query.page(DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    let findings = store(&state)?.list_findings_page(page.limit, page.offset)?;
    audit_api(
        &state,
        &identity,
        "api.findings.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!(findings)))
}

async fn list_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let page = query.page(DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    let reports = store(&state)?.list_reports_page(page.limit, page.offset)?;
    audit_api(
        &state,
        &identity,
        "api.reports.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!(reports)))
}

async fn generate_report_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReportRequest>,
) -> Result<Json<Value>, ApiError> {
    let target = request.run.clone().or_else(|| request.task.clone());
    let identity = require_identity_audited(
        &state,
        &headers,
        Role::Operator,
        "api.reports.generate",
        target.clone(),
    )?;
    let workspace_dir = state.config.workspace_dir.clone();
    let report_result = tokio::task::spawn_blocking(move || {
        let store = WorkspaceStore::open(workspace_dir)?;
        let (report_id, markdown) = if let Some(run_id) = &request.run {
            enforce_report_finding_limit(store.count_findings_for_run(run_id)?, run_id)?;
            store
                .load_bundle(run_id)
                .map(|bundle| (run_id.clone(), generate_markdown(&bundle)))?
        } else if let Some(task_id) = &request.task {
            enforce_report_finding_limit(store.count_findings_for_task(task_id)?, task_id)?;
            store.load_task(task_id).and_then(|task| {
                let bundles = store.load_task_bundles(task_id)?;
                let audit = store.task_audit(task_id)?;
                Ok((
                    task_id.clone(),
                    generate_task_markdown(&task, &bundles, &audit),
                ))
            })?
        } else {
            return Err(ApiError::bad_request("either run or task is required"));
        };
        let path = store.save_report(&report_id, &markdown)?;
        Ok::<_, ApiError>((report_id, path))
    })
    .await
    .map_err(|error| ApiError::system(format!("report worker failed: {error}")))?;
    let (report_id, path) = match report_result {
        Ok(report) => report,
        Err(error) => {
            audit_api(
                &state,
                &identity,
                "api.reports.generate",
                AuditOutcome::Failed,
                target,
            )?;
            return Err(error);
        }
    };
    audit_api(
        &state,
        &identity,
        "api.reports.generate",
        AuditOutcome::Succeeded,
        Some(path.display().to_string()),
    )?;
    audit_api(
        &state,
        &identity,
        "report.generated",
        AuditOutcome::Succeeded,
        Some(path.display().to_string()),
    )?;
    Ok(Json(json!({"reportId": report_id, "path": path})))
}

async fn get_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(report_id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let identity = require_identity_audited(
        &state,
        &headers,
        Role::Viewer,
        "api.reports.get",
        Some(report_id.clone()),
    )?;
    let markdown = store(&state)?.load_report(&report_id)?;
    audit_api(
        &state,
        &identity,
        "api.reports.get",
        AuditOutcome::Allowed,
        Some(report_id),
    )?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        markdown,
    )
        .into_response())
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let identity =
        require_identity_audited(&state, &headers, Role::Viewer, "api.audit.list", None)?;
    let page = query.page(DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    let events = store(&state)?.list_audit_page(page.limit, page.offset)?;
    audit_api(
        &state,
        &identity,
        "api.audit.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!(events)))
}

async fn list_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let page = query.page(DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    let approvals = store(&state)?.list_approvals_page(page.limit, page.offset)?;
    audit_api(
        &state,
        &identity,
        "api.approvals.list",
        AuditOutcome::Allowed,
        None,
    )?;
    Ok(Json(json!(approvals)))
}

async fn request_approval_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ApprovalRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Operator)?;
    let approval = ApprovalRecord {
        approval_id: format!("approval-{}", now_rfc3339()?.replace([':', '.'], "-")),
        resource_ref: request.resource,
        risk: request.risk,
        status: ApprovalStatus::Pending,
        actor: identity.actor_id.clone(),
    };
    let mut store = store(&state)?;
    store.save_approval(&approval)?;
    store.record_audit(
        "api.approvals.request",
        AuditOutcome::Succeeded,
        None,
        Some(approval.approval_id.clone()),
    )?;
    Ok(Json(json!(approval)))
}

async fn approve_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(approval_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    decide_approval_endpoint(&state, &headers, &approval_id, ApprovalStatus::Approved)
}

async fn reject_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(approval_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    decide_approval_endpoint(&state, &headers, &approval_id, ApprovalStatus::Rejected)
}

async fn expire_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(approval_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    decide_approval_endpoint(&state, &headers, &approval_id, ApprovalStatus::Expired)
}

fn decide_approval_endpoint(
    state: &AppState,
    headers: &HeaderMap,
    approval_id: &str,
    status: ApprovalStatus,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(state, headers, Role::Approver)?;
    let mut store = store(state)?;
    let mut approval = store.load_approval(approval_id)?;
    match status {
        ApprovalStatus::Approved => approval.approve(&identity.actor_id),
        ApprovalStatus::Rejected => approval.reject(&identity.actor_id),
        ApprovalStatus::Expired => approval.expire(&identity.actor_id),
        ApprovalStatus::Pending => return Err(ApiError::bad_request("pending is not a decision")),
    }
    .map_err(|error| ApiError::forbidden(error.message))?;
    store.save_approval(&approval)?;
    store.record_audit(
        match status {
            ApprovalStatus::Approved => "api.approvals.approve",
            ApprovalStatus::Rejected => "api.approvals.reject",
            ApprovalStatus::Expired => "api.approvals.expire",
            ApprovalStatus::Pending => "api.approvals.pending",
        },
        AuditOutcome::Succeeded,
        None,
        Some(approval.approval_id.clone()),
    )?;
    Ok(Json(json!(approval)))
}

async fn policy_explain_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TaskDocumentRequest>,
) -> Result<Json<Value>, ApiError> {
    let identity = require_identity(&state, &headers, Role::Viewer)?;
    let task = parse_task_request(&request, &state.config.schema_root)?;
    let explanations = explain_policy(&state.config.workspace_dir, &task)?;
    audit_api(
        &state,
        &identity,
        "api.policy.explain",
        AuditOutcome::Succeeded,
        Some(task.metadata.name.clone()),
    )?;
    Ok(Json(json!(explanations)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PathRequest {
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskDocumentRequest {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    task: Option<TaskSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReportRequest {
    run: Option<String>,
    task: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct Page {
    limit: usize,
    offset: usize,
}

impl PageQuery {
    const fn page(&self, default_limit: usize, max_limit: usize) -> Page {
        let requested = match self.limit {
            Some(0) | None => default_limit,
            Some(limit) => limit,
        };
        Page {
            limit: if requested > max_limit {
                max_limit
            } else {
                requested
            },
            offset: match self.offset {
                Some(offset) => offset,
                None => 0,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequest {
    resource: String,
    risk: RiskLevel,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamQuery {
    cursor: Option<usize>,
    token: Option<String>,
    limit: Option<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    code: String,
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "SchemaValidationFailed".to_owned(),
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "AuthorizationDenied".to_owned(),
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "AuthorizationDenied".to_owned(),
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "RuntimeError".to_owned(),
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NotFound".to_owned(),
            message: message.into(),
        }
    }

    fn system(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "SystemError".to_owned(),
            message: message.into(),
        }
    }

    fn from_plan(error: &sentinelflow_orchestrator::PlanError) -> Self {
        Self::bad_request(format!("{}: {}", error.field, error.message))
    }

    fn from_cli(error: &sentinelflow_cli::CliError, context: &str) -> Self {
        let standard_error = error.to_standard_error();
        Self {
            status: match error.exit_code() {
                2 | 3 => StatusCode::BAD_REQUEST,
                4 => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            code: standard_error.error.code,
            message: format!("{context}: {error}"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                code: self.code,
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<sentinelflow_store::StoreError> for ApiError {
    fn from(error: sentinelflow_store::StoreError) -> Self {
        Self::system(error.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::system(error.to_string())
    }
}

fn require_identity(
    state: &AppState,
    headers: &HeaderMap,
    role: Role,
) -> Result<Identity, ApiError> {
    let token = authorization_token(headers)
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let identity = state
        .identity_provider
        .authenticate_token(token)
        .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
    if identity.role.can(role) {
        Ok(identity)
    } else {
        Err(ApiError::forbidden(
            "role is not authorized for this operation",
        ))
    }
}

fn require_identity_audited(
    state: &AppState,
    headers: &HeaderMap,
    role: Role,
    action: &str,
    target: Option<String>,
) -> Result<Identity, ApiError> {
    match require_identity(state, headers, role) {
        Ok(identity) => Ok(identity),
        Err(error) => {
            let identity = authorization_token(headers)
                .and_then(|token| state.identity_provider.authenticate_token(token));
            let mut store = store(state)?;
            store.record_audit(
                action,
                AuditOutcome::Denied,
                None,
                target.or_else(|| identity.map(|identity| identity.actor_id)),
            )?;
            Err(error)
        }
    }
}

fn authorization_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get("x-sentinelflow-token")
                .and_then(|value| value.to_str().ok())
        })
}

fn require_identity_or_query_token(
    state: &AppState,
    headers: &HeaderMap,
    query_token: Option<&str>,
    role: Role,
) -> Result<Identity, ApiError> {
    match require_identity(state, headers, role) {
        Ok(identity) => Ok(identity),
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            let token = query_token.ok_or(error)?;
            let identity = state
                .identity_provider
                .authenticate_token(token)
                .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
            if identity.role.can(role) {
                Ok(identity)
            } else {
                Err(ApiError::forbidden(
                    "role is not authorized for this operation",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn store(state: &AppState) -> Result<WorkspaceStore, ApiError> {
    WorkspaceStore::open(&state.config.workspace_dir).map_err(Into::into)
}

fn audit_api(
    state: &AppState,
    identity: &Identity,
    action: &str,
    outcome: AuditOutcome,
    target: Option<String>,
) -> Result<(), ApiError> {
    let mut store = store(state)?;
    store.record_audit(
        action,
        outcome,
        None,
        target.or_else(|| Some(identity.actor_id.clone())),
    )?;
    Ok(())
}

fn load_registry(workspace_dir: &Path) -> Result<ToolRegistry, ApiError> {
    let discovery = discover_plugins([workspace_dir.join("plugins")])
        .map_err(|error| ApiError::system(error.to_string()))?;
    let mut registry = ToolRegistry::new();
    for plugin_root in discovery.plugins {
        let plugin =
            validate_plugin(&plugin_root).map_err(|error| ApiError::system(error.to_string()))?;
        if plugin.is_valid() {
            let validated = plugin
                .manifest
                .map(|manifest| sentinelflow_registry::ValidatedPlugin {
                    root: plugin_root,
                    manifest,
                })
                .ok_or_else(|| ApiError::system("valid plugin did not include a manifest"))?;
            registry
                .register(validated)
                .map_err(|error| ApiError::system(error.to_string()))?;
        }
    }
    Ok(registry)
}

fn parse_task_request(
    request: &TaskDocumentRequest,
    schema_root: &Path,
) -> Result<TaskSpec, ApiError> {
    let task = if let Some(task) = &request.task {
        task.clone()
    } else if let Some(content) = &request.content {
        serde_yaml::from_str(content)
            .map_err(|error| ApiError::bad_request(format!("invalid Task Spec: {error}")))?
    } else {
        return Err(ApiError::bad_request("content or task is required"));
    };
    task.validate(&ValidationContext::new(schema_root))
        .map_err(|errors| ApiError::bad_request(errors.to_string()))?;
    Ok(task)
}

fn persist_api_task(workspace_dir: &Path, task: &TaskSpec) -> Result<PathBuf, ApiError> {
    let directory = workspace_dir.join("tasks").join("api-submissions");
    fs::create_dir_all(&directory).map_err(|error| {
        ApiError::system(format!("failed to create task staging directory: {error}"))
    })?;
    let path = directory.join(format!(
        "{}-{}.yaml",
        task.metadata.name,
        now_rfc3339()?.replace([':', '.'], "-")
    ));
    let content = serde_yaml::to_string(task)
        .map_err(|error| ApiError::system(format!("failed to serialize Task Spec: {error}")))?;
    fs::write(&path, content)
        .map_err(|error| ApiError::system(format!("failed to stage Task Spec: {error}")))?;
    Ok(path)
}

fn enforce_report_finding_limit(count: usize, report_id: &str) -> Result<(), ApiError> {
    if count > DEFAULT_REPORT_MAX_FINDINGS {
        return Err(ApiError::conflict(format!(
            "report {report_id} has {count} findings, above v1.0-rc limit {DEFAULT_REPORT_MAX_FINDINGS}"
        )));
    }
    Ok(())
}

fn explain_policy(workspace_dir: &Path, task: &TaskSpec) -> Result<Vec<Value>, ApiError> {
    plan(task).map_err(|error| ApiError::from_plan(&error))?;
    let registry = load_registry(workspace_dir)?;
    let approval_status = task
        .spec
        .policy
        .approval_ref
        .as_ref()
        .and_then(|approval_id| {
            WorkspaceStore::open(workspace_dir)
                .ok()
                .and_then(|store| store.load_approval(approval_id).ok())
                .map(|approval| approval.status)
        });
    let mut explanations = Vec::new();
    for target in &task.spec.targets {
        for step in &task.spec.steps {
            let risk = registry
                .get(&step.tool_ref)
                .and_then(|tool| {
                    tool.manifest
                        .spec
                        .capabilities
                        .iter()
                        .find(|capability| capability.name == step.capability)
                })
                .map_or(RiskLevel::Critical, |capability| capability.risk);
            let decision = evaluate_task(&TaskPolicyRequest {
                authorization_scope: &task.spec.authorization_scope,
                target: &target.name,
                risk,
                approval: approval_status,
                utc_minute: current_utc_minute(),
                running_nodes: 0,
                starts_this_minute: 0,
                policy: &task.spec.policy,
            });
            explanations.push(json!({
                "target": target.name,
                "step": step.name,
                "tool": step.tool_ref,
                "capability": step.capability,
                "risk": risk,
                "decision": decision,
            }));
        }
    }
    Ok(explanations)
}

fn current_utc_minute() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    ((seconds / 60) % (24 * 60)) as u16
}

fn bundle_as_json(bundle: &sentinelflow_store::RunBundle) -> Value {
    json!({
        "run": bundle.run,
        "result": bundle.result,
        "auditEvents": bundle.audit_events,
    })
}

fn openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "SentinelFlow API",
            "version": "0.1.0",
            "description": "Team API for SentinelFlow. Web Console clients call this API; browser code never starts tools directly."
        },
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            },
            "schemas": {
                "TaskDocumentRequest": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"},
                        "task": {"type": "object"}
                    }
                }
            }
        },
        "paths": {
            "/api/session/login": {"post": {"summary": "Issue a replaceable-provider session token"}},
            "/api/tools": {"get": {"summary": "List tools"}},
            "/api/tools/{name}": {"get": {"summary": "Get tool details and Manifest"}},
            "/api/plugins": {"get": {"summary": "List plugin directories"}},
            "/api/plugins/validate": {"post": {"summary": "Validate a plugin package"}},
            "/api/plugins/install": {"post": {"summary": "Install a validated plugin package"}},
            "/api/plugins/test": {"post": {"summary": "Run a plugin fixture through the API/Core path"}},
            "/api/tasks": {"get": {"summary": "List persisted tasks", "parameters": paginated_parameters()}},
            "/api/tasks/validate": {"post": {"summary": "Validate a Task Spec"}},
            "/api/tasks/plan": {"post": {"summary": "Preview a DAG plan"}},
            "/api/tasks/run": {"post": {"summary": "Run a Task through SentinelFlow orchestration"}},
            "/api/tasks/{taskId}": {"get": {"summary": "Get task state"}},
            "/api/tasks/{taskId}/cancel": {"post": {"summary": "Cancel a task"}},
            "/api/tasks/{taskId}/logs": {"get": {"summary": "List task audit logs", "parameters": paginated_parameters()}},
            "/api/tasks/{taskId}/logs/stream": {"get": {"summary": "Stream task logs with reconnect cursor via SSE", "parameters": stream_parameters()}},
            "/api/runs": {"get": {"summary": "List runs", "parameters": paginated_parameters()}},
            "/api/runs/{runId}": {"get": {"summary": "Get run bundle"}},
            "/api/findings": {"get": {"summary": "List normalized findings", "parameters": paginated_parameters()}},
            "/api/reports": {"get": {"summary": "List reports", "parameters": paginated_parameters()}},
            "/api/reports/generate": {"post": {"summary": "Generate a Markdown report with a default finding-count upper bound"}},
            "/api/reports/{reportId}": {"get": {"summary": "Read a Markdown report"}},
            "/api/audit": {"get": {"summary": "List audit events", "parameters": paginated_parameters()}},
            "/api/approvals": {"get": {"summary": "List approvals", "parameters": paginated_parameters()}},
            "/api/approvals/request": {"post": {"summary": "Request approval"}},
            "/api/approvals/{approvalId}/approve": {"post": {"summary": "Approve"}},
            "/api/approvals/{approvalId}/reject": {"post": {"summary": "Reject"}},
            "/api/approvals/{approvalId}/expire": {"post": {"summary": "Expire"}},
            "/api/policy/explain": {"post": {"summary": "Explain policy by reusing Core policy evaluation"}}
        },
        "x-sentinelflow-boundary": {
            "webDoesNotExecuteTools": true,
            "policyIsServerSide": true,
            "auditRequiredForMutations": true
        }
    })
}

fn paginated_parameters() -> Value {
    json!([
        {
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_LIMIT},
            "description": "Maximum items to return. Defaults to 100 and is capped at 500."
        },
        {
            "name": "offset",
            "in": "query",
            "required": false,
            "schema": {"type": "integer", "minimum": 0},
            "description": "Zero-based item offset."
        }
    ])
}

fn stream_parameters() -> Value {
    json!([
        {
            "name": "cursor",
            "in": "query",
            "required": false,
            "schema": {"type": "integer", "minimum": 0},
            "description": "Zero-based reconnect cursor."
        },
        {
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": {"type": "integer", "minimum": 1, "maximum": MAX_LOG_LIMIT},
            "description": "Maximum events to emit before closing the SSE stream."
        }
    ])
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf()
    }

    async fn request_json(
        app: Router,
        method: &str,
        uri: impl Into<String>,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri.into())
            .header("authorization", format!("Bearer {token}"));
        let body = if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_string(&body).expect("request JSON"))
        } else {
            Body::empty()
        };
        let response = app
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                json!({
                    "text": String::from_utf8_lossy(&bytes)
                })
            })
        };
        (status, value)
    }

    fn task_body(root: &Path, fixture: &str) -> Value {
        json!({
            "content": fs::read_to_string(root.join(fixture)).expect("task fixture")
        })
    }

    fn install_plugin_body(root: &Path, name: &str) -> Value {
        json!({
            "path": root.join("plugins/examples").join(name)
        })
    }

    fn hhmm(minute: u16) -> String {
        format!("{:02}:{:02}", minute / 60, minute % 60)
    }

    #[tokio::test]
    async fn protected_routes_require_authentication_and_role() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let app = development_router(ApiConfig {
            workspace_dir: temporary.path().join(".sentinelflow"),
            schema_root: PathBuf::from("."),
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/tools")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/plugins/install")
                    .header("authorization", "Bearer viewer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"path":"plugins/examples/example-echo"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_endpoints_apply_pagination_limits() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let app = development_router(ApiConfig {
            workspace_dir: temporary.path().join(".sentinelflow"),
            schema_root: PathBuf::from("."),
        });
        for _ in 0..4 {
            let (status, _) =
                request_json(app.clone(), "GET", "/api/tools", "viewer-token", None).await;
            assert_eq!(status, StatusCode::OK);
        }

        let (status, audit) = request_json(
            app,
            "GET",
            "/api/audit?limit=2&offset=1",
            "viewer-token",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let events = audit.as_array().expect("audit array");
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event["spec"]["action"] == "api.tools.list")
        );
    }

    #[tokio::test]
    async fn api_plan_matches_orchestrator_plan() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let root = workspace_root();
        let task: TaskSpec = serde_yaml::from_slice(
            &fs::read(root.join("tests/fixtures/task.dag.yaml")).expect("task fixture"),
        )
        .expect("task spec");
        let expected = serde_json::to_value(plan(&task).expect("plan")).expect("plan JSON");
        let app = development_router(ApiConfig {
            workspace_dir: temporary.path().join(".sentinelflow"),
            schema_root: PathBuf::from("."),
        });
        let body = serde_json::to_string(&json!({"task": task})).expect("request");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tasks/plan")
                    .header("authorization", "Bearer viewer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let actual: Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn api_supports_plugin_to_report_flow() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let root = workspace_root();
        let app = development_router(ApiConfig {
            workspace_dir: temporary.path().join(".sentinelflow"),
            schema_root: root.clone(),
        });

        let plugin_body = serde_json::to_string(&json!({
            "path": root.join("plugins/examples/example-echo")
        }))
        .expect("plugin request");
        for path in ["/api/plugins/validate", "/api/plugins/install"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("authorization", "Bearer operator-token")
                        .header("content-type", "application/json")
                        .body(Body::from(plugin_body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/tools")
                    .header("authorization", "Bearer viewer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let task_content = fs::read_to_string(root.join("tests/fixtures/task.single-step.yaml"))
            .expect("task fixture");
        let task_body = serde_json::to_string(&json!({"content": task_content})).expect("request");
        let expected_policy = explain_policy(
            &temporary.path().join(".sentinelflow"),
            &serde_json::from_str::<Value>(&task_body).expect("task request JSON")["content"]
                .as_str()
                .and_then(|content| serde_yaml::from_str::<TaskSpec>(content).ok())
                .expect("task spec"),
        )
        .expect("policy explain");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/policy/explain")
                    .header("authorization", "Bearer viewer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(task_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let actual_policy: Value = serde_json::from_slice(&bytes).expect("policy JSON");
        assert_eq!(actual_policy, json!(expected_policy));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tasks/run")
                    .header("authorization", "Bearer operator-token")
                    .header("content-type", "application/json")
                    .body(Body::from(task_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let task: Value = serde_json::from_slice(&bytes).expect("task JSON");
        let task_id = task["taskId"].as_str().expect("task id");
        assert_eq!(task["status"], "completed");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/findings")
                    .header("authorization", "Bearer viewer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let report_body = serde_json::to_string(&json!({"task": task_id})).expect("report request");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/reports/generate")
                    .header("authorization", "Bearer operator-token")
                    .header("content-type", "application/json")
                    .body(Body::from(report_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/reports/{task_id}"))
                    .header("authorization", "Bearer viewer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let markdown = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(String::from_utf8_lossy(&markdown).contains("SentinelFlow Task Report"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit")
                    .header("authorization", "Bearer viewer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let audit: Value = serde_json::from_slice(&bytes).expect("audit JSON");
        let actions = audit
            .as_array()
            .expect("audit array")
            .iter()
            .filter_map(|event| event["spec"]["action"].as_str())
            .collect::<Vec<_>>();
        for expected in [
            "api.plugins.validate",
            "api.plugins.install",
            "api.policy.explain",
            "api.tasks.run",
            "api.reports.generate",
        ] {
            assert!(
                actions.contains(&expected),
                "missing audit action {expected}"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn api_rejects_rc_blocker_failure_modes() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let workspace = temporary.path().join(".sentinelflow");
        let root = workspace_root();
        let app = development_router(ApiConfig {
            workspace_dir: workspace.clone(),
            schema_root: root.clone(),
        });

        for plugin in ["example-echo", "example-high-risk", "example-failure"] {
            let (status, _) = request_json(
                app.clone(),
                "POST",
                "/api/plugins/install",
                "operator-token",
                Some(install_plugin_body(&root, plugin)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "install {plugin}");
        }

        let high_risk = task_body(&root, "tests/fixtures/task.high-risk.yaml");
        let (status, body) = request_json(
            app.clone(),
            "POST",
            "/api/tasks/run",
            "operator-token",
            Some(high_risk.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|value| value.contains("approved"))
        );

        let (status, approval) = request_json(
            app.clone(),
            "POST",
            "/api/approvals/request",
            "operator-token",
            Some(json!({"resource": "example-high-risk-task", "risk": "high"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let approval_id = approval["approvalId"].as_str().expect("approval id");
        let (status, _) = request_json(
            app.clone(),
            "POST",
            format!("/api/approvals/{approval_id}/approve"),
            "approver-token",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let approved_content = high_risk["content"]
            .as_str()
            .expect("task content")
            .replace(
                "approveHighRisk: false",
                &format!("approveHighRisk: false\n    approvalRef: {approval_id}"),
            );
        let (status, approved_run) = request_json(
            app.clone(),
            "POST",
            "/api/tasks/run",
            "operator-token",
            Some(json!({"content": approved_content})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(approved_run["status"], "completed");

        let unauthorized_content =
            task_body(&root, "tests/fixtures/task.single-step.yaml")["content"]
                .as_str()
                .expect("task content")
                .replace("      - fixture-two\n", "");
        let (status, _) = request_json(
            app.clone(),
            "POST",
            "/api/tasks/run",
            "operator-token",
            Some(json!({"content": unauthorized_content})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let now = current_utc_minute();
        let start = (now + 120) % (24 * 60);
        let end = (start + 1) % (24 * 60);
        let time_window_content =
            task_body(&root, "tests/fixtures/task.single-step.yaml")["content"]
                .as_str()
                .expect("task content")
                .replace(
                    "timeoutSeconds: 5",
                    &format!(
                        "timeoutSeconds: 5\n    timeWindows:\n      - start: {}\n        end: {}",
                        hhmm(start),
                        hhmm(end)
                    ),
                );
        let (status, body) = request_json(
            app.clone(),
            "POST",
            "/api/tasks/run",
            "operator-token",
            Some(json!({"content": time_window_content})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|value| value.contains("outside every allowed window"))
        );

        let failure_task = r"apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: api-failure-task
spec:
  authorizationScope: fixture:local-only
  targets:
    - name: fixture-one
      input:
        message: fail
  steps:
    - name: fails
      toolRef: example-failure
      capability: fail.fixture
  policy:
    allowedTargets: [fixture-one]
";
        let (status, _) = request_json(
            app.clone(),
            "POST",
            "/api/tasks/run",
            "operator-token",
            Some(json!({"content": failure_task})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let installed_manifest = workspace
            .join("plugins/example-echo")
            .join("sentinelflow.tool.yaml");
        let original_manifest = fs::read_to_string(&installed_manifest).expect("manifest");
        fs::write(
            &installed_manifest,
            original_manifest.replace("name: example-echo-v1", "name: fixture-invalid-output-v1"),
        )
        .expect("invalid parser manifest");
        let (status, body) = request_json(
            app.clone(),
            "POST",
            "/api/tasks/run",
            "operator-token",
            Some(task_body(&root, "tests/fixtures/task.single-step.yaml")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|value| value.contains("normalization contract"))
        );
        fs::write(&installed_manifest, original_manifest).expect("restore manifest");

        let (status, _) = request_json(
            app.clone(),
            "POST",
            "/api/reports/generate",
            "operator-token",
            Some(json!({"task": "task-does-not-exist"})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn task_log_sse_reconnects_from_cursor() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let workspace = temporary.path().join(".sentinelflow");
        let root = workspace_root();
        let app = development_router(ApiConfig {
            workspace_dir: workspace,
            schema_root: root.clone(),
        });
        let (status, _) = request_json(
            app.clone(),
            "POST",
            "/api/plugins/install",
            "operator-token",
            Some(install_plugin_body(&root, "example-echo")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, task) = request_json(
            app.clone(),
            "POST",
            "/api/tasks/run",
            "operator-token",
            Some(task_body(&root, "tests/fixtures/task.single-step.yaml")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let task_id = task["taskId"].as_str().expect("task id");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/tasks/{task_id}/logs/stream?cursor=1&limit=1&token=viewer-token"
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("sse body");
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("event: audit"));
        assert!(body.contains("\"cursor\":2"));
    }

    #[test]
    fn web_console_reconnects_logs_with_cursor() {
        assert!(CONSOLE_HTML.contains("cursor=${logCursor}"));
        assert!(CONSOLE_HTML.contains("logCursor = payload.cursor"));
        assert!(CONSOLE_HTML.contains("source.onerror"));
        assert!(CONSOLE_HTML.contains("source.close()"));
        assert!(CONSOLE_HTML.contains("setTimeout(connectLogs"));
    }
}
