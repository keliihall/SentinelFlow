//! Plugin discovery, validation, installation, and registry contracts.

use std::fs;
use std::path::PathBuf;

use sentinelflow_registry::{
    CheckStage, InstallOutcome, RegisterOutcome, ToolRegistry, discover_plugins, install_plugin,
    validate_plugin,
};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example_echo() -> PathBuf {
    workspace_root().join("plugins/examples/example-echo")
}

fn example(name: &str) -> PathBuf {
    workspace_root().join("plugins/examples").join(name)
}

fn official(name: &str) -> PathBuf {
    workspace_root().join("plugins/official").join(name)
}

#[test]
fn example_echo_passes_every_validation_stage() {
    let report = validate_plugin(example_echo()).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    for stage in [
        CheckStage::Structure,
        CheckStage::Semantic,
        CheckStage::Compatibility,
        CheckStage::Dependencies,
        CheckStage::Safety,
    ] {
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.stage == stage && check.passed),
            "missing passing stage: {stage:?}"
        );
    }
}

#[test]
fn all_safe_example_plugins_are_valid() {
    for name in ["example-echo", "example-dns-resolve", "example-file-import"] {
        let report = validate_plugin(example(name)).expect("validation must run");
        assert!(report.is_valid(), "{name}: {:?}", report.checks);
    }
}

#[test]
fn official_subdomain_discovery_plugin_is_valid() {
    let report = validate_plugin(official("subdomain-discovery")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "subdomain-discovery");
    assert_eq!(manifest.spec.parser.name, "example-file-import-v1");
}

#[test]
fn official_subdomain_discovery_plus_plugin_is_valid() {
    let report =
        validate_plugin(official("subdomain-discovery-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "subdomain-discovery-plus");
    assert_eq!(manifest.spec.parser.name, "subdomain-discovery-plus-v1");
}

#[test]
fn official_dns_resolve_plus_plugin_is_valid() {
    let report = validate_plugin(official("dns-resolve-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "dns-resolve-plus");
    assert_eq!(manifest.spec.parser.name, "dns-resolve-plus-v1");
}

#[test]
fn official_crtsh_subdomain_plus_plugin_is_valid() {
    let report = validate_plugin(official("crtsh-subdomain-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "crtsh-subdomain-plus");
    assert_eq!(manifest.spec.parser.name, "crtsh-subdomain-plus-v1");
}

#[test]
fn official_ip_enrichment_plus_plugin_is_valid() {
    let report = validate_plugin(official("ip-enrichment-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "ip-enrichment-plus");
    assert_eq!(manifest.spec.parser.name, "ip-enrichment-plus-v1");
}

#[test]
fn official_service_detect_plus_plugin_is_valid() {
    let report = validate_plugin(official("service-detect-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "service-detect-plus");
    assert_eq!(manifest.spec.parser.name, "service-detect-plus-v1");
}

#[test]
fn official_http_probe_plus_plugin_is_valid() {
    let report = validate_plugin(official("http-probe-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "http-probe-plus");
    assert_eq!(manifest.spec.parser.name, "http-probe-plus-v1");
}

#[test]
fn official_web_fingerprint_plus_plugin_is_valid() {
    let report = validate_plugin(official("web-fingerprint-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "web-fingerprint-plus");
    assert_eq!(manifest.spec.parser.name, "web-fingerprint-plus-v1");
}

#[test]
fn official_tls_certificate_check_plus_plugin_is_valid() {
    let report =
        validate_plugin(official("tls-certificate-check-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "tls-certificate-check-plus");
    assert_eq!(manifest.spec.parser.name, "tls-certificate-check-plus-v1");
}

#[test]
fn official_fofa_import_plus_plugin_is_valid() {
    let report = validate_plugin(official("fofa-import-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "fofa-import-plus");
    assert_eq!(manifest.spec.parser.name, "fofa-import-plus-v1");
}

#[test]
fn official_shodan_import_plus_plugin_is_valid() {
    let report = validate_plugin(official("shodan-import-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "shodan-import-plus");
    assert_eq!(manifest.spec.parser.name, "shodan-import-plus-v1");
}

#[test]
fn official_censys_import_plus_plugin_is_valid() {
    let report = validate_plugin(official("censys-import-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "censys-import-plus");
    assert_eq!(manifest.spec.parser.name, "censys-import-plus-v1");
}

#[test]
fn official_nessus_import_plus_plugin_is_valid() {
    let report = validate_plugin(official("nessus-import-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "nessus-import-plus");
    assert_eq!(manifest.spec.parser.name, "nessus-import-plus-v1");
}

#[test]
fn official_openvas_import_plus_plugin_is_valid() {
    let report = validate_plugin(official("openvas-import-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "openvas-import-plus");
    assert_eq!(manifest.spec.parser.name, "openvas-import-plus-v1");
}

#[test]
fn official_nuclei_adapter_plus_plugin_is_valid() {
    let report = validate_plugin(official("nuclei-adapter-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "nuclei-adapter-plus");
    assert_eq!(manifest.spec.parser.name, "nuclei-adapter-plus-v1");
}

#[test]
fn official_zap_baseline_plus_plugin_is_valid() {
    let report = validate_plugin(official("zap-baseline-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "zap-baseline-plus");
    assert_eq!(manifest.spec.parser.name, "zap-baseline-plus-v1");
}

#[test]
fn official_cloud_asset_import_plus_plugin_is_valid() {
    let report = validate_plugin(official("cloud-asset-import-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "cloud-asset-import-plus");
    assert_eq!(manifest.spec.parser.name, "cloud-asset-import-plus-v1");
}

#[test]
fn official_cmdb_sync_plus_plugin_is_valid() {
    let report = validate_plugin(official("cmdb-sync-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "cmdb-sync-plus");
    assert_eq!(manifest.spec.parser.name, "cmdb-sync-plus-v1");
}

#[test]
fn official_markdown_report_plus_plugin_is_valid() {
    let report = validate_plugin(official("markdown-report-plus")).expect("validation must run");
    assert!(report.is_valid(), "{:?}", report.checks);
    let manifest = report.manifest.expect("manifest");
    assert_eq!(manifest.metadata.name, "markdown-report-plus");
    assert_eq!(manifest.spec.parser.name, "markdown-report-plus-v1");
}

#[test]
fn official_plugins_declare_p5_6_fixture_or_disabled_status() {
    let expected = [
        ("censys-import-plus", "disabled-future"),
        ("cloud-asset-import-plus", "fixture-only"),
        ("cmdb-sync-plus", "fixture-only"),
        ("crtsh-subdomain-plus", "disabled-future"),
        ("dns-resolve-plus", "disabled-future"),
        ("fofa-import-plus", "disabled-future"),
        ("http-probe-plus", "disabled-future"),
        ("ip-enrichment-plus", "disabled-future"),
        ("markdown-report-plus", "fixture-only"),
        ("nessus-import-plus", "fixture-only"),
        ("nuclei-adapter-plus", "fixture-only"),
        ("openvas-import-plus", "fixture-only"),
        ("port-probe-plus", "disabled-future"),
        ("service-detect-plus", "disabled-future"),
        ("shodan-import-plus", "disabled-future"),
        ("subdomain-discovery", "disabled-future"),
        ("subdomain-discovery-plus", "disabled-future"),
        ("tls-certificate-check-plus", "disabled-future"),
        ("web-fingerprint-plus", "disabled-future"),
        ("zap-baseline-plus", "fixture-only"),
    ];

    for (name, status) in expected {
        let report = validate_plugin(official(name)).expect("validation must run");
        assert!(report.is_valid(), "{name}: {:?}", report.checks);
        let manifest = report.manifest.expect("manifest");
        let actual = manifest
            .extensions
            .get("sentinelflow.io/p5_6_status")
            .and_then(|value| value.as_str());
        assert_eq!(actual, Some(status), "{name}");
    }
}

#[test]
fn examples_root_is_supported_by_discovery() {
    let root = workspace_root().join("plugins/examples");
    let discovery = discover_plugins([root]).expect("discovery must succeed");
    for name in ["example-echo", "example-dns-resolve", "example-file-import"] {
        assert!(discovery.plugins.contains(&example(name)));
    }
}

#[test]
fn official_plugins_root_is_supported_by_discovery() {
    let root = workspace_root().join("plugins/official");
    let discovery = discover_plugins([root]).expect("discovery must succeed");
    assert!(discovery.plugins.contains(&official("subdomain-discovery")));
    assert!(
        discovery
            .plugins
            .contains(&official("subdomain-discovery-plus"))
    );
    assert!(
        discovery
            .plugins
            .contains(&official("crtsh-subdomain-plus"))
    );
    assert!(discovery.plugins.contains(&official("dns-resolve-plus")));
    assert!(discovery.plugins.contains(&official("ip-enrichment-plus")));
    assert!(discovery.plugins.contains(&official("http-probe-plus")));
    assert!(
        discovery
            .plugins
            .contains(&official("web-fingerprint-plus"))
    );
    assert!(
        discovery
            .plugins
            .contains(&official("tls-certificate-check-plus"))
    );
    assert!(discovery.plugins.contains(&official("fofa-import-plus")));
    assert!(discovery.plugins.contains(&official("shodan-import-plus")));
    assert!(discovery.plugins.contains(&official("censys-import-plus")));
    assert!(discovery.plugins.contains(&official("nessus-import-plus")));
    assert!(discovery.plugins.contains(&official("openvas-import-plus")));
    assert!(discovery.plugins.contains(&official("nuclei-adapter-plus")));
    assert!(discovery.plugins.contains(&official("zap-baseline-plus")));
    assert!(
        discovery
            .plugins
            .contains(&official("cloud-asset-import-plus"))
    );
    assert!(discovery.plugins.contains(&official("cmdb-sync-plus")));
    assert!(
        discovery
            .plugins
            .contains(&official("markdown-report-plus"))
    );
    assert!(discovery.plugins.contains(&official("service-detect-plus")));
}

#[test]
fn installation_is_idempotent_and_registry_is_queryable() {
    let temporary = TempDir::new().expect("temporary directory");
    let plugins = temporary.path().join("plugins");

    let first = install_plugin(example_echo(), &plugins).expect("first install");
    assert!(matches!(first, InstallOutcome::Installed(_)));
    let second = install_plugin(example_echo(), &plugins).expect("second install");
    assert!(matches!(second, InstallOutcome::AlreadyInstalled(_)));

    let discovery = discover_plugins([&plugins]).expect("discover installed plugin");
    let mut registry = ToolRegistry::new();
    for path in discovery.plugins {
        let plugin = validate_plugin(path)
            .expect("validation must run")
            .into_validated()
            .expect("installed plugin must remain valid");
        assert_eq!(
            registry.register(plugin).expect("register"),
            RegisterOutcome::Registered
        );
    }
    let tool = registry
        .get("example-echo")
        .expect("tool must be queryable");
    assert_eq!(tool.manifest.spec.version, "0.1.0");
    assert!(tool.enabled);
    registry
        .set_enabled("example-echo", false)
        .expect("disable must work");
    assert!(!registry.get("example-echo").expect("tool").enabled);
}

#[test]
fn a_different_installed_version_is_rejected_without_overwrite() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = temporary.path().join("source");
    copy_fixture(&example_echo(), &source);
    let plugins = temporary.path().join("plugins");
    install_plugin(&source, &plugins).expect("initial install");

    let manifest_path = source.join("sentinelflow.tool.yaml");
    let manifest = fs::read_to_string(&manifest_path).expect("manifest");
    fs::write(
        &manifest_path,
        manifest.replace("version: 0.1.0", "version: 0.2.0"),
    )
    .expect("updated source manifest");

    let error = install_plugin(&source, &plugins).expect_err("version must conflict");
    assert!(error.to_string().contains("version conflict"));
    let installed = fs::read_to_string(plugins.join("example-echo").join("sentinelflow.tool.yaml"))
        .expect("installed manifest");
    assert!(installed.contains("version: 0.1.0"));
}

#[cfg(unix)]
#[test]
fn package_symlinks_fail_safety_validation() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().expect("temporary directory");
    let source = temporary.path().join("source");
    copy_fixture(&example_echo(), &source);
    symlink(
        source.join("README.md"),
        source.join("examples/linked-readme"),
    )
    .expect("create symlink");

    let report = validate_plugin(&source).expect("validation must run");
    assert!(!report.is_valid());
    let safety = report
        .checks
        .iter()
        .find(|check| check.stage == CheckStage::Safety)
        .expect("safety stage");
    assert!(!safety.passed);
    assert!(
        safety
            .messages
            .iter()
            .any(|message| message.contains("symbolic links"))
    );
}

#[test]
fn structural_dependency_and_runtime_failures_are_reported_by_stage() {
    let temporary = TempDir::new().expect("temporary directory");

    let structural_root = temporary.path().join("structural");
    copy_fixture(&example_echo(), &structural_root);
    let manifest_path = structural_root.join("sentinelflow.tool.yaml");
    let manifest = fs::read_to_string(&manifest_path).expect("manifest");
    fs::write(
        &manifest_path,
        manifest.replace(
            "apiVersion: sentinelflow.io/v1alpha1",
            "apiVersion: sentinelflow.io/v9",
        ),
    )
    .expect("invalid manifest");
    let structural = validate_plugin(&structural_root).expect("validation");
    assert!(
        structural
            .checks
            .iter()
            .any(|check| check.stage == CheckStage::Structure && !check.passed)
    );

    let dependency_root = temporary.path().join("dependency");
    copy_fixture(&example_echo(), &dependency_root);
    fs::remove_dir_all(dependency_root.join("parser")).expect("remove parser");
    fs::remove_file(dependency_root.join("schemas/input.schema.json")).expect("remove schema");
    let dependency = validate_plugin(&dependency_root).expect("validation");
    let dependency_check = dependency
        .checks
        .iter()
        .find(|check| check.stage == CheckStage::Dependencies)
        .expect("dependencies stage");
    assert!(!dependency_check.passed);
    assert!(
        dependency_check
            .messages
            .iter()
            .any(|message| message.contains("$.package.parser"))
    );
    assert!(
        dependency_check
            .messages
            .iter()
            .any(|message| message.contains("$.spec.inputSchema"))
    );

    let runtime_root = temporary.path().join("runtime");
    copy_fixture(&example_echo(), &runtime_root);
    let manifest_path = runtime_root.join("sentinelflow.tool.yaml");
    let manifest = fs::read_to_string(&manifest_path).expect("manifest");
    fs::write(
        &manifest_path,
        manifest
            .replace("mode: process", "mode: container")
            .replace("version: 0.1.0", "version: not-semver"),
    )
    .expect("unsupported runtime manifest");
    let runtime = validate_plugin(&runtime_root).expect("validation");
    let compatibility = runtime
        .checks
        .iter()
        .find(|check| check.stage == CheckStage::Compatibility)
        .expect("compatibility stage");
    assert!(!compatibility.passed);
    assert!(
        compatibility
            .messages
            .iter()
            .any(|message| message.contains("$.spec.runtime.mode"))
    );
    assert!(
        compatibility
            .messages
            .iter()
            .any(|message| message.contains("$.spec.version"))
    );
}

#[test]
fn unsafe_tool_name_cannot_escape_install_root() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = temporary.path().join("source");
    copy_fixture(&example_echo(), &source);
    let manifest_path = source.join("sentinelflow.tool.yaml");
    let manifest = fs::read_to_string(&manifest_path).expect("manifest");
    fs::write(
        &manifest_path,
        manifest.replace("name: example-echo", "name: ../outside"),
    )
    .expect("unsafe manifest");

    let report = validate_plugin(&source).expect("validation");
    let safety = report
        .checks
        .iter()
        .find(|check| check.stage == CheckStage::Safety)
        .expect("safety stage");
    assert!(!safety.passed);
    assert!(
        safety
            .messages
            .iter()
            .any(|message| message.contains("$.metadata.name"))
    );

    let plugins = temporary.path().join("plugins");
    assert!(install_plugin(&source, &plugins).is_err());
    assert!(!temporary.path().join("outside").exists());
}

fn copy_fixture(source: &std::path::Path, destination: &std::path::Path) {
    fs::create_dir(destination).expect("destination");
    for entry in fs::read_dir(source).expect("fixture directory") {
        let entry = entry.expect("fixture entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_fixture(&source_path, &destination_path);
        } else {
            fs::copy(source_path, destination_path).expect("copy fixture file");
        }
    }
}
