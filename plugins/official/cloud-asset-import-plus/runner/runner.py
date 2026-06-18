#!/usr/bin/env python3
"""Bounded multi-cloud inventory importer for SentinelFlow."""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "cloud-asset-import-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
PROVIDERS = {"alibaba", "tencent", "huawei", "aws", "azure"}
RESOURCE_TYPES = {"compute", "public_ip", "load_balancer", "security_group", "dns", "object_storage", "waf", "cdn"}
SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|api.?key|access.?key|private.?key|credential|authorization)")
SECRET_TEXT = re.compile(r"(?i)(password|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*\S+")


class InputError(Exception):
    """Controlled input validation error."""

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message)
        self.field = field


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        output = run(payload)
    except json.JSONDecodeError as error:
        print(f"invalid JSON input: {error}", file=sys.stderr)
        return 2
    except InputError as error:
        print(f"{error.field}: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"runner import failure: {safe_message(error)}", file=sys.stderr)
        return 2
    json.dump(output, sys.stdout, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise InputError("input must be a JSON object", "$")
    context = object_at(payload, "context", "$.context")
    authorization_scope = string_at(context, "authorization_scope", "$.context.authorization_scope")
    target = object_at(payload, "target", "$.target")
    if string_at(target, "type", "$.target.type") != "cloud_inventory":
        raise InputError("target.type must be cloud_inventory", "$.target.type")
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "local_file"}:
        raise InputError("unsupported cloud import mode", "$.options.mode")
    sources = options.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 32:
        raise InputError("sources must contain 1 to 32 entries", "$.options.sources")
    filters = object_at(options, "filters", "$.options.filters")
    output_options = object_at(options, "output", "$.options.output")
    policy = object_at(payload, "policy", "$.policy")
    for key in ("allow_cloud_api", "allow_credential_use", "allow_asset_connections", "allow_mutation"):
        if bool(policy.get(key)):
            raise InputError("online or mutating cloud operations are not supported", f"$.policy.{key}")

    validated_sources = [validate_source(item, index) for index, item in enumerate(sources)]
    if mode == "dry_run":
        statuses = [source_status(item, "planned", 0, "offline source validated; file not read") for item in validated_sources]
        return build_output(target, mode, authorization_scope, [], statuses, [], 0, 0)

    provider_filter = normalized_filter(filters.get("providers"), PROVIDERS, "$.options.filters.providers")
    type_filter = normalized_filter(filters.get("resource_types"), RESOURCE_TYPES, "$.options.filters.resource_types")
    observations: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for source in validated_sources:
        if provider_filter and source["provider"] not in provider_filter:
            statuses.append(source_status(source, "filtered", 0, "provider excluded by input filter"))
            continue
        if type_filter and source["resource_type"] not in type_filter:
            statuses.append(source_status(source, "filtered", 0, "resource type excluded by input filter"))
            continue
        try:
            records = load_source(source)
        except (InputError, OSError, json.JSONDecodeError) as error:
            statuses.append(source_status(source, "error", 0, safe_message(error)))
            if len(errors) < MAX_ERRORS:
                errors.append({"code": "CloudSourceImportFailed", "message": safe_message(error), "field": "$.options.sources"})
            continue
        observations.extend(records)
        statuses.append(source_status(source, "ok", len(records), "provider inventory imported"))

    results = merge_results(observations) if bool(output_options.get("deduplicate")) else sorted(observations, key=result_sort_key)
    if bool(filters.get("internet_exposed_only")):
        results = [item for item in results if item["internet_exposed"]]
    max_records = bounded_int(output_options.get("max_records"), 1000, 0, MAX_RESULTS)
    results = results[:max_records]
    for result in results:
        if not bool(output_options.get("include_tags")):
            result["tags"] = {}
        if not bool(output_options.get("include_security_rules")):
            result["security_rules"] = []
        if not bool(output_options.get("include_source_details")):
            result["source_details"] = []
    return build_output(target, mode, authorization_scope, results, statuses, errors, len(observations), len(validated_sources))


def validate_source(value: Any, index: int) -> dict[str, str]:
    if not isinstance(value, dict):
        raise InputError("source must be an object", f"$.options.sources[{index}]")
    provider = string_at(value, "provider", f"$.options.sources[{index}].provider").lower()
    resource_type = string_at(value, "resource_type", f"$.options.sources[{index}].resource_type").lower()
    if provider not in PROVIDERS:
        raise InputError("unsupported cloud provider", f"$.options.sources[{index}].provider")
    if resource_type not in RESOURCE_TYPES:
        raise InputError("unsupported cloud resource type", f"$.options.sources[{index}].resource_type")
    return {
        "provider": provider,
        "resource_type": resource_type,
        "file": string_at(value, "file", f"$.options.sources[{index}].file"),
        "scope_id": string_at(value, "scope_id", f"$.options.sources[{index}].scope_id"),
        "region": string_at(value, "region", f"$.options.sources[{index}].region"),
    }


def load_source(source: dict[str, str]) -> list[dict[str, Any]]:
    path = resolve_plugin_file(source["file"])
    document = json.loads(path.read_text(encoding="utf-8"))
    raw_records = extract_records(document, source["provider"], source["resource_type"])
    return [normalize_record(item, source, index) for index, item in enumerate(raw_records) if isinstance(item, dict)]


def extract_records(document: Any, provider: str, resource_type: str) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if not isinstance(document, dict):
        raise InputError("cloud inventory must be a JSON object or array", "$.options.sources.file")
    paths = provider_paths(provider, resource_type)
    for path in paths:
        value = get_path(document, path)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
    if looks_like_resource(document):
        return [document]
    return []


def provider_paths(provider: str, resource_type: str) -> list[tuple[str, ...]]:
    common = [("resources",), ("items",), ("value",), ("data",)]
    mapping: dict[tuple[str, str], list[tuple[str, ...]]] = {
        ("aws", "compute"): [("Reservations", "*", "Instances"), ("Instances",)],
        ("aws", "public_ip"): [("Addresses",)],
        ("aws", "load_balancer"): [("LoadBalancers",)],
        ("aws", "security_group"): [("SecurityGroups",)],
        ("aws", "dns"): [("ResourceRecordSets",), ("HostedZones",)],
        ("aws", "object_storage"): [("Buckets",)],
        ("aws", "waf"): [("WebACLs",)],
        ("aws", "cdn"): [("DistributionList", "Items"), ("Distributions",)],
        ("alibaba", "compute"): [("Instances", "Instance"), ("Instances",)],
        ("alibaba", "public_ip"): [("EipAddresses", "EipAddress"), ("EipAddresses",)],
        ("alibaba", "load_balancer"): [("LoadBalancers", "LoadBalancer"), ("LoadBalancers",)],
        ("alibaba", "security_group"): [("SecurityGroups", "SecurityGroup"), ("SecurityGroups",)],
        ("alibaba", "dns"): [("DomainRecords", "Record"), ("Records", "Record"), ("Records",)],
        ("alibaba", "object_storage"): [("Buckets", "Bucket"), ("Buckets",)],
        ("alibaba", "waf"): [("WebACLs",), ("Instances", "Instance")],
        ("alibaba", "cdn"): [("Domains", "PageData"), ("Domains",)],
        ("tencent", "compute"): [("Response", "InstanceSet"), ("InstanceSet",)],
        ("tencent", "public_ip"): [("Response", "AddressSet"), ("AddressSet",)],
        ("tencent", "load_balancer"): [("Response", "LoadBalancerSet"), ("LoadBalancerSet",)],
        ("tencent", "security_group"): [("Response", "SecurityGroupSet"), ("SecurityGroupSet",)],
        ("tencent", "dns"): [("Response", "RecordList"), ("RecordList",)],
        ("tencent", "object_storage"): [("Response", "Buckets"), ("Buckets",)],
        ("tencent", "waf"): [("Response", "Data"), ("Data",)],
        ("tencent", "cdn"): [("Response", "Domains"), ("Domains",)],
        ("huawei", "compute"): [("servers",)],
        ("huawei", "public_ip"): [("publicips",), ("public_ips",)],
        ("huawei", "load_balancer"): [("loadbalancers",)],
        ("huawei", "security_group"): [("security_groups",)],
        ("huawei", "dns"): [("recordsets",)],
        ("huawei", "object_storage"): [("buckets",)],
        ("huawei", "waf"): [("items",), ("instances",)],
        ("huawei", "cdn"): [("domains",)],
        ("azure", "compute"): [("value",), ("data",)],
        ("azure", "public_ip"): [("value",), ("data",)],
        ("azure", "load_balancer"): [("value",), ("data",)],
        ("azure", "security_group"): [("value",), ("data",)],
        ("azure", "dns"): [("value",), ("data",)],
        ("azure", "object_storage"): [("value",), ("data",)],
        ("azure", "waf"): [("value",), ("data",)],
        ("azure", "cdn"): [("value",), ("data",)],
    }
    return mapping.get((provider, resource_type), []) + common


def get_path(value: Any, path: tuple[str, ...]) -> Any:
    current = value
    for index, part in enumerate(path):
        if part == "*":
            if not isinstance(current, list):
                return None
            remainder = path[index + 1:]
            merged = []
            for item in current:
                nested = get_path(item, remainder)
                if isinstance(nested, list):
                    merged.extend(nested)
            return merged
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def normalize_record(raw: dict[str, Any], source: dict[str, str], index: int) -> dict[str, Any]:
    provider = source["provider"]
    resource_type = source["resource_type"]
    properties = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
    resource_id = first_text(raw, properties, keys=id_keys(provider, resource_type))
    if not resource_id:
        resource_id = f"{provider}:{source['scope_id']}:{source['region']}:{resource_type}:{index}"
    name = (
        first_text(raw, properties, keys=("name", "Name", "InstanceName", "LoadBalancerName", "SecurityGroupName", "DomainName", "BucketName", "RecordName"))
        or tag_name(raw.get("tags") or raw.get("Tags") or properties.get("tags"))
        or resource_id
    )
    status = first_text(raw, properties, keys=("status", "Status", "State", "InstanceState", "ProvisioningState", "provisioningState", "resourceState"))
    public_ips, private_ips = collect_ips(raw, resource_type)
    dns_names = collect_dns(raw, resource_type)
    tags = clean_tags(raw.get("tags") or raw.get("Tags") or properties.get("tags"))
    security_rules = clean_security_rules(raw, properties) if resource_type == "security_group" else []
    exposure_reasons = exposure_signals(resource_type, raw, public_ips, dns_names, security_rules)
    internet_exposed = bool(exposure_reasons)
    risk = risk_for(resource_type, exposure_reasons)
    source_name = f"{provider}:{resource_type}"
    return {
        "type": "cloud_asset_result",
        "provider": provider,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "name": name,
        "scope_id": source["scope_id"],
        "region": first_text(raw, properties, keys=("region", "RegionId", "Placement", "location")) or source["region"],
        "status": status,
        "public_ips": public_ips,
        "private_ips": private_ips,
        "dns_names": dns_names,
        "internet_exposed": internet_exposed,
        "exposure_reasons": exposure_reasons,
        "risk": risk,
        "tags": tags,
        "security_rules": security_rules,
        "sources": [source_name],
        "source_count": 1,
        "source_details": [{"source": source_name, "file": source["file"], "scope_id": source["scope_id"], "region": source["region"]}],
        "confidence": 0.92,
        "evidence": {
            "summary": f"{provider} {resource_type} asset {name} imported from offline inventory.",
            "items": [{"public_ips": public_ips, "dns_names": dns_names, "exposure_reasons": exposure_reasons}],
        },
    }


def id_keys(provider: str, resource_type: str) -> tuple[str, ...]:
    common = ("id", "Id", "arn", "Arn", "resourceId", "ResourceId")
    specific = {
        "compute": ("InstanceId", "instance_id", "server_id", "vmId"),
        "public_ip": ("AllocationId", "AddressId", "PublicIpId", "publicip_id"),
        "load_balancer": ("LoadBalancerArn", "LoadBalancerId", "loadbalancer_id", "id"),
        "security_group": ("GroupId", "SecurityGroupId", "security_group_id"),
        "dns": ("RecordId", "record_id", "Name"),
        "object_storage": ("BucketArn", "BucketName", "Name"),
        "waf": ("WebACLId", "InstanceId", "id"),
        "cdn": ("DistributionId", "DomainName", "id"),
    }
    return specific.get(resource_type, ()) + common


def collect_ips(value: Any, resource_type: str) -> tuple[list[str], list[str]]:
    public: set[str] = set()
    private: set[str] = set()
    walk_values(
        value,
        lambda key, item: classify_ip(
            key,
            item,
            public,
            private,
            allow_any=resource_type in {"public_ip", "dns"},
            force_public=resource_type in {"public_ip", "dns"},
        ),
    )
    return sorted(public), sorted(private)


def classify_ip(
    key: str,
    value: Any,
    public: set[str],
    private: set[str],
    *,
    allow_any: bool,
    force_public: bool,
) -> None:
    if not isinstance(value, str):
        return
    key_lower = key.lower()
    if not allow_any and "ip" not in key_lower and "address" not in key_lower:
        return
    for candidate in re.split(r"[,;\s]+", value):
        try:
            address = ipaddress.ip_address(candidate.strip())
        except ValueError:
            continue
        explicitly_public = "public" in key_lower or key_lower.startswith("eip") or "elasticip" in key_lower
        if force_public or explicitly_public or address.is_global:
            public.add(str(address))
        else:
            private.add(str(address))


def collect_dns(value: Any, resource_type: str) -> list[str]:
    names: set[str] = set()
    def visit(key: str, item: Any) -> None:
        if not isinstance(item, str):
            return
        lowered = key.lower()
        if resource_type != "dns" and not any(token in lowered for token in ("dns", "domain", "hostname", "endpoint", "record", "cname", "fqdn")):
            return
        candidate = item.strip().rstrip(".").lower()
        try:
            ipaddress.ip_address(candidate)
            return
        except ValueError:
            pass
        if len(candidate) <= 253 and "." in candidate and " " not in candidate and not candidate.startswith(("http://", "https://")):
            names.add(candidate)
    walk_values(value, visit)
    return sorted(names)


def walk_values(value: Any, visitor: Any, key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            visitor(str(child_key), child)
            walk_values(child, visitor, str(child_key))
    elif isinstance(value, list):
        for child in value:
            walk_values(child, visitor, key)


def clean_tags(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if isinstance(value, dict):
        pairs = value.items()
    elif isinstance(value, list):
        pairs = []
        for item in value:
            if isinstance(item, dict):
                pairs.append((item.get("Key") or item.get("key") or item.get("TagKey"), item.get("Value") or item.get("value") or item.get("TagValue")))
    else:
        pairs = []
    for key, item in pairs:
        name = text(key, 128)
        if not name:
            continue
        result[name] = "[REDACTED]" if SECRET_KEY.search(name) else redact(text(item, 512) or "")
        if len(result) >= 64:
            break
    return result


def tag_name(value: Any) -> str | None:
    tags = clean_tags(value)
    for key, item in tags.items():
        if key.lower() == "name" and item != "[REDACTED]":
            return text(item, 2048)
    return None


def clean_security_rules(raw: dict[str, Any], properties: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = (
        raw.get("IpPermissions") or raw.get("SecurityGroupPolicySet") or raw.get("security_group_rules")
        or properties.get("securityRules") or properties.get("security_rules") or []
    )
    if isinstance(candidates, dict):
        for key in ("Ingress", "Egress", "SecurityGroupPolicy", "rules"):
            if isinstance(candidates.get(key), list):
                candidates = candidates[key]
                break
    if not isinstance(candidates, list):
        return []
    result = []
    for rule in candidates[:256]:
        if not isinstance(rule, dict):
            continue
        serialized = json.dumps(rule, ensure_ascii=True).lower()
        result.append({
            "direction": first_text(rule, {}, keys=("direction", "Direction", "Access")) or ("inbound" if "ingress" in serialized else "unknown"),
            "protocol": first_text(rule, {}, keys=("IpProtocol", "Protocol", "protocol")) or "any",
            "from_port": first_int(rule, ("FromPort", "PortStart", "port_range_min")),
            "to_port": first_int(rule, ("ToPort", "PortEnd", "port_range_max")),
            "source": first_text(rule, {}, keys=("CidrIp", "SourceCidrIp", "remote_ip_prefix", "source")) or extract_open_cidr(serialized),
            "access": first_text(rule, {}, keys=("Access", "Action", "action")) or "allow",
        })
    return result


def exposure_signals(resource_type: str, raw: dict[str, Any], public_ips: list[str], dns_names: list[str], rules: list[dict[str, Any]]) -> list[str]:
    reasons = []
    serialized = json.dumps(raw, ensure_ascii=True).lower()
    if public_ips:
        reasons.append("public_ip")
    if resource_type in {"load_balancer", "cdn", "waf"} and dns_names:
        reasons.append("public_endpoint")
    if resource_type == "dns" and dns_names:
        reasons.append("public_dns_record")
    if resource_type == "object_storage" and any(token in serialized for token in ('"public"', "allusers", "authenticated-read", "public-read")):
        reasons.append("public_object_storage")
    if resource_type == "security_group":
        for rule in rules:
            if rule.get("source") in {"0.0.0.0/0", "::/0", "*", "any"} and str(rule.get("access", "allow")).lower() != "deny":
                reasons.append("open_security_group_rule")
                break
    return sorted(set(reasons))


def risk_for(resource_type: str, reasons: list[str]) -> str:
    if "public_object_storage" in reasons or "open_security_group_rule" in reasons:
        return "medium"
    if reasons and resource_type in {"compute", "public_ip", "load_balancer", "dns"}:
        return "low"
    return "info"


def merge_results(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for item in observations:
        key = (item["provider"], item["scope_id"], item["resource_type"], item["resource_id"])
        grouped.setdefault(key, []).append(item)
    results = []
    for items in grouped.values():
        selected = items[0]
        selected["public_ips"] = sorted({value for item in items for value in item["public_ips"]})
        selected["private_ips"] = sorted({value for item in items for value in item["private_ips"]})
        selected["dns_names"] = sorted({value for item in items for value in item["dns_names"]})
        selected["exposure_reasons"] = sorted({value for item in items for value in item["exposure_reasons"]})
        selected["internet_exposed"] = bool(selected["exposure_reasons"])
        selected["sources"] = sorted({value for item in items for value in item["sources"]})
        selected["source_count"] = len(selected["sources"])
        selected["source_details"] = [detail for item in items for detail in item["source_details"]]
        selected["confidence"] = min(0.92 + 0.02 * (len(items) - 1), 0.98)
        results.append(selected)
    return sorted(results, key=result_sort_key)


def result_sort_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return item["provider"], item["scope_id"], item["resource_type"], item["resource_id"]


def build_output(
    target: dict[str, Any], mode: str, authorization_scope: str,
    results: list[dict[str, Any]], statuses: list[dict[str, Any]],
    errors: list[dict[str, Any]], observation_count: int, source_count: int,
) -> dict[str, Any]:
    providers = sorted({item["provider"] for item in results})
    resource_types = sorted({item["resource_type"] for item in results})
    return {
        "source": SOURCE,
        "target": {"type": target.get("type"), "value": target.get("value")},
        "mode": mode,
        "results": results[:MAX_RESULTS],
        "source_status": statuses[:32],
        "summary": {
            "source_count": source_count,
            "observation_count": observation_count,
            "result_count": len(results),
            "internet_exposed_count": sum(1 for item in results if item["internet_exposed"]),
            "providers": providers,
            "resource_types": resource_types,
            "requires_cloud_api": False,
            "requires_credentials": False,
            "requires_approval": False,
            "error_count": len(errors),
            "authorization_scope": authorization_scope,
        },
        "errors": errors[:MAX_ERRORS],
        "safety": {
            "authorization_scope_required": True,
            "offline_import_only": True,
            "cloud_api_calls": 0,
            "credential_use": False,
            "active_asset_connections": 0,
            "mutations": 0,
            "secret_redaction_enabled": True,
            "file_boundary_enforced": True,
        },
    }


def source_status(source: dict[str, str], status: str, record_count: int, message: str) -> dict[str, Any]:
    return {
        "source": f"{source['provider']}:{source['resource_type']}",
        "provider": source["provider"],
        "resource_type": source["resource_type"],
        "status": status,
        "message": message,
        "record_count": record_count,
        "query_count": 0,
        "probe_count": 0,
    }


def normalized_filter(value: Any, choices: set[str], field: str) -> set[str]:
    if not isinstance(value, list):
        raise InputError("filter must be an array", field)
    result = {str(item).strip().lower() for item in value}
    if not result.issubset(choices):
        raise InputError("filter contains unsupported values", field)
    return result


def first_text(primary: dict[str, Any], secondary: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for source in (primary, secondary):
        for key in keys:
            value = source.get(key)
            if isinstance(value, dict):
                value = value.get("Name") or value.get("name") or value.get("Value") or value.get("value")
            if isinstance(value, (str, int)) and str(value).strip():
                return text(value, 2048)
    return None


def first_int(value: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        try:
            if key in value:
                return int(value[key])
        except (TypeError, ValueError):
            continue
    return None


def extract_open_cidr(serialized: str) -> str | None:
    for candidate in ("0.0.0.0/0", "::/0"):
        if candidate in serialized:
            return candidate
    return None


def looks_like_resource(value: dict[str, Any]) -> bool:
    return any(key in value for key in ("id", "Id", "InstanceId", "name", "Name", "arn", "ResourceId"))


def resolve_plugin_file(value: str) -> Path:
    path = Path(value)
    candidate = path if path.is_absolute() else PLUGIN_ROOT / path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise InputError("inventory file must exist under plugin root", "$.options.sources.file") from error
    try:
        resolved.relative_to(PLUGIN_ROOT)
    except ValueError as error:
        raise InputError("inventory file must stay under plugin root", "$.options.sources.file") from error
    if not resolved.is_file():
        raise InputError("inventory path must point to a regular file", "$.options.sources.file")
    if resolved.stat().st_size > 4_194_304:
        raise InputError("inventory file exceeds 4 MiB limit", "$.options.sources.file")
    return resolved


def object_at(payload: dict[str, Any], field: str, path: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise InputError(f"{field} must be an object", path)
    return value


def string_at(payload: dict[str, Any], field: str, path: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{field} must be a non-empty string", path)
    return value.strip()


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    return value if isinstance(value, int) and minimum <= value <= maximum else default


def text(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    return str(value).replace("\x00", "").strip()[:limit]


def redact(value: str) -> str:
    return SECRET_TEXT.sub(lambda match: match.group(1) + "=[REDACTED]", value)


def safe_message(error: BaseException) -> str:
    return str(error).replace(str(PLUGIN_ROOT), "<plugin>").replace("\n", " ")[:512]


if __name__ == "__main__":
    raise SystemExit(main())
