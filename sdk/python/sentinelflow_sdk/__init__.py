"""Dependency-free helpers for SentinelFlow out-of-process plugins."""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO


def read_input(stream: TextIO | None = None) -> Any:
    """Read one JSON value from standard input."""
    source = stream or sys.stdin
    try:
        return json.load(source)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError(f"invalid SentinelFlow JSON input: {error}") from error


def write_output(value: Any, stream: TextIO | None = None) -> None:
    """Write one compact JSON value to standard output."""
    destination = stream or sys.stdout
    json.dump(value, destination, ensure_ascii=True, separators=(",", ":"))
    destination.write("\n")
    destination.flush()


def standard_error(
    code: str,
    message: str,
    *,
    field: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create the standard non-sensitive error details object."""
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "details": dict(details or {}),
    }
    if field is not None:
        error["field"] = field
    return error


def evidence(
    evidence_type: str, description: str, data: Mapping[str, Any]
) -> dict[str, Any]:
    """Create structured, non-sensitive evidence."""
    return {
        "evidenceType": evidence_type,
        "description": description,
        "data": dict(data),
    }


def finding(
    title: str,
    severity: str,
    summary: str,
    *,
    evidence_items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a Finding draft for a trusted SentinelFlow parser."""
    return {
        "title": title,
        "severity": severity,
        "summary": summary,
        "evidence": list(evidence_items or []),
    }


def parser_envelope(
    values: Any,
    *,
    findings: list[dict[str, Any]] | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create the standard parser envelope consumed by the Normalizer."""
    return {
        "values": values,
        "findings": list(findings or []),
        "errors": list(errors or []),
    }


def invoke(handler: Callable[[Any], Any], payload: Any) -> Any:
    """Invoke a plugin handler directly for unit tests."""
    return handler(payload)


def invoke_json(handler: Callable[[Any], Any], payload: str) -> str:
    """Invoke a handler with JSON text and return compact JSON text."""
    source = io.StringIO(payload)
    destination = io.StringIO()
    write_output(handler(read_input(source)), destination)
    return destination.getvalue()


def run(handler: Callable[[Any], Any]) -> None:
    """Run a handler over stdin/stdout without importing SentinelFlow Core."""
    write_output(handler(read_input()))


__all__ = [
    "evidence",
    "finding",
    "invoke",
    "invoke_json",
    "parser_envelope",
    "read_input",
    "run",
    "standard_error",
    "write_output",
]

