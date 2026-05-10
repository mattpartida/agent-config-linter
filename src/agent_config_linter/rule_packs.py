"""Non-executable rule-pack manifest parsing and validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

EXECUTABLE_FIELD_NAMES = {
    "command",
    "commands",
    "entry_point",
    "entrypoint",
    "module",
    "script",
    "scripts",
    "hook",
    "hooks",
    "installer",
    "install",
    "package_install",
    "dynamic_import",
    "import",
    "python",
    "shell",
    "subprocess",
}

ALLOWED_TOP_LEVEL_FIELDS = {"schema_version", "name", "version", "publisher", "description", "homepage", "rules"}
ALLOWED_RULE_FIELDS = {
    "id",
    "name",
    "default_severity",
    "confidence",
    "title",
    "evidence",
    "remediation",
    "docs",
    "fixtures",
    "description",
}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CONFIDENCES = {"high", "medium", "low"}
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]+-[0-9]+$")


class RulePackManifestError(ValueError):
    """Raised when a rule-pack manifest is invalid or crosses execution boundaries."""


@dataclass(frozen=True)
class RulePackManifest:
    schema_version: str
    name: str
    version: str
    publisher: str | None
    rules: tuple[dict[str, Any], ...]
    description: str | None = None
    homepage: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "name": self.name,
            "version": self.version,
            "rules": [dict(rule) for rule in self.rules],
        }
        if self.publisher is not None:
            data["publisher"] = self.publisher
        if self.description is not None:
            data["description"] = self.description
        if self.homepage is not None:
            data["homepage"] = self.homepage
        return data


def _load_manifest_data(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(path.read_text())
        elif suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(path.read_text())
        else:
            raise RulePackManifestError(f"unsupported rule-pack manifest extension: {suffix or '(none)'}")
    except json.JSONDecodeError as exc:
        raise RulePackManifestError(f"invalid JSON rule-pack manifest: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RulePackManifestError(f"invalid YAML rule-pack manifest: {exc}") from exc
    if not isinstance(data, dict):
        raise RulePackManifestError("rule-pack manifest must be a mapping")
    return data


def _field_path(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key


def _reject_executable_fields(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            normalized = key_text.lower().replace("-", "_")
            child_path = _field_path(path, key_text)
            if normalized in EXECUTABLE_FIELD_NAMES:
                raise RulePackManifestError(f"executable field is not allowed: {child_path}")
            _reject_executable_fields(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_executable_fields(child, f"{path}[{index}]")


def _require_string(data: dict[str, Any], field: str, path: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RulePackManifestError(f"{path}.{field} must be a non-empty string")
    return value


def _optional_string(data: dict[str, Any], field: str, path: str) -> str | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RulePackManifestError(f"{path}.{field} must be a string")
    return value


def _validate_rule(rule: Any, index: int) -> dict[str, Any]:
    path = f"rules[{index}]"
    if not isinstance(rule, dict):
        raise RulePackManifestError(f"{path} must be a mapping")
    unknown_fields = sorted(set(rule) - ALLOWED_RULE_FIELDS)
    if unknown_fields:
        raise RulePackManifestError(f"unsupported rule field: {path}.{unknown_fields[0]}")

    rule_id = _require_string(rule, "id", path)
    if not RULE_ID_RE.match(rule_id) or rule_id.startswith("ACL-"):
        raise RulePackManifestError(f"{path}.id must be a non-ACL namespaced rule ID such as ORG-001")
    name = _require_string(rule, "name", path)
    severity = _require_string(rule, "default_severity", path)
    if severity not in VALID_SEVERITIES:
        raise RulePackManifestError(f"{path}.default_severity must be one of {sorted(VALID_SEVERITIES)}")
    confidence = _require_string(rule, "confidence", path)
    if confidence not in VALID_CONFIDENCES:
        raise RulePackManifestError(f"{path}.confidence must be one of {sorted(VALID_CONFIDENCES)}")

    normalized: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "default_severity": severity,
        "confidence": confidence,
        "title": _require_string(rule, "title", path),
        "evidence": _require_string(rule, "evidence", path),
        "remediation": _require_string(rule, "remediation", path),
    }
    for field in ("docs", "description"):
        optional = _optional_string(rule, field, path)
        if optional is not None:
            normalized[field] = optional
    if "fixtures" in rule:
        fixtures = rule["fixtures"]
        if not isinstance(fixtures, dict):
            raise RulePackManifestError(f"{path}.fixtures must be a mapping")
        for fixture_name, fixture_path in fixtures.items():
            if not isinstance(fixture_name, str) or not isinstance(fixture_path, str):
                raise RulePackManifestError(f"{path}.fixtures entries must map strings to strings")
        normalized["fixtures"] = dict(sorted(fixtures.items()))
    return normalized


def parse_rule_pack_manifest(data: dict[str, Any]) -> RulePackManifest:
    _reject_executable_fields(data)
    unknown_fields = sorted(set(data) - ALLOWED_TOP_LEVEL_FIELDS)
    if unknown_fields:
        raise RulePackManifestError(f"unsupported rule-pack field: {unknown_fields[0]}")
    schema_version = _require_string(data, "schema_version", "manifest")
    if schema_version != "rule-pack/v0":
        raise RulePackManifestError("manifest.schema_version must be rule-pack/v0")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RulePackManifestError("manifest.rules must be a non-empty list")
    return RulePackManifest(
        schema_version=schema_version,
        name=_require_string(data, "name", "manifest"),
        version=_require_string(data, "version", "manifest"),
        publisher=_optional_string(data, "publisher", "manifest"),
        description=_optional_string(data, "description", "manifest"),
        homepage=_optional_string(data, "homepage", "manifest"),
        rules=tuple(_validate_rule(rule, index) for index, rule in enumerate(rules)),
    )


def load_rule_pack_manifest(path: str | Path) -> RulePackManifest:
    return parse_rule_pack_manifest(_load_manifest_data(Path(path)))
