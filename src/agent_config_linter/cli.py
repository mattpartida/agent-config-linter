"""Command-line interface for agent-config-linter."""

import argparse
import fnmatch
import json
import re
import sys
import tomllib
from datetime import date
from pathlib import Path

import yaml

from . import __version__
from .linter import lint_config
from .rule_packs import RulePackManifestError, load_rule_pack_manifest
from .rules import RULE_REGISTRY

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
CONFIDENCES = ("high", "medium", "low")
CONFIDENCE_RANK = {confidence: index for index, confidence in enumerate(CONFIDENCES)}
POLICY_BUNDLE_VERSION = "0.2.0"

SUPPORTED_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}
REPO_SCAN_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site-packages",
    "vendor",
}


def _report_path(path):
    """Serialize report paths as stable URI-like paths across platforms."""
    if hasattr(path, "as_posix"):
        return path.as_posix()
    return str(path).replace("\\", "/")


class ConfigValidationError(ValueError):
    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field


SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _load_config(path):
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            return json.loads(path.read_text())
        if suffix == ".toml":
            return tomllib.loads(path.read_text())
        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(path.read_text()) or {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    raise ValueError(f"Unsupported config extension: {suffix or '(none)'}")


def _validate_iso_date(value, field_name):
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"Baseline suppression {field_name} must be a YYYY-MM-DD string")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Baseline suppression {field_name} must be a YYYY-MM-DD string") from exc


def _load_baseline(path):
    baseline = _load_config(path)
    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be a mapping with a suppressions list")
    suppressions = baseline.get("suppressions", [])
    if not isinstance(suppressions, list):
        raise ValueError("Baseline suppressions must be a list")
    for suppression in suppressions:
        if not isinstance(suppression, dict):
            raise ValueError("Each baseline suppression must be a mapping")
        _validate_iso_date(suppression.get("expires_at"), "expires_at")
        for field_name in ("owner", "ticket"):
            if field_name in suppression and not isinstance(suppression[field_name], str):
                raise ValueError(f"Baseline suppression {field_name} must be a string")
    return suppressions


def _load_policy(path):
    policy = _load_config(path)
    if not isinstance(policy, dict):
        raise ConfigValidationError("Policy must be a mapping", "<root>")

    severity_overrides = policy.get("severity_overrides", policy.get("severities", {}))
    severity_field = "severity_overrides" if "severity_overrides" in policy or "severities" not in policy else "severities"
    if not isinstance(severity_overrides, dict):
        raise ConfigValidationError("Policy severity_overrides must be a mapping", severity_field)
    for rule, severity in severity_overrides.items():
        field = f"{severity_field}.{rule}"
        if not isinstance(rule, str):
            raise ConfigValidationError("Policy severity_overrides keys must be strings", field)
        if severity not in SEVERITIES:
            raise ConfigValidationError(f"Invalid severity for {rule}: {severity}", field)

    disabled_rules = policy.get("disabled_rules", policy.get("rule_disables", []))
    disabled_field = "disabled_rules" if "disabled_rules" in policy or "rule_disables" not in policy else "rule_disables"
    if isinstance(disabled_rules, str):
        disabled_rules = [disabled_rules]
    if not isinstance(disabled_rules, list):
        raise ConfigValidationError("Policy disabled_rules must be a list of rule IDs or finding IDs", disabled_field)
    for index, rule in enumerate(disabled_rules):
        if not isinstance(rule, str):
            raise ConfigValidationError("Policy disabled_rules entries must be strings", f"{disabled_field}[{index}]")

    allowlists = policy.get("allowlists", {})
    if allowlists is None:
        allowlists = {}
    if not isinstance(allowlists, dict):
        raise ConfigValidationError("Policy allowlists must be a mapping", "allowlists")
    for key in ("paths", "tools", "rules"):
        if key in allowlists and not isinstance(allowlists[key], list):
            raise ConfigValidationError(f"Policy allowlists.{key} must be a list", f"allowlists.{key}")
    for key in ("tools", "rules"):
        for index, value in enumerate(allowlists.get(key, [])):
            if not isinstance(value, str):
                raise ConfigValidationError(f"Policy allowlists.{key} entries must be strings", f"allowlists.{key}[{index}]")
    for index, entry in enumerate(allowlists.get("paths", [])):
        field_prefix = f"allowlists.paths[{index}]"
        if not isinstance(entry, dict):
            raise ConfigValidationError("Policy allowlists.paths entries must be mappings", field_prefix)
        if "path" not in entry:
            raise ConfigValidationError("Policy allowlists.paths entries require a path", f"{field_prefix}.path")
        for field_name in ("path", "rule_id", "id", "reason"):
            if field_name in entry and not isinstance(entry[field_name], str):
                raise ConfigValidationError(f"Policy {field_prefix}.{field_name} must be a string", f"{field_prefix}.{field_name}")

    min_confidence = policy.get("min_confidence")
    if min_confidence is not None and min_confidence not in CONFIDENCES:
        raise ConfigValidationError(f"Invalid min_confidence: {min_confidence}", "min_confidence")

    metadata = policy.get("metadata", {})
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise ConfigValidationError("Policy metadata must be a mapping", "metadata")
    if "policy_bundle_version" in metadata and not isinstance(metadata["policy_bundle_version"], str):
        raise ConfigValidationError(
            "Policy metadata.policy_bundle_version must be a string",
            "metadata.policy_bundle_version",
        )

    covered_rules = policy.get("covered_rules", [])
    if covered_rules is None:
        covered_rules = []
    if not isinstance(covered_rules, list):
        raise ConfigValidationError("Policy covered_rules must be a list", "covered_rules")
    for index, rule in enumerate(covered_rules):
        if not isinstance(rule, str):
            raise ConfigValidationError("Policy covered_rules entries must be strings", f"covered_rules[{index}]")

    return {
        "severity_overrides": dict(severity_overrides),
        "disabled_rules": set(disabled_rules),
        "allowlists": allowlists,
        "min_confidence": min_confidence,
        "metadata": dict(metadata),
        "covered_rules": list(covered_rules),
    }


def _relative_report_path(path, root):
    try:
        return _report_path(path.relative_to(root))
    except ValueError:
        return _report_path(path)


def _should_ignore_repo_path(path, root):
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(part in REPO_SCAN_IGNORED_DIRS for part in parts)


def _discover_repo_configs(root):
    if not root.is_dir():
        raise ValueError(f"Repo scan path must be a directory: {root}")
    discovered = []
    ignored_paths = []
    root_resolved = root.resolve()
    for child in sorted(root.rglob("*")):
        if child.is_symlink():
            if child.suffix.lower() in SUPPORTED_SUFFIXES:
                ignored_paths.append(_relative_report_path(child, root))
            continue
        if not child.is_file():
            continue
        try:
            child.resolve().relative_to(root_resolved)
        except ValueError:
            if child.suffix.lower() in SUPPORTED_SUFFIXES:
                ignored_paths.append(_relative_report_path(child, root))
            continue
        if _should_ignore_repo_path(child, root):
            if child.suffix.lower() in SUPPORTED_SUFFIXES:
                ignored_paths.append(_relative_report_path(child, root))
            continue
        if child.suffix.lower() in SUPPORTED_SUFFIXES:
            discovered.append(child)
    return discovered, sorted(set(ignored_paths))


def _expand_path(path):
    if path.is_dir():
        config_paths = sorted(
            child for child in path.rglob("*") if child.is_file() and child.suffix.lower() in SUPPORTED_SUFFIXES
        )
        if not config_paths:
            raise ValueError(f"No supported config files found under directory: {path}")
        return config_paths
    return [path]


def _markdown_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def _path_matches(pattern, path):
    normalized_pattern = str(pattern).replace("\\", "/")
    normalized_path = str(path).replace("\\", "/")
    path_name = Path(path).name
    return (
        normalized_pattern in {normalized_path, path_name}
        or fnmatch.fnmatch(normalized_path, normalized_pattern)
        or fnmatch.fnmatch(path_name, normalized_pattern)
    )


def _suppression_matches(suppression, path, finding):
    suppression_path = suppression.get("path", "*")
    if not _path_matches(suppression_path, path):
        return False

    rule_id = suppression.get("rule_id")
    finding_id = suppression.get("finding_id") or suppression.get("id")
    if rule_id and rule_id != finding.get("rule_id"):
        return False
    if finding_id and finding_id != finding.get("id"):
        return False
    return bool(rule_id or finding_id)


def _risk_from_summary(summary):
    score = summary["critical"] * 40 + summary["high"] * 15 + summary["medium"] * 5 + summary["low"]
    if summary["critical"] or score >= 60:
        return "critical", score
    if summary["high"] or score >= 25:
        return "high", score
    if summary["medium"]:
        return "medium", score
    return "low", score


def _finding_rule_keys(finding):
    return {str(value) for value in (finding.get("rule_id"), finding.get("rule_name"), finding.get("id")) if value}


def _finalize_report(report):
    findings = report.get("findings", [])
    report["summary"] = {severity: sum(1 for finding in findings if finding["severity"] == severity) for severity in SEVERITIES}
    report["risk_level"], report["score"] = _risk_from_summary(report["summary"])
    report["recommended_next_actions"] = [finding["remediation"] for finding in findings[:5]]
    return report


def _confidence_at_or_above(confidence, threshold):
    return CONFIDENCE_RANK.get(confidence, len(CONFIDENCE_RANK)) <= CONFIDENCE_RANK[threshold]


def _apply_min_confidence(report, threshold):
    if not threshold:
        return report
    remaining_findings = []
    filtered_findings = []
    for finding in report.get("findings", []):
        if _confidence_at_or_above(finding.get("confidence", "low"), threshold):
            remaining_findings.append(finding)
        else:
            filtered_findings.append(finding)
    report["findings"] = remaining_findings
    report["confidence_filtered_findings"] = filtered_findings
    report["confidence_filtered_summary"] = {
        severity: sum(1 for finding in filtered_findings if finding["severity"] == severity) for severity in SEVERITIES
    }
    return _finalize_report(report)


def _apply_policy(report, path, policy):
    if not policy:
        return report

    severity_overrides = policy.get("severity_overrides", {})
    disabled_rules = policy.get("disabled_rules", set())
    allowlists = policy.get("allowlists", {})
    allowlisted_tools = {str(tool).lower().replace("_", "-") for tool in allowlists.get("tools", [])}
    allowlisted_rules = {str(rule) for rule in allowlists.get("rules", [])}
    allowlisted_paths = allowlists.get("paths", [])

    remaining_findings = []
    suppressed_findings = []
    for finding in report.get("findings", []):
        rule_keys = _finding_rule_keys(finding)
        disabled_match = bool(rule_keys & disabled_rules)
        rule_allow_match = bool(rule_keys & allowlisted_rules)
        tool_allow_match = False
        tool_allowlist_entry = None
        for evidence_path in finding.get("evidence_paths", []):
            normalized_evidence = str(evidence_path).lower().replace("_", "-")
            if normalized_evidence.startswith("tools."):
                tool_name = normalized_evidence.split(".", 1)[1].split("[", 1)[0]
                if tool_name in allowlisted_tools:
                    tool_allow_match = True
                    tool_allowlist_entry = f"tools.{tool_name}"
                    break
        path_allow_match = any(
            isinstance(entry, dict)
            and _path_matches(entry.get("path", "*"), path)
            and (not entry.get("rule_id") or entry.get("rule_id") in rule_keys)
            and (not entry.get("id") or entry.get("id") in rule_keys)
            for entry in allowlisted_paths
        )

        if disabled_match or rule_allow_match or tool_allow_match or path_allow_match:
            suppressed = dict(finding)
            reason = "disabled_rule" if disabled_match else "allowlist"
            suppressed["policy"] = {"reason": reason}
            if tool_allowlist_entry:
                suppressed["policy"]["allowlist"] = tool_allowlist_entry
            suppressed_findings.append(suppressed)
            continue

        override = next((severity_overrides[key] for key in rule_keys if key in severity_overrides), None)
        if override:
            finding = dict(finding)
            finding["severity"] = override
        remaining_findings.append(finding)

    report["findings"] = remaining_findings
    report["policy_suppressed_findings"] = suppressed_findings
    report["policy_suppressed_summary"] = {
        severity: sum(1 for finding in suppressed_findings if finding["severity"] == severity) for severity in SEVERITIES
    }
    return _apply_min_confidence(_finalize_report(report), policy.get("min_confidence"))


def _is_expired_suppression(suppression, today=None):
    expires_at = _validate_iso_date(suppression.get("expires_at"), "expires_at")
    return bool(expires_at and expires_at < (today or date.today()))


def _apply_baseline(report, path, suppressions, matched_suppression_ids=None):
    remaining_findings = []
    suppressed_findings = []
    today = date.today()
    for finding in report.get("findings", []):
        matching_suppression = next(
            (
                suppression
                for suppression in suppressions
                if not _is_expired_suppression(suppression, today)
                and _suppression_matches(suppression, path, finding)
            ),
            None,
        )
        if matching_suppression:
            if matched_suppression_ids is not None:
                matched_suppression_ids.add(id(matching_suppression))
            suppressed = dict(finding)
            suppressed["suppression"] = {
                key: matching_suppression[key]
                for key in ("path", "rule_id", "finding_id", "id", "reason", "expires_at", "owner", "ticket")
                if key in matching_suppression
            }
            suppressed_findings.append(suppressed)
        else:
            remaining_findings.append(finding)

    report["findings"] = remaining_findings
    report["suppressed_findings"] = suppressed_findings
    report["suppressed_summary"] = {
        severity: sum(1 for finding in suppressed_findings if finding["severity"] == severity) for severity in SEVERITIES
    }
    return _finalize_report(report)


def _evidence_path_segments(evidence_path):
    segments = []
    for raw_part in str(evidence_path).split("."):
        if not raw_part:
            continue
        match = re.fullmatch(r"([^\[]+)(?:\[(\d+)\])?", raw_part)
        if match:
            segments.append((match.group(1), int(match.group(2)) if match.group(2) is not None else None))
        else:
            segments.append((raw_part.split("[")[0], None))
    return segments


def _line_for_indexed_sequence(lines, key, index):
    key_pattern = re.compile(rf"^\s*[\"']?{re.escape(key)}[\"']?\s*[:=]\s*\[?")
    for key_line_index, line in enumerate(lines):
        if not key_pattern.search(line):
            continue
        item_count = -1
        for candidate_index in range(key_line_index + 1, len(lines)):
            candidate = lines[candidate_index]
            stripped = candidate.strip().rstrip(",")
            if not stripped:
                continue
            if stripped.startswith("]"):
                break
            if stripped.startswith("-") or stripped.startswith('"') or stripped.startswith("'"):
                item_count += 1
                if item_count == index:
                    return candidate_index + 1
    return None


def _source_line_for_evidence(path, evidence_paths):
    """Best-effort line lookup for SARIF locations from dotted evidence paths."""
    if not evidence_paths:
        return 1
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return 1
    for evidence_path in evidence_paths:
        segments = _evidence_path_segments(evidence_path)
        if len(segments) >= 2:
            parent_key = segments[-2][0]
            leaf_key = segments[-1][0]
            parent_pattern = re.compile(rf"^\s*[\"']?{re.escape(parent_key)}[\"']?\s*[:=]")
            leaf_pattern = re.compile(rf"^\s*[\"']?{re.escape(leaf_key)}[\"']?\s*[:=]")
            for parent_line_index, line in enumerate(lines):
                if not parent_pattern.search(line):
                    continue
                parent_indent = len(line) - len(line.lstrip())
                for candidate_index in range(parent_line_index + 1, len(lines)):
                    candidate = lines[candidate_index]
                    if not candidate.strip():
                        continue
                    candidate_indent = len(candidate) - len(candidate.lstrip())
                    if candidate_indent <= parent_indent:
                        break
                    if leaf_pattern.search(candidate):
                        return candidate_index + 1
        for key, index in reversed(segments):
            if index is not None:
                indexed_line = _line_for_indexed_sequence(lines, key, index)
                if indexed_line:
                    return indexed_line
        for key, _index in reversed(segments):
            key_pattern = re.compile(
                rf"^\s*(?:[\"']?{re.escape(key)}[\"']?\s*[:=]|\[[^\]]*(?:^|\.){re.escape(key)}(?:\.|\]))"
            )
            for line_number, line in enumerate(lines, start=1):
                if key_pattern.search(line):
                    return line_number
    return 1


def _suggestions_for_finding(finding):
    finding_id = finding.get("id")
    suggestions = {
        "approval_gate_missing": {
            "id": "require-approval-gates",
            "title": "Require approval for dangerous actions",
            "patch": "Set approvals.shell, approvals.exec, and other dangerous-action approvals to true before enabling agent execution.",
        },
        "filesystem_broad_access": {
            "id": "narrow-filesystem-roots",
            "title": "Narrow filesystem roots",
            "patch": "Replace broad roots such as /, ~, $HOME, or * with project-scoped read-only paths such as ./src or ./docs.",
        },
        "unrestricted_network_egress": {
            "id": "restrict-network-egress",
            "title": "Restrict network egress",
            "patch": "Replace wildcard egress with an explicit domain allowlist such as network.egress.domains.",
        },
        "unpinned_remote_tool_source": {
            "id": "pin-remote-tool-source",
            "title": "Pin remote tool source",
            "patch": "Pin remote tool sources to a commit, tag, version, or digest and record the expected source.",
        },
        "runtime_package_install": {
            "id": "disable-runtime-package-install",
            "title": "Disable runtime package installation",
            "patch": "Set package_install to false and pre-build dependencies in a reviewed environment.",
        },
    }
    suggestion = suggestions.get(finding_id)
    if not suggestion:
        return []
    return [{**suggestion, "review_required": True, "applied": False}]


def _attach_suggestions(result):
    for report in result.get("files", []):
        for finding in report.get("findings", []):
            suggestions = _suggestions_for_finding(finding)
            if suggestions:
                finding["suggestions"] = suggestions
    return result


def _rule_anchor(finding):
    rule_id = finding.get("rule_id", finding["id"]).lower()
    return f"docs/rules.md#{rule_id}"


def _finding_matches_explain_selector(finding, selector):
    selector = selector.lower()
    return selector in {finding.get("rule_id", "").lower(), finding.get("id", "").lower(), finding.get("rule_name", "").lower()}


def _build_explanations(result, selector):
    explanations = []
    for report in result.get("files", []):
        for finding in report.get("findings", []):
            if not _finding_matches_explain_selector(finding, selector):
                continue
            rule_id = finding.get("rule_id", finding["id"])
            explanations.append(
                {
                    "path": report["path"],
                    "rule_id": rule_id,
                    "finding_id": finding["id"],
                    "rule_name": finding.get("rule_name", finding["id"].replace("_", "-")),
                    "severity": finding["severity"],
                    "confidence": finding.get("confidence", "low"),
                    "title": finding["title"],
                    "intent": finding["evidence"],
                    "remediation": finding["remediation"],
                    "evidence_paths": finding.get("evidence_paths", []),
                    "source_evidence_paths": finding.get("source_evidence_paths", finding.get("evidence_paths", [])),
                    "docs": _rule_anchor(finding),
                    "suppression_guidance": f"Use a baseline suppression for {rule_id}/{finding['id']} only after documenting owner, ticket, reason, and expiry.",
                }
            )
            return explanations
    return explanations


def _format_markdown(result):
    lines = ["# Agent Config Linter Report", ""]
    if result["errors"]:
        lines.extend(["## Errors", ""])
        for error in result["errors"]:
            lines.append(f"- `{error['path']}`: {error['message']}")
        lines.append("")

    for report in result["files"]:
        path = Path(report["path"])
        lines.extend(
            [
                f"## {path.name}",
                "",
                f"- Risk level: **{report['risk_level']}**",
                f"- Score: **{report['score']}**",
                f"- Lethal trifecta: **{str(report['signals']['lethal_trifecta']).lower()}**",
                "",
            ]
        )
        findings = report.get("findings", [])
        if findings:
            lines.extend(
                [
                    "| Rule | Severity | Confidence | Finding | Title |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for finding in findings:
                lines.append(
                    "| {rule_id} | {severity} | {confidence} | {finding_id} | {title} |".format(
                        rule_id=_markdown_escape(finding.get("rule_id", finding["id"])),
                        severity=_markdown_escape(finding["severity"]),
                        confidence=_markdown_escape(finding.get("confidence", "low")),
                        finding_id=_markdown_escape(finding["id"]),
                        title=_markdown_escape(finding["title"]),
                    )
                )
            lines.append("")
            suggestion_rows = [
                (finding, suggestion)
                for finding in findings
                for suggestion in finding.get("suggestions", [])
            ]
            if suggestion_rows:
                lines.extend([
                    "### Review-required remediation suggestions",
                    "",
                    "These suggestions are not applied automatically; review before editing config files.",
                    "",
                    "| Rule | Suggestion | Patch guidance |",
                    "| --- | --- | --- |",
                ])
                for finding, suggestion in suggestion_rows:
                    lines.append(
                        "| {rule_id} | {title} | {patch} |".format(
                            rule_id=_markdown_escape(finding.get("rule_id", finding["id"])),
                            title=_markdown_escape(suggestion["title"]),
                            patch=_markdown_escape(suggestion["patch"]),
                        )
                    )
                lines.append("")
        else:
            lines.extend(["No findings.", ""])
    return "\n".join(lines).rstrip() + "\n"


def _format_github_markdown(result, summary_only=False):
    total_files = len(result.get("files", []))
    total_findings = sum(len(report.get("findings", [])) for report in result.get("files", []))
    lines = ["## agent-config-linter summary", ""]
    lines.append(f"Scanned **{total_files}** file(s) and found **{total_findings}** active finding(s).")
    lines.append("")

    if result.get("errors"):
        lines.extend(["### Errors", ""])
        for error in result["errors"]:
            field = f" `{error['field']}`" if "field" in error else ""
            lines.append(f"- `{error['path']}`{field}: {error['message']}")
        lines.append("")

    if result.get("files"):
        lines.extend(
            [
                "| File | Risk | Score | Critical | High | Medium | Low |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for report in result["files"]:
            summary = report["summary"]
            lines.append(
                "| {path} | {risk} | {score} | {critical} | {high} | {medium} | {low} |".format(
                    path=_markdown_escape(Path(report["path"]).name),
                    risk=_markdown_escape(report["risk_level"]),
                    score=report["score"],
                    critical=summary["critical"],
                    high=summary["high"],
                    medium=summary["medium"],
                    low=summary["low"],
                )
            )
        lines.append("")

    if summary_only:
        return "\n".join(lines).rstrip() + "\n"

    findings = [
        (Path(report["path"]).name, finding)
        for report in result.get("files", [])
        for finding in report.get("findings", [])
    ]
    if findings:
        lines.extend(["### Findings", "", "| File | Rule | Severity | Confidence | Finding | Remediation |", "| --- | --- | --- | --- | --- | --- |"])
        for file_name, finding in findings:
            lines.append(
                "| {file} | {rule_id} | {severity} | {confidence} | {title} | {remediation} |".format(
                    file=_markdown_escape(file_name),
                    rule_id=_markdown_escape(finding.get("rule_id", finding["id"])),
                    severity=_markdown_escape(finding["severity"]),
                    confidence=_markdown_escape(finding.get("confidence", "low")),
                    title=_markdown_escape(finding["title"]),
                    remediation=_markdown_escape(finding["remediation"]),
                )
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _format_sarif(result):
    rules = {}
    sarif_results = []
    for report in result["files"]:
        for finding in report.get("findings", []):
            rule_id = finding.get("rule_id", finding["id"])
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding.get("rule_name", finding["id"].replace("_", "-")),
                    "shortDescription": {"text": finding["title"]},
                    "fullDescription": {"text": finding["evidence"]},
                    "help": {"text": finding["remediation"]},
                    "properties": {
                        "severity": finding["severity"],
                        "confidence": finding.get("confidence", "low"),
                        "finding_id": finding["id"],
                    },
                },
            )
            evidence_paths = finding.get("evidence_paths", [])
            source_evidence_paths = finding.get("source_evidence_paths", evidence_paths)
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": SARIF_LEVELS.get(finding["severity"], "warning"),
                    "message": {"text": f"{finding['title']}: {finding['evidence']}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": report["path"]},
                                "region": {"startLine": _source_line_for_evidence(report["path"], source_evidence_paths)},
                            }
                        }
                    ],
                    "properties": {
                        "finding_id": finding["id"],
                        "confidence": finding.get("confidence", "low"),
                        "remediation": finding["remediation"],
                        "evidence_paths": evidence_paths,
                        "source_evidence_paths": source_evidence_paths,
                    },
                }
            )

    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "agent-config-linter",
                            "informationUri": "https://github.com/mattpartida/agent-config-linter",
                            "rules": sorted(rules.values(), key=lambda rule: rule["id"]),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _increment(mapping, key, amount=1):
    mapping[key] = mapping.get(key, 0) + amount


def _trend_path_prefix(path):
    path_text = str(path)
    parts = path_text.split("/")
    if not parts:
        return path_text
    if parts[0] == "":
        return parts[-1] or path_text
    if len(parts) == 1:
        return parts[0]
    if parts[0].startswith(".") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def _build_trend_summary(result):
    trend = {
        "schema_version": "0.1",
        "total_files": len(result.get("files", [])),
        "total_active_findings": 0,
        "total_suppressed_findings": 0,
        "counts_by_rule": {},
        "counts_by_severity": {severity: 0 for severity in SEVERITIES},
        "counts_by_confidence": {confidence: 0 for confidence in CONFIDENCES},
        "counts_by_adapter": {},
        "counts_by_path_prefix": {},
        "baseline_state": {"active": 0, "expired": 0, "stale": 0, "suppressed": 0},
        "counts_by_owner": {},
    }
    for report in result.get("files", []):
        adapter = report.get("schema", {}).get("adapter", "generic")
        prefix = _trend_path_prefix(report.get("path", "<unknown>"))
        for finding in report.get("findings", []):
            trend["total_active_findings"] += 1
            _increment(trend["counts_by_rule"], finding.get("rule_id", finding["id"]))
            _increment(trend["counts_by_severity"], finding["severity"])
            _increment(trend["counts_by_confidence"], finding.get("confidence", "low"))
            _increment(trend["counts_by_adapter"], adapter)
            _increment(trend["counts_by_path_prefix"], prefix)
        for finding in report.get("suppressed_findings", []) + report.get("policy_suppressed_findings", []):
            trend["total_suppressed_findings"] += 1
            trend["baseline_state"]["suppressed"] += 1
            suppression = finding.get("suppression", {})
            owner = str(suppression.get("owner") or "unowned")
            owner_entry = trend["counts_by_owner"].setdefault(
                owner, {"active": 0, "expired": 0, "stale": 0, "suppressed": 0}
            )
            owner_entry["suppressed"] += 1
            owner_entry["active"] += 1
            trend["baseline_state"]["active"] += 1
    baseline = result.get("baseline", {})
    trend["baseline_state"]["expired"] = baseline.get("expired_count", 0)
    trend["baseline_state"]["stale"] = baseline.get("stale_count", 0)
    for owner, summary in baseline.get("owner_summary", {}).items():
        owner_entry = trend["counts_by_owner"].setdefault(
            owner, {"active": 0, "expired": 0, "stale": 0, "suppressed": 0}
        )
        owner_entry["expired"] = summary.get("expired", 0)
        owner_entry["stale"] = summary.get("stale", 0)
        owner_entry["active"] = max(owner_entry["active"], summary.get("active", 0))
    for key in ("counts_by_rule", "counts_by_adapter", "counts_by_path_prefix", "counts_by_owner"):
        trend[key] = dict(sorted(trend[key].items()))
    return trend


def _policy_rule_references(policy):
    references = []
    for rule in policy.get("severity_overrides", {}):
        references.append((f"severity_overrides.{rule}", rule))
    for rule in sorted(policy.get("disabled_rules", set())):
        references.append((f"disabled_rules.{rule}", rule))
    for index, rule in enumerate(policy.get("allowlists", {}).get("rules", [])):
        references.append((f"allowlists.rules[{index}]", rule))
    for index, entry in enumerate(policy.get("allowlists", {}).get("paths", [])):
        for key in ("rule_id", "id"):
            if key in entry:
                references.append((f"allowlists.paths[{index}].{key}", entry[key]))
    for index, rule in enumerate(policy.get("covered_rules", [])):
        references.append((f"covered_rules[{index}]", rule))
    return references


def _known_rule_ids():
    return {definition.rule_id for definition in RULE_REGISTRY.values()}


def _known_finding_ids():
    return set(RULE_REGISTRY.keys())


def _build_policy_drift(policy):
    known_rule_ids = _known_rule_ids()
    known_finding_ids = _known_finding_ids()
    covered_rules = {rule for rule in policy.get("covered_rules", []) if isinstance(rule, str)}
    unknown_rules = []
    for field, rule in _policy_rule_references(policy):
        if rule not in known_rule_ids and rule not in known_finding_ids:
            unknown_rules.append({"field": field, "rule": rule})
    missing_rules = sorted(known_rule_ids - covered_rules) if covered_rules else sorted(known_rule_ids)
    metadata = policy.get("metadata", {})
    policy_bundle_version = metadata.get("policy_bundle_version")
    stale_fields = []
    if policy_bundle_version != POLICY_BUNDLE_VERSION:
        stale_fields.append("policy_bundle_version")
    return {
        "current_policy_bundle_version": POLICY_BUNDLE_VERSION,
        "policy_bundle_version": policy_bundle_version,
        "unknown_rules": sorted(unknown_rules, key=lambda entry: (entry["field"], entry["rule"])),
        "missing_rules": missing_rules,
        "stale_fields": stale_fields,
        "failed": bool(unknown_rules or missing_rules or stale_fields),
    }


def _format_result(result, output_format, summary_only=False):
    if output_format == "json":
        return json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output_format == "markdown":
        if summary_only:
            return _format_github_markdown(result, summary_only=True)
        return _format_markdown(result)
    if output_format == "github-markdown":
        return _format_github_markdown(result, summary_only=summary_only)
    if output_format == "sarif":
        return _format_sarif(result)
    raise ValueError(f"Unsupported format: {output_format}")


def _baseline_entry(path, finding):
    return {
        "path": str(path),
        "rule_id": finding.get("rule_id", finding["id"]),
        "finding_id": finding["id"],
        "reason": "TODO: document accepted risk",
        "owner": "TODO",
        "ticket": "TODO",
        "expires_at": None,
    }


def _write_generated_baseline(path, reports):
    suppressions = [
        _baseline_entry(report["path"], finding)
        for report in reports
        for finding in report.get("findings", [])
    ]
    baseline = {
        "schema_version": "0.1",
        "generated_by": "agent-config-linter",
        "suppressions": suppressions,
    }
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")
    return baseline


def _expired_suppressions(suppressions):
    today = date.today()
    return [suppression for suppression in suppressions if _is_expired_suppression(suppression, today)]


def _stale_suppressions(suppressions, matched_suppression_ids):
    return [
        suppression
        for suppression in suppressions
        if id(suppression) not in matched_suppression_ids and not _is_expired_suppression(suppression)
    ]


def _owner_key(suppression):
    return str(suppression.get("owner") or "unowned")


def _baseline_owner_summary(suppressions, matched_suppression_ids, stale, expired):
    summary = {}
    stale_ids = {id(suppression) for suppression in stale}
    expired_ids = {id(suppression) for suppression in expired}
    for suppression in suppressions:
        owner = _owner_key(suppression)
        entry = summary.setdefault(owner, {"active": 0, "expired": 0, "stale": 0, "total": 0})
        entry["total"] += 1
        if id(suppression) in expired_ids:
            entry["expired"] += 1
        elif id(suppression) in stale_ids:
            entry["stale"] += 1
        elif id(suppression) in matched_suppression_ids:
            entry["active"] += 1
    return dict(sorted(summary.items()))


def _severity_at_or_above(severity, threshold):
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[threshold]


def _apply_min_severity(report, threshold):
    if not threshold:
        return report
    remaining_findings = []
    filtered_findings = []
    for finding in report.get("findings", []):
        if _severity_at_or_above(finding["severity"], threshold):
            remaining_findings.append(finding)
        else:
            filtered_findings.append(finding)
    report["findings"] = remaining_findings
    report["filtered_findings"] = filtered_findings
    report["filtered_summary"] = {
        severity: sum(1 for finding in filtered_findings if finding["severity"] == severity) for severity in SEVERITIES
    }
    return _finalize_report(report)


def _has_failure_at_threshold(reports, threshold):
    return any(
        _severity_at_or_above(finding["severity"], threshold)
        for report in reports
        for finding in report.get("findings", [])
    )


def run(argv=None):
    parser = argparse.ArgumentParser(description="Lint autonomous-agent config files for risky capability combinations")
    parser.add_argument("paths", nargs="*", help="Config file or directory paths. Directories are scanned recursively for JSON, YAML, and TOML files.")
    parser.add_argument("--format", choices=["json", "markdown", "github-markdown", "sarif"], default="json")
    parser.add_argument("--summary-only", action="store_true", help="Emit only the concise summary section for PR comments or chat/CI logs")
    parser.add_argument("--baseline", help="JSON, YAML, or TOML file containing accepted finding suppressions")
    parser.add_argument("--policy", help="JSON, YAML, or TOML policy file with severity overrides, rule disables, and allowlists")
    parser.add_argument("--generate-baseline", help="Write current findings as baseline suppressions to this JSON file")
    parser.add_argument("--fail-on-stale-baseline", action="store_true", help="Exit non-zero when baseline suppressions no longer match any finding")
    parser.add_argument("--fail-on-expired-baseline", action="store_true", help="Exit non-zero when baseline suppressions have passed expires_at")
    parser.add_argument("--min-severity", choices=SEVERITIES, help="Only include active findings at or above this severity")
    parser.add_argument("--fail-on", choices=SEVERITIES, help="Exit with code 1 when active findings meet or exceed this severity")
    parser.add_argument("--validate-rule-pack", help="Validate a non-executable rule-pack manifest and emit deterministic metadata")
    parser.add_argument("--repo-scan", action="store_true", help="Scan repository roots with ignored-path and parser-failure diagnostics")
    parser.add_argument("--explain", help="Emit an explanation for the first active finding matching a rule ID or finding ID")
    parser.add_argument("--suggestions", action="store_true", help="Attach review-only remediation suggestions to selected findings")
    parser.add_argument("--trend-summary", action="store_true", help="Attach compact deterministic counts for time-series ingestion")
    parser.add_argument("--check-policy-drift", action="store_true", help="Report unknown, missing, or stale policy bundle references")
    parser.add_argument("--fail-on-policy-drift", action="store_true", help="Exit non-zero when policy drift is found; implies --check-policy-drift")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    args = parser.parse_args(argv)
    if args.fail_on_policy_drift:
        args.check_policy_drift = True

    if args.version:
        return 0, f"agent-config-linter {__version__}\n"
    if args.validate_rule_pack:
        manifest_path = Path(args.validate_rule_pack)
        try:
            manifest = load_rule_pack_manifest(manifest_path)
        except (OSError, RulePackManifestError) as exc:
            result = {"schema_version": "0.1", "rule_pack": None, "errors": [{"path": _report_path(manifest_path), "message": str(exc)}]}
            return 2, json.dumps(result, indent=2, sort_keys=True) + "\n"
        result = {"schema_version": "0.1", "rule_pack": manifest.to_dict(), "errors": []}
        return 0, json.dumps(result, indent=2, sort_keys=True) + "\n"
    if not args.paths:
        parser.error("the following arguments are required: paths")

    result = {"schema_version": "0.1", "files": [], "errors": []}
    if args.repo_scan:
        result["scan"] = {"discovered_files": [], "ignored_paths": [], "parser_failures": []}
    exit_code = 0
    suppressions = []
    matched_suppression_ids = set()
    policy = None

    if args.baseline:
        baseline_path = Path(args.baseline)
        try:
            suppressions = _load_baseline(baseline_path)
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(baseline_path), "message": str(exc)})
        except ValueError as exc:
            exit_code = 2
            result["errors"].append({"path": str(baseline_path), "message": str(exc)})

    if args.policy:
        policy_path = Path(args.policy)
        try:
            policy = _load_policy(policy_path)
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(policy_path), "message": str(exc)})
        except ValueError as exc:
            exit_code = 2
            error = {"path": str(policy_path), "message": str(exc)}
            if getattr(exc, "field", None):
                error["field"] = exc.field
            result["errors"].append(error)

    for raw_path in args.paths:
        input_path = Path(raw_path)
        scan_root = None
        try:
            if args.repo_scan:
                scan_root = input_path
                config_paths, ignored_paths = _discover_repo_configs(input_path)
                result["scan"]["ignored_paths"].extend(ignored_paths)
                result["scan"]["discovered_files"].extend(_relative_report_path(path, scan_root) for path in config_paths)
            else:
                config_paths = _expand_path(input_path)
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(input_path), "message": str(exc)})
            continue
        except ValueError as exc:
            exit_code = 2
            result["errors"].append({"path": str(input_path), "message": str(exc)})
            continue

        for path in config_paths:
            report_path = _relative_report_path(path, scan_root) if scan_root else _report_path(path)
            try:
                config = _load_config(path)
                report = lint_config(config)
                report["path"] = report_path
                if policy:
                    report = _apply_policy(report, path, policy)
                if args.baseline:
                    report = _apply_baseline(report, path, suppressions, matched_suppression_ids)
                if args.min_severity:
                    report = _apply_min_severity(report, args.min_severity)
                result["files"].append(report)
            except OSError as exc:
                if args.repo_scan:
                    result["scan"]["parser_failures"].append({"path": report_path, "message": str(exc)})
                else:
                    exit_code = 2
                    result["errors"].append({"path": str(path), "message": str(exc)})
            except ValueError as exc:
                if args.repo_scan:
                    result["scan"]["parser_failures"].append({"path": report_path, "message": str(exc)})
                else:
                    exit_code = 2
                    result["errors"].append({"path": str(path), "message": str(exc)})

    if args.repo_scan:
        result["scan"]["discovered_files"] = sorted(set(result["scan"]["discovered_files"]))
        result["scan"]["ignored_paths"] = sorted(set(result["scan"]["ignored_paths"]))
        result["scan"]["parser_failures"] = sorted(result["scan"]["parser_failures"], key=lambda error: error["path"])

    if args.baseline:
        stale = _stale_suppressions(suppressions, matched_suppression_ids)
        expired = _expired_suppressions(suppressions)
        result["baseline"] = {
            "stale_count": len(stale),
            "stale_suppressions": stale,
            "expired_count": len(expired),
            "expired_suppressions": expired,
            "owner_summary": _baseline_owner_summary(suppressions, matched_suppression_ids, stale, expired),
        }
        if stale and args.fail_on_stale_baseline and exit_code == 0:
            exit_code = 1
        if expired and args.fail_on_expired_baseline and exit_code == 0:
            exit_code = 1

    if args.generate_baseline and exit_code == 0:
        baseline_path = Path(args.generate_baseline)
        try:
            generated = _write_generated_baseline(baseline_path, result["files"])
            result["baseline"] = {
                **result.get("baseline", {}),
                "generated": str(baseline_path),
                "generated_count": len(generated["suppressions"]),
            }
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(baseline_path), "message": str(exc)})

    if args.suggestions:
        result = _attach_suggestions(result)

    if args.explain:
        result["explanations"] = _build_explanations(result, args.explain)
        if not result["explanations"] and exit_code == 0:
            exit_code = 1

    if args.fail_on:
        failed = _has_failure_at_threshold(result["files"], args.fail_on)
        result["exit_policy"] = {"fail_on": args.fail_on, "failed": failed}
        if failed and exit_code == 0:
            exit_code = 1

    if args.check_policy_drift:
        if policy:
            result["policy_drift"] = _build_policy_drift(policy)
        else:
            result["policy_drift"] = {
                "current_policy_bundle_version": POLICY_BUNDLE_VERSION,
                "policy_bundle_version": None,
                "unknown_rules": [],
                "missing_rules": sorted(_known_rule_ids()),
                "stale_fields": ["policy"],
                "failed": True,
            }
        if result["policy_drift"]["failed"] and args.fail_on_policy_drift and exit_code == 0:
            exit_code = 1

    if args.trend_summary:
        result["trend_summary"] = _build_trend_summary(result)

    return exit_code, _format_result(result, args.format, summary_only=args.summary_only)


def main(argv=None):
    exit_code, output = run(argv)
    stream = sys.stderr if exit_code else sys.stdout
    stream.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
