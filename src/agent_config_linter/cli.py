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

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
CONFIDENCES = ("high", "medium", "low")
CONFIDENCE_RANK = {confidence: index for index, confidence in enumerate(CONFIDENCES)}

SUPPORTED_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}


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

    return {
        "severity_overrides": dict(severity_overrides),
        "disabled_rules": set(disabled_rules),
        "allowlists": allowlists,
        "min_confidence": min_confidence,
    }


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


def _apply_baseline(report, path, suppressions, matched_suppression_ids=None):
    remaining_findings = []
    suppressed_findings = []
    today = date.today()
    for finding in report.get("findings", []):
        matching_suppression = next(
            (
                suppression
                for suppression in suppressions
                if not (_validate_iso_date(suppression.get("expires_at"), "expires_at") and _validate_iso_date(suppression.get("expires_at"), "expires_at") < today)
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


def _stale_suppressions(suppressions, matched_suppression_ids):
    return [suppression for suppression in suppressions if id(suppression) not in matched_suppression_ids]


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
    parser.add_argument("--min-severity", choices=SEVERITIES, help="Only include active findings at or above this severity")
    parser.add_argument("--fail-on", choices=SEVERITIES, help="Exit with code 1 when active findings meet or exceed this severity")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    args = parser.parse_args(argv)

    if args.version:
        return 0, f"agent-config-linter {__version__}\n"
    if not args.paths:
        parser.error("the following arguments are required: paths")

    result = {"schema_version": "0.1", "files": [], "errors": []}
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
        try:
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
            try:
                config = _load_config(path)
                report = lint_config(config)
                report["path"] = str(path)
                if policy:
                    report = _apply_policy(report, path, policy)
                if args.baseline:
                    report = _apply_baseline(report, path, suppressions, matched_suppression_ids)
                if args.min_severity:
                    report = _apply_min_severity(report, args.min_severity)
                result["files"].append(report)
            except OSError as exc:
                exit_code = 2
                result["errors"].append({"path": str(path), "message": str(exc)})
            except ValueError as exc:
                exit_code = 2
                result["errors"].append({"path": str(path), "message": str(exc)})

    if args.baseline:
        stale = _stale_suppressions(suppressions, matched_suppression_ids)
        result["baseline"] = {"stale_count": len(stale), "stale_suppressions": stale}
        if stale and args.fail_on_stale_baseline and exit_code == 0:
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

    if args.fail_on:
        failed = _has_failure_at_threshold(result["files"], args.fail_on)
        result["exit_policy"] = {"fail_on": args.fail_on, "failed": failed}
        if failed and exit_code == 0:
            exit_code = 1

    return exit_code, _format_result(result, args.format, summary_only=args.summary_only)


def main(argv=None):
    exit_code, output = run(argv)
    stream = sys.stderr if exit_code else sys.stdout
    stream.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
