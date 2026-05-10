"""Rule metadata registry for built-in agent-config-linter checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

CollectorHelpers = Mapping[str, Callable[..., list[str]]]


@dataclass(frozen=True)
class RuleDefinition:
    """Stable metadata and evidence collection hook for a built-in rule."""

    finding_id: str
    rule_id: str
    rule_name: str
    default_severity: str
    confidence: str
    title: str
    evidence: str
    remediation: str
    collect_evidence: Callable[[dict[str, Any], CollectorHelpers], list[str]]


def _helper(name: str, helpers: CollectorHelpers) -> Callable[..., list[str]]:
    return helpers[name]


def collect_shell_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("tool_paths", helpers)(config, {"shell", "exec", "terminal", "subprocess", "python", "node"})


def collect_filesystem_broad_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    broad_paths, _write_paths = helpers["filesystem_access_paths"](config)
    return broad_paths


def collect_filesystem_write_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    _broad_paths, write_paths = helpers["filesystem_access_paths"](config)
    return write_paths


def collect_browser_private_network_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("browser_private_network_paths", helpers)(config)


def collect_approval_gate_missing_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("approval_missing_paths", helpers)(config)


def collect_weak_model_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("model_risk_paths", helpers)(config)


def collect_unpinned_remote_tool_source_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("unpinned_remote_tool_source_paths", helpers)(config)


def collect_runtime_package_install_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("runtime_package_install_paths", helpers)(config)


def collect_unrestricted_network_egress_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("unrestricted_network_egress_paths", helpers)(config)


def collect_secret_env_to_dangerous_tool_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    return _helper("secret_env_to_dangerous_tool_paths", helpers)(config)


def collect_no_evidence(_config: dict[str, Any], _helpers: CollectorHelpers) -> list[str]:
    """Composite rules receive pre-computed evidence paths from the linter."""

    return []


RULE_REGISTRY = {
    "shell_enabled": RuleDefinition(
        finding_id="shell_enabled",
        rule_id="ACL-001",
        rule_name="shell-enabled",
        default_severity="high",
        confidence="high",
        title="Shell execution is enabled",
        evidence="Agent can run local commands",
        remediation="Require explicit approval and sandbox shell execution.",
        collect_evidence=collect_shell_evidence,
    ),
    "filesystem_broad_access": RuleDefinition(
        finding_id="filesystem_broad_access",
        rule_id="ACL-002",
        rule_name="filesystem-broad-access",
        default_severity="high",
        confidence="high",
        title="Broad filesystem access",
        evidence="Filesystem roots include broad or unrestricted paths",
        remediation="Constrain file access to project-scoped allowlists.",
        collect_evidence=collect_filesystem_broad_evidence,
    ),
    "browser_private_network": RuleDefinition(
        finding_id="browser_private_network",
        rule_id="ACL-003",
        rule_name="browser-private-network",
        default_severity="high",
        confidence="high",
        title="Browser can reach private network",
        evidence="Browser config permits LAN/localhost/private network access",
        remediation="Block private network ranges unless explicitly needed.",
        collect_evidence=collect_browser_private_network_evidence,
    ),
    "lethal_trifecta": RuleDefinition(
        finding_id="lethal_trifecta",
        rule_id="ACL-004",
        rule_name="lethal-trifecta",
        default_severity="critical",
        confidence="high",
        title="Lethal trifecta present",
        evidence="Untrusted content, private data, and outbound action all appear enabled",
        remediation="Break at least one leg with isolation, deny-by-default tools, or approval gates.",
        collect_evidence=collect_no_evidence,
    ),
    "prompt_injection_exfiltration_bridge": RuleDefinition(
        finding_id="prompt_injection_exfiltration_bridge",
        rule_id="ACL-005",
        rule_name="prompt-injection-exfiltration-bridge",
        default_severity="critical",
        confidence="high",
        title="Prompt-injection-to-exfiltration bridge",
        evidence="Untrusted inputs can reach code execution with secrets/credentials and network egress enabled",
        remediation="Separate untrusted-input handling from code execution and credentials, or require per-action approval with egress allowlists.",
        collect_evidence=collect_no_evidence,
    ),
    "unattended_dangerous_tools": RuleDefinition(
        finding_id="unattended_dangerous_tools",
        rule_id="ACL-006",
        rule_name="unattended-dangerous-tools",
        default_severity="critical",
        confidence="high",
        title="Unattended dangerous tool use without approval gates",
        evidence="Autonomous or scheduled execution can use shell, destructive, or outbound tools without an explicit approval policy",
        remediation="Disable unattended execution or add explicit approval gates for shell, writes, deletes, deploys, and outbound sends.",
        collect_evidence=collect_no_evidence,
    ),
    "privileged_infra_control": RuleDefinition(
        finding_id="privileged_infra_control",
        rule_id="ACL-007",
        rule_name="privileged-infra-control",
        default_severity="critical",
        confidence="high",
        title="Privileged infrastructure control with credentials and network egress",
        evidence="Infrastructure-control tools have credential access and can communicate over the network",
        remediation="Run infra tools in isolated environments with least-privilege credentials, network egress restrictions, and mandatory approvals.",
        collect_evidence=collect_no_evidence,
    ),
    "approval_gate_missing": RuleDefinition(
        finding_id="approval_gate_missing",
        rule_id="ACL-008",
        rule_name="approval-gate-missing",
        default_severity="critical",
        confidence="high",
        title="Approval gate disabled for dangerous action",
        evidence="Approvals config disables one or more high-risk action gates",
        remediation="Require human approval for sends, shell, deletes, trades, purchases, and force-pushes.",
        collect_evidence=collect_approval_gate_missing_evidence,
    ),
    "weak_model_risk": RuleDefinition(
        finding_id="weak_model_risk",
        rule_id="ACL-009",
        rule_name="weak-model-risk",
        default_severity="medium",
        confidence="medium",
        title="Model may be weaker against prompt injection",
        evidence="Model name suggests small/local/uncensored configuration",
        remediation="Use stronger models for adversarial routing or add stricter tool gates.",
        collect_evidence=collect_weak_model_evidence,
    ),
    "filesystem_write_access": RuleDefinition(
        finding_id="filesystem_write_access",
        rule_id="ACL-010",
        rule_name="filesystem-write-access",
        default_severity="high",
        confidence="high",
        title="Filesystem write access",
        evidence="Filesystem configuration permits write-capable access",
        remediation="Prefer read-only filesystem mounts unless writes are required and path-scoped.",
        collect_evidence=collect_filesystem_write_evidence,
    ),
    "unpinned_remote_tool_source": RuleDefinition(
        finding_id="unpinned_remote_tool_source",
        rule_id="ACL-011",
        rule_name="unpinned-remote-tool-source",
        default_severity="high",
        confidence="medium",
        title="Remote tool source is not pinned",
        evidence="A remote MCP/tool package, URL, or command does not appear version-pinned or digest-pinned",
        remediation="Pin remote tools by exact version, commit, or digest and review update provenance.",
        collect_evidence=collect_unpinned_remote_tool_source_evidence,
    ),
    "runtime_package_install": RuleDefinition(
        finding_id="runtime_package_install",
        rule_id="ACL-012",
        rule_name="runtime-package-install",
        default_severity="high",
        confidence="high",
        title="Runtime package installation is enabled",
        evidence="Agent runtime can install packages or run package-manager install commands",
        remediation="Pre-build dependencies or require approval and lockfiles for runtime package installation.",
        collect_evidence=collect_runtime_package_install_evidence,
    ),
    "unrestricted_network_egress": RuleDefinition(
        finding_id="unrestricted_network_egress",
        rule_id="ACL-013",
        rule_name="unrestricted-network-egress",
        default_severity="high",
        confidence="high",
        title="Network egress is unrestricted",
        evidence="Network egress allows all destinations instead of a domain-scoped allowlist",
        remediation="Restrict network egress to reviewed domains or service endpoints.",
        collect_evidence=collect_unrestricted_network_egress_evidence,
    ),
    "secret_env_to_dangerous_tool": RuleDefinition(
        finding_id="secret_env_to_dangerous_tool",
        rule_id="ACL-014",
        rule_name="secret-env-to-dangerous-tool",
        default_severity="critical",
        confidence="high",
        title="Secret-bearing environment exposed to dangerous tool",
        evidence="Secret or environment variables are available to shell, MCP, package, or outbound tools",
        remediation="Do not expose broad environment secrets to dangerous tools; use scoped credentials and approval gates.",
        collect_evidence=collect_secret_env_to_dangerous_tool_evidence,
    ),
}
