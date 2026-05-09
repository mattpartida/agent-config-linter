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
    title: str
    evidence: str
    remediation: str
    collect_evidence: Callable[[dict[str, Any], CollectorHelpers], list[str]]


def collect_shell_evidence(config: dict[str, Any], helpers: CollectorHelpers) -> list[str]:
    """Collect evidence paths for shell/code-execution capability."""

    tool_paths = helpers["tool_paths"]
    return tool_paths(config, {"shell", "exec", "terminal", "subprocess", "python", "node"})


RULE_REGISTRY = {
    "shell_enabled": RuleDefinition(
        finding_id="shell_enabled",
        rule_id="ACL-001",
        rule_name="shell-enabled",
        default_severity="high",
        title="Shell execution is enabled",
        evidence="Agent can run local commands",
        remediation="Require explicit approval and sandbox shell execution.",
        collect_evidence=collect_shell_evidence,
    )
}
