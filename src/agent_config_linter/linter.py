"""Core risk scoring for autonomous-agent configuration files."""

SEVERITIES = ("critical", "high", "medium", "low")


def is_enabled(value):
    """Return True when a scalar/dict config value represents an enabled feature."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    if isinstance(value, dict):
        if "enabled" in value:
            return is_enabled(value["enabled"])
        if "disabled" in value:
            return not is_enabled(value["disabled"])
        return bool(value)
    if isinstance(value, list):
        return any(is_enabled(item) for item in value)
    return bool(value)


def walk_items(value, path=""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield child_path, child
            yield from walk_items(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            yield child_path, child
            yield from walk_items(child, child_path)


def _has_enabled_key(config, names):
    names = {name.lower() for name in names}
    for path, value in walk_items(config):
        parts = path.lower().replace("_", "-").split(".")
        if any(part in names or part.replace("-", "_") in names for part in parts) and is_enabled(value):
            return True
    return False


def _filesystem_broad(config):
    for path, value in walk_items(config):
        lower_path = path.lower()
        if "filesystem" not in lower_path and "file" not in lower_path:
            continue
        if not isinstance(value, dict) or not is_enabled(value):
            continue
        roots = value.get("roots") or value.get("paths") or value.get("allow") or value.get("allowlist") or []
        if isinstance(roots, str):
            roots = [roots]
        if any(root in {"/", "~", "$HOME", "*"} for root in roots):
            return True
        if value.get("write") is True or value.get("mode") in {"rw", "write", "read-write"}:
            return True
    return False


def _browser_private_network(config):
    for path, value in walk_items(config):
        if "browser" in path.lower() and isinstance(value, dict) and is_enabled(value):
            if is_enabled(value.get("private_network")) or is_enabled(value.get("localhost")) or is_enabled(value.get("lan")):
                return True
    return False


def _approval_missing(config):
    approvals = config.get("approvals") if isinstance(config, dict) else None
    if approvals is False or approvals == "none":
        return True
    if isinstance(approvals, dict):
        dangerous = ["send_email", "email", "shell", "exec", "delete", "trade", "purchase", "force_push", "force-push"]
        return any(name in approvals and not is_enabled(approvals[name]) for name in dangerous)
    return False


def _model_risk(config):
    model = str(config.get("model", "") if isinstance(config, dict) else "").lower()
    risky_fragments = ["small", "local", "7b", "3b", "uncensored", "abliterated", "abliteratus", "no-guard"]
    return any(fragment in model for fragment in risky_fragments)


def _tool_enabled(config, names):
    tools = config.get("tools", {}) if isinstance(config, dict) else {}
    names = {name.lower() for name in names}
    if isinstance(tools, dict):
        for key, value in tools.items():
            normalized = str(key).lower().replace("_", "-")
            if normalized in names or normalized.replace("-", "_") in names:
                return is_enabled(value)
    return False


def _add(findings, finding_id, severity, title, evidence, remediation):
    findings.append(
        {
            "id": finding_id,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "remediation": remediation,
        }
    )


def lint_config(config):
    """Return a deterministic risk report for one config mapping."""
    if not isinstance(config, dict):
        config = {}

    capabilities = []
    findings = []

    untrusted_inputs = _has_enabled_key(config.get("inputs", config), {"web", "browser", "discord", "slack", "telegram", "email", "http", "rss", "webhook"})
    private_data = _has_enabled_key(config, {"filesystem", "files", "memory", "notes", "gmail", "email", "drive", "github", "secrets", "env"})
    outbound_actions = _has_enabled_key(config, {"email", "discord", "telegram", "slack", "send_message", "http", "webhook", "github", "browser"})

    if _tool_enabled(config, {"shell", "exec", "terminal", "subprocess"}):
        capabilities.append("shell_enabled")
        _add(findings, "shell_enabled", "high", "Shell execution is enabled", "Agent can run local commands", "Require explicit approval and sandbox shell execution.")

    if _filesystem_broad(config):
        capabilities.append("filesystem_broad_access")
        _add(findings, "filesystem_broad_access", "high", "Broad filesystem access", "Filesystem roots include broad paths or write access", "Constrain file access to project-scoped allowlists.")

    if _browser_private_network(config):
        capabilities.append("browser_private_network")
        _add(findings, "browser_private_network", "high", "Browser can reach private network", "Browser config permits LAN/localhost/private network access", "Block private network ranges unless explicitly needed.")

    if untrusted_inputs:
        capabilities.append("untrusted_inputs")
    if private_data:
        capabilities.append("private_data_access")
    if outbound_actions:
        capabilities.append("outbound_actions")

    lethal_trifecta = untrusted_inputs and private_data and outbound_actions
    if lethal_trifecta:
        _add(findings, "lethal_trifecta", "critical", "Lethal trifecta present", "Untrusted content, private data, and outbound action all appear enabled", "Break at least one leg with isolation, deny-by-default tools, or approval gates.")

    if _approval_missing(config):
        _add(findings, "approval_gate_missing", "critical", "Approval gate disabled for dangerous action", "Approvals config disables one or more high-risk action gates", "Require human approval for sends, shell, deletes, trades, purchases, and force-pushes.")

    if _model_risk(config):
        _add(findings, "weak_model_risk", "medium", "Model may be weaker against prompt injection", "Model name suggests small/local/uncensored configuration", "Use stronger models for adversarial routing or add stricter tool gates.")

    summary = {severity: sum(1 for finding in findings if finding["severity"] == severity) for severity in SEVERITIES}
    score = summary["critical"] * 40 + summary["high"] * 15 + summary["medium"] * 5 + summary["low"]
    if summary["critical"] or score >= 60:
        risk_level = "critical"
    elif summary["high"] or score >= 25:
        risk_level = "high"
    elif summary["medium"] or capabilities:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "schema_version": "0.1",
        "risk_level": risk_level,
        "score": score,
        "summary": summary,
        "signals": {
            "lethal_trifecta": lethal_trifecta,
            "enabled_capabilities": sorted(set(capabilities)),
        },
        "findings": findings,
        "recommended_next_actions": [finding["remediation"] for finding in findings[:5]],
    }
