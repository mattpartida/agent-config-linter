"""Core risk scoring for autonomous-agent configuration files."""

from copy import deepcopy

SEVERITIES = ("critical", "high", "medium", "low")

RULE_IDS = {
    "shell_enabled": ("ACL-001", "shell-enabled"),
    "filesystem_broad_access": ("ACL-002", "filesystem-broad-access"),
    "browser_private_network": ("ACL-003", "browser-private-network"),
    "lethal_trifecta": ("ACL-004", "lethal-trifecta"),
    "prompt_injection_exfiltration_bridge": ("ACL-005", "prompt-injection-exfiltration-bridge"),
    "unattended_dangerous_tools": ("ACL-006", "unattended-dangerous-tools"),
    "privileged_infra_control": ("ACL-007", "privileged-infra-control"),
    "approval_gate_missing": ("ACL-008", "approval-gate-missing"),
    "weak_model_risk": ("ACL-009", "weak-model-risk"),
    "filesystem_write_access": ("ACL-010", "filesystem-write-access"),
}


def _merge_dict(target, key, value):
    existing = target.get(key)
    if isinstance(existing, dict) and isinstance(value, dict):
        merged = dict(value)
        merged.update(existing)
        target[key] = merged
    elif key not in target:
        target[key] = value


def _normalize_hermes_config(config):
    normalized = deepcopy(config)
    hermes = normalized.get("hermes")
    if not isinstance(hermes, dict):
        return normalized

    if "enabled_toolsets" in hermes and "enabled_toolsets" not in normalized:
        normalized["enabled_toolsets"] = hermes["enabled_toolsets"]
    if "toolsets" in hermes and "toolsets" not in normalized:
        normalized["toolsets"] = hermes["toolsets"]

    channels = hermes.get("channels") or hermes.get("bindings")
    if isinstance(channels, dict):
        inputs = dict(normalized.get("inputs", {})) if isinstance(normalized.get("inputs"), dict) else {}
        for channel, value in channels.items():
            inputs.setdefault(channel, value)
        normalized["inputs"] = inputs

    if isinstance(hermes.get("secrets"), dict):
        _merge_dict(normalized, "secrets", hermes["secrets"])

    network = hermes.get("network")
    if isinstance(network, dict) and is_enabled(network.get("egress")):
        tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
        tools.setdefault("http", {"enabled": True})
        normalized["tools"] = tools
    return normalized


def _normalize_openclaw_config(config):
    normalized = deepcopy(config)
    openclaw = normalized.get("openclaw")
    if not isinstance(openclaw, dict):
        return normalized

    tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
    browser = openclaw.get("browser")
    if isinstance(browser, dict) and is_enabled(browser):
        browser_tool = dict(tools.get("browser", {})) if isinstance(tools.get("browser"), dict) else {}
        browser_tool.setdefault("enabled", True)
        if is_enabled(browser.get("allowPrivateNetwork")) or is_enabled(browser.get("privateNetwork")):
            browser_tool["private_network"] = True
        if is_enabled(browser.get("localhost")):
            browser_tool["localhost"] = True
        tools["browser"] = browser_tool
    web = openclaw.get("web")
    if is_enabled(web):
        tools.setdefault("http", {"enabled": True})
    if tools:
        normalized["tools"] = tools
    return normalized


def _normalize_openai_config(config):
    normalized = deepcopy(config)
    tools = normalized.get("tools")
    if not isinstance(tools, list):
        return normalized

    normalized_tools = {}
    for tool in tools:
        if isinstance(tool, str):
            tool_type = tool
            function_name = tool
        elif isinstance(tool, dict):
            tool_type = str(tool.get("type", ""))
            function = tool.get("function", {}) if isinstance(tool.get("function"), dict) else {}
            function_name = str(function.get("name", tool_type))
        else:
            continue
        normalized_type = tool_type.lower().replace("-", "_")
        normalized_name = function_name.lower().replace("-", "_")
        if normalized_type in {"code_interpreter", "computer_use"} or normalized_name in {"python", "shell", "terminal", "exec"}:
            normalized_tools["python"] = True
        if any(fragment in normalized_name for fragment in ("email", "send", "slack", "discord", "telegram", "http", "webhook")):
            normalized_tools[normalized_name] = {"enabled": True}
    normalized["tools"] = normalized_tools
    return normalized


def normalize_config(config):
    """Return (adapter name, normalized config) for known agent schema shapes."""
    if not isinstance(config, dict):
        return "generic", {}
    if isinstance(config.get("hermes"), dict):
        return "hermes", _normalize_hermes_config(config)
    if isinstance(config.get("openclaw"), dict):
        return "openclaw", _normalize_openclaw_config(config)
    if isinstance(config.get("tools"), list):
        return "openai", _normalize_openai_config(config)
    return "generic", deepcopy(config)


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


def _enabled_key_paths(config, names, prefix=""):
    names = {name.lower() for name in names}
    paths = []
    for path, value in walk_items(config):
        parts = path.lower().replace("_", "-").split(".")
        if any(part in names or part.replace("-", "_") in names for part in parts) and is_enabled(value):
            paths.append(f"{prefix}.{path}" if prefix else path)
    return paths


def _has_enabled_key(config, names):
    return bool(_enabled_key_paths(config, names))


def _filesystem_access_paths(config):
    broad_paths = []
    write_paths = []
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
            broad_paths.append(path)
        if value.get("write") is True or value.get("mode") in {"rw", "write", "read-write"}:
            write_paths.append(path)
            broad_paths.append(path)
    return sorted(set(broad_paths)), sorted(set(write_paths))


def _filesystem_broad(config):
    broad_paths, _write_paths = _filesystem_access_paths(config)
    return bool(broad_paths)


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


def _model_risk_paths(config):
    model = str(config.get("model", "") if isinstance(config, dict) else "").lower()
    risky_fragments = ["small", "local", "7b", "3b", "uncensored", "abliterated", "abliteratus", "no-guard"]
    return ["model"] if any(fragment in model for fragment in risky_fragments) else []


def _model_risk(config):
    return bool(_model_risk_paths(config))


def _network_egress_paths(config):
    return _enabled_key_paths(
        config,
        {
            "api",
            "browser",
            "discord",
            "email",
            "fetch",
            "github",
            "http",
            "post",
            "requests",
            "send_message",
            "slack",
            "telegram",
            "webhook",
        },
    )


def _network_egress(config):
    return bool(_network_egress_paths(config))


def _secrets_or_credentials_access_paths(config):
    return _enabled_key_paths(
        config,
        {
            "api_key",
            "api-keys",
            "api_keys",
            "cloud",
            "credential",
            "credentials",
            "env",
            "environment",
            "kubeconfig",
            "oauth",
            "secret",
            "secrets",
            "ssh-key",
            "ssh_key",
            "token",
            "tokens",
        },
    )


def _secrets_or_credentials_access(config):
    return bool(_secrets_or_credentials_access_paths(config))


def _destructive_action_paths(config):
    paths = _enabled_key_paths(
        config,
        {
            "admin",
            "approve",
            "delete",
            "deploy",
            "force-push",
            "force_push",
            "merge",
            "purchase",
            "rm",
            "trade",
            "write",
        },
    )
    for path, value in walk_items(config):
        lower_path = path.lower().replace("_", "-")
        if not isinstance(value, dict) or not is_enabled(value):
            continue
        if any(name in lower_path for name in {"github", "filesystem", "file", "database", "db", "cloud"}):
            if any(is_enabled(value.get(flag)) for flag in ("write", "delete", "admin", "deploy", "merge", "force_push")):
                paths.append(path)
                continue
            if str(value.get("mode", "")).lower() in {"rw", "write", "read-write", "admin"}:
                paths.append(path)
    return sorted(set(paths))


def _destructive_actions(config):
    return bool(_destructive_action_paths(config))


def _unattended_autonomy_paths(config):
    paths = []
    for path, value in walk_items(config):
        lower_path = path.lower().replace("_", "-")
        if any(name in lower_path for name in {"autonomy", "schedule", "cron", "daemon", "background", "loop"}) and is_enabled(value):
            if isinstance(value, dict):
                mode = str(value.get("mode", "")).lower()
                if mode in {"unattended", "autonomous", "auto", "always-on"} or any(
                    key in value for key in ("cron", "interval", "every", "schedule")
                ):
                    paths.append(path)
            else:
                paths.append(path)
    return sorted(set(paths))


def _unattended_autonomy(config):
    return bool(_unattended_autonomy_paths(config))


def _privileged_infra_paths(config):
    return _enabled_key_paths(
        config,
        {
            "aws",
            "azure",
            "cloud",
            "docker",
            "gcp",
            "k8s",
            "kubernetes",
            "pulumi",
            "terraform",
            "vps",
        },
    )


def _privileged_infra(config):
    return bool(_privileged_infra_paths(config))


def _approval_configured(config):
    approvals = config.get("approvals") if isinstance(config, dict) else None
    if isinstance(approvals, dict):
        return any(is_enabled(value) for value in approvals.values())
    return is_enabled(approvals)


def _tool_paths(config, names):
    tools = config.get("tools", {}) if isinstance(config, dict) else {}
    names = {name.lower().replace("_", "-") for name in names}
    paths = []
    if isinstance(tools, dict):
        for key, value in tools.items():
            normalized = str(key).lower().replace("_", "-")
            if normalized in names and is_enabled(value):
                paths.append(f"tools.{key}")
    for toolset_key in ("enabled_toolsets", "toolsets", "enabled-tools", "enabled_tools"):
        toolsets = config.get(toolset_key, []) if isinstance(config, dict) else []
        if isinstance(toolsets, str):
            toolsets = [toolsets]
        if isinstance(toolsets, list):
            for index, tool_name in enumerate(toolsets):
                normalized = str(tool_name).lower().replace("_", "-")
                if normalized in names:
                    paths.append(f"{toolset_key}[{index}]")
    return paths


def _tool_enabled(config, names):
    return bool(_tool_paths(config, names))


def _add(findings, finding_id, severity, title, evidence, remediation, evidence_paths=None):
    rule_id, rule_name = RULE_IDS.get(finding_id, (finding_id, finding_id.replace("_", "-")))
    unique_evidence_paths = list(dict.fromkeys(evidence_paths or []))
    findings.append(
        {
            "id": finding_id,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "evidence_paths": unique_evidence_paths,
            "remediation": remediation,
        }
    )


def lint_config(config):
    """Return a deterministic risk report for one config mapping."""
    adapter, normalized_config = normalize_config(config)
    config = normalized_config

    capabilities = []
    findings = []

    input_config = config.get("inputs", config)
    input_prefix = "inputs" if isinstance(config, dict) and isinstance(config.get("inputs"), dict) else ""
    untrusted_input_paths = _enabled_key_paths(
        input_config,
        {"web", "browser", "discord", "slack", "telegram", "email", "http", "rss", "webhook"},
        prefix=input_prefix,
    )
    private_data_paths = _enabled_key_paths(
        config,
        {"filesystem", "files", "memory", "notes", "gmail", "email", "drive", "github", "secrets", "env"},
    )
    outbound_action_paths = _enabled_key_paths(
        config,
        {"email", "send_email", "send-email", "discord", "telegram", "slack", "send_message", "http", "webhook", "github", "browser"},
    )
    untrusted_inputs = bool(untrusted_input_paths)
    private_data = bool(private_data_paths)
    outbound_actions = bool(outbound_action_paths)
    shell_paths = _tool_paths(config, {"shell", "exec", "terminal", "subprocess", "python", "node"})
    code_execution = bool(shell_paths)
    network_egress_paths = _network_egress_paths(config)
    network_egress = bool(network_egress_paths)
    filesystem_broad_paths, filesystem_write_paths = _filesystem_access_paths(config)
    secrets_access_paths = _secrets_or_credentials_access_paths(config)
    secrets_access = bool(secrets_access_paths)
    destructive_action_paths = _destructive_action_paths(config)
    destructive_actions = bool(destructive_action_paths)
    unattended_autonomy_paths = _unattended_autonomy_paths(config)
    unattended_autonomy = bool(unattended_autonomy_paths)
    privileged_infra_paths = _privileged_infra_paths(config)
    privileged_infra = bool(privileged_infra_paths)

    if code_execution:
        capabilities.append("shell_enabled")
        capabilities.append("code_execution")
        _add(
            findings,
            "shell_enabled",
            "high",
            "Shell execution is enabled",
            "Agent can run local commands",
            "Require explicit approval and sandbox shell execution.",
            shell_paths,
        )

    if filesystem_broad_paths:
        capabilities.append("filesystem_broad_access")
        _add(
            findings,
            "filesystem_broad_access",
            "high",
            "Broad filesystem access",
            "Filesystem roots include broad paths or write access",
            "Constrain file access to project-scoped allowlists.",
            filesystem_broad_paths,
        )

    if filesystem_write_paths:
        capabilities.append("filesystem_write_access")
        _add(
            findings,
            "filesystem_write_access",
            "high",
            "Filesystem write access",
            "Filesystem configuration permits write-capable access",
            "Prefer read-only filesystem mounts unless writes are required and path-scoped.",
            filesystem_write_paths,
        )

    if _browser_private_network(config):
        capabilities.append("browser_private_network")
        _add(findings, "browser_private_network", "high", "Browser can reach private network", "Browser config permits LAN/localhost/private network access", "Block private network ranges unless explicitly needed.")

    if untrusted_inputs:
        capabilities.append("untrusted_inputs")
    if private_data:
        capabilities.append("private_data_access")
    if outbound_actions:
        capabilities.append("outbound_actions")
    if network_egress:
        capabilities.append("network_egress")
    if secrets_access:
        capabilities.append("secrets_access")
        capabilities.append("credentials_access")
    if destructive_actions:
        capabilities.append("destructive_actions")
    if unattended_autonomy:
        capabilities.append("unattended_autonomy")
    if privileged_infra:
        capabilities.append("privileged_infra")

    lethal_trifecta = untrusted_inputs and private_data and outbound_actions
    if lethal_trifecta:
        _add(
            findings,
            "lethal_trifecta",
            "critical",
            "Lethal trifecta present",
            "Untrusted content, private data, and outbound action all appear enabled",
            "Break at least one leg with isolation, deny-by-default tools, or approval gates.",
            untrusted_input_paths + private_data_paths + outbound_action_paths,
        )

    if untrusted_inputs and code_execution and secrets_access and network_egress:
        _add(
            findings,
            "prompt_injection_exfiltration_bridge",
            "critical",
            "Prompt-injection-to-exfiltration bridge",
            "Untrusted inputs can reach code execution with secrets/credentials and network egress enabled",
            "Separate untrusted-input handling from code execution and credentials, or require per-action approval with egress allowlists.",
            shell_paths + untrusted_input_paths + secrets_access_paths + network_egress_paths,
        )

    if unattended_autonomy and (code_execution or destructive_actions or outbound_actions) and not _approval_configured(config):
        _add(
            findings,
            "unattended_dangerous_tools",
            "critical",
            "Unattended dangerous tool use without approval gates",
            "Autonomous or scheduled execution can use shell, destructive, or outbound tools without an explicit approval policy",
            "Disable unattended execution or add explicit approval gates for shell, writes, deletes, deploys, and outbound sends.",
            unattended_autonomy_paths + shell_paths + destructive_action_paths + outbound_action_paths,
        )

    if privileged_infra and secrets_access and network_egress:
        _add(
            findings,
            "privileged_infra_control",
            "critical",
            "Privileged infrastructure control with credentials and network egress",
            "Infrastructure-control tools have credential access and can communicate over the network",
            "Run infra tools in isolated environments with least-privilege credentials, network egress restrictions, and mandatory approvals.",
            privileged_infra_paths + secrets_access_paths + network_egress_paths,
        )

    if _approval_missing(config):
        _add(findings, "approval_gate_missing", "critical", "Approval gate disabled for dangerous action", "Approvals config disables one or more high-risk action gates", "Require human approval for sends, shell, deletes, trades, purchases, and force-pushes.")

    model_risk_paths = _model_risk_paths(config)
    if model_risk_paths:
        _add(findings, "weak_model_risk", "medium", "Model may be weaker against prompt injection", "Model name suggests small/local/uncensored configuration", "Use stronger models for adversarial routing or add stricter tool gates.", model_risk_paths)

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
        "schema": {"adapter": adapter},
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
