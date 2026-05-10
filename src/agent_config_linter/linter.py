"""Core risk scoring for autonomous-agent configuration files."""

from copy import deepcopy

from .rules import RULE_REGISTRY

SEVERITIES = ("critical", "high", "medium", "low")


def _merge_dict(target, key, value):
    existing = target.get(key)
    if isinstance(existing, dict) and isinstance(value, dict):
        merged = dict(value)
        merged.update(existing)
        target[key] = merged
    elif key not in target:
        target[key] = value


def _list_provenance(target_key, source_key, values):
    if isinstance(values, list):
        return {f"{target_key}[{index}]": [f"{source_key}[{index}]"] for index in range(len(values))}
    return {target_key: [source_key]}


def _normalize_hermes_config(config):
    normalized = deepcopy(config)
    provenance = {}
    hermes = normalized.get("hermes")
    if not isinstance(hermes, dict):
        return normalized, provenance

    if "enabled_toolsets" in hermes and "enabled_toolsets" not in normalized:
        normalized["enabled_toolsets"] = hermes["enabled_toolsets"]
        provenance.update(_list_provenance("enabled_toolsets", "hermes.enabled_toolsets", hermes["enabled_toolsets"]))
    if "toolsets" in hermes and "toolsets" not in normalized:
        normalized["toolsets"] = hermes["toolsets"]
        provenance.update(_list_provenance("toolsets", "hermes.toolsets", hermes["toolsets"]))

    channels_key = "channels" if isinstance(hermes.get("channels"), dict) else "bindings"
    channels = hermes.get(channels_key)
    if isinstance(channels, dict):
        inputs = dict(normalized.get("inputs", {})) if isinstance(normalized.get("inputs"), dict) else {}
        for channel, value in channels.items():
            inputs.setdefault(channel, value)
            provenance[f"inputs.{channel}"] = [f"hermes.{channels_key}.{channel}"]
        normalized["inputs"] = inputs

    if isinstance(hermes.get("secrets"), dict):
        _merge_dict(normalized, "secrets", hermes["secrets"])
        for key in hermes["secrets"]:
            provenance[f"secrets.{key}"] = [f"hermes.secrets.{key}"]
        provenance["secrets"] = ["hermes.secrets"]

    network = hermes.get("network")
    if isinstance(network, dict) and is_enabled(network.get("egress")):
        tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
        tools.setdefault("http", {"enabled": True})
        provenance["tools.http"] = ["hermes.network.egress"]
        normalized["tools"] = tools
    return normalized, provenance


def _normalize_openclaw_config(config):
    normalized = deepcopy(config)
    provenance = {}
    openclaw = normalized.get("openclaw")
    if not isinstance(openclaw, dict):
        return normalized, provenance

    tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
    browser = openclaw.get("browser")
    if isinstance(browser, dict) and is_enabled(browser):
        browser_tool = dict(tools.get("browser", {})) if isinstance(tools.get("browser"), dict) else {}
        browser_tool.setdefault("enabled", True)
        provenance["tools.browser"] = ["openclaw.browser.enabled"]
        if is_enabled(browser.get("allowPrivateNetwork")) or is_enabled(browser.get("privateNetwork")):
            browser_tool["private_network"] = True
            provenance["tools.browser"].append(
                "openclaw.browser.allowPrivateNetwork" if "allowPrivateNetwork" in browser else "openclaw.browser.privateNetwork"
            )
        if is_enabled(browser.get("localhost")):
            browser_tool["localhost"] = True
            provenance["tools.browser"].append("openclaw.browser.localhost")
        tools["browser"] = browser_tool
    web = openclaw.get("web")
    if is_enabled(web):
        tools.setdefault("http", {"enabled": True})
        provenance["tools.http"] = ["openclaw.web"]
    if tools:
        normalized["tools"] = tools
    return normalized, provenance


def _normalize_openai_config(config):
    normalized = deepcopy(config)
    provenance = {}
    tools = normalized.get("tools")
    if not isinstance(tools, list):
        return normalized, provenance

    normalized_tools = {}
    for index, tool in enumerate(tools):
        if isinstance(tool, str):
            tool_type = tool
            function_name = tool
            source_path = f"tools[{index}]"
        elif isinstance(tool, dict):
            tool_type = str(tool.get("type", ""))
            function = tool.get("function", {}) if isinstance(tool.get("function"), dict) else {}
            function_name = str(function.get("name", tool_type))
            source_path = f"tools[{index}].function.name" if function else f"tools[{index}].type"
        else:
            continue
        normalized_type = tool_type.lower().replace("-", "_")
        normalized_name = function_name.lower().replace("-", "_")
        if normalized_type in {"code_interpreter", "computer_use"} or normalized_name in {"python", "shell", "terminal", "exec"}:
            normalized_tools["python"] = True
            provenance.setdefault("tools.python", []).append(source_path)
        if any(fragment in normalized_name for fragment in ("email", "send", "slack", "discord", "telegram", "http", "webhook")):
            normalized_tools[normalized_name] = {"enabled": True}
            provenance.setdefault(f"tools.{normalized_name}", []).append(source_path)
    normalized["tools"] = normalized_tools
    return normalized, provenance


def _text_contains_any(value, fragments):
    text = " ".join(str(item) for item in value) if isinstance(value, list) else str(value)
    normalized = text.lower().replace("-", "_")
    return any(fragment in normalized for fragment in fragments)


def _normalize_mcp_config(config):
    normalized = deepcopy(config)
    provenance = {}
    servers = normalized.get("mcpServers") or normalized.get("mcp_servers")
    server_key = "mcpServers" if isinstance(normalized.get("mcpServers"), dict) else "mcp_servers"
    if not isinstance(servers, dict):
        return normalized, provenance

    tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
    secrets = dict(normalized.get("secrets", {})) if isinstance(normalized.get("secrets"), dict) else {}
    for server_name, server in servers.items():
        if not isinstance(server, dict) or is_enabled(server.get("disabled")):
            continue
        command = server.get("command", "")
        args = server.get("args", [])
        server_text = [server_name, command, *args] if isinstance(args, list) else [server_name, command, args]
        source_prefix = f"{server_key}.{server_name}"
        if _text_contains_any(server_text, {"shell", "terminal", "exec", "code_interpreter"}):
            tools.setdefault("shell", {"enabled": True})
            provenance.setdefault("tools.shell", []).append(f"{source_prefix}.command")
        if _text_contains_any(server_text, {"filesystem", "file_system", "fs"}):
            tools.setdefault("filesystem", {"enabled": True, "mode": "ro", "paths": ["./"]})
            provenance.setdefault("tools.filesystem", []).append(f"{source_prefix}.command")
        if _text_contains_any(server_text, {"browser", "http", "webhook", "slack", "discord", "telegram", "email", "send"}):
            tools.setdefault("http", {"enabled": True})
            provenance.setdefault("tools.http", []).append(f"{source_prefix}.command")
        if isinstance(server.get("env"), dict) and server["env"]:
            secrets.setdefault("env", True)
            provenance.setdefault("secrets.env", []).append(f"{source_prefix}.env")

    if tools:
        normalized["tools"] = tools
    if secrets:
        normalized["secrets"] = secrets
    return normalized, provenance


def _permissions_allow_write(value):
    if isinstance(value, str):
        return value.lower() in {"write", "admin"}
    if isinstance(value, dict):
        return any(_permissions_allow_write(child) for child in value.values())
    return False


def _normalize_github_actions_config(config):
    normalized = deepcopy(config)
    provenance = {}
    tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
    secrets = dict(normalized.get("secrets", {})) if isinstance(normalized.get("secrets"), dict) else {}
    autonomy = dict(normalized.get("autonomy", {})) if isinstance(normalized.get("autonomy"), dict) else {}

    if _permissions_allow_write(normalized.get("permissions")):
        tools.setdefault("github", {"enabled": True, "write": True})
        provenance.setdefault("tools.github", []).append("permissions")

    jobs = normalized.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_prefix = f"jobs.{job_name}"
            if _permissions_allow_write(job.get("permissions")):
                tools.setdefault("github", {"enabled": True, "write": True})
                provenance.setdefault("tools.github", []).append(f"{job_prefix}.permissions")
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                run = str(step.get("run", ""))
                step_text = [step.get("name", ""), run]
                step_prefix = f"{job_prefix}.steps[{index}]"
                if "secrets." in (str(step.get("env", {})) + run).lower():
                    secrets.setdefault("env", True)
                    provenance.setdefault("secrets.env", []).append(f"{step_prefix}.env" if step.get("env") else f"{step_prefix}.run")
                if _text_contains_any(step_text, {"unattended", "autonomous", "schedule"}):
                    autonomy.setdefault("enabled", True)
                    autonomy.setdefault("mode", "unattended")
                    provenance.setdefault("autonomy", []).append(f"{step_prefix}.run")
                if _text_contains_any(step_text, {"tool shell", " terminal", " exec", "bash", "python"}):
                    tools.setdefault("shell", {"enabled": True})
                    provenance.setdefault("tools.shell", []).append(f"{step_prefix}.run")
                if _text_contains_any(step_text, {"webhook", "http", "curl", "slack", "discord", "telegram", "email", "send"}):
                    tools.setdefault("http", {"enabled": True})
                    provenance.setdefault("tools.http", []).append(f"{step_prefix}.run")

    if tools:
        normalized["tools"] = tools
    if secrets:
        normalized["secrets"] = secrets
    if autonomy:
        normalized["autonomy"] = autonomy
    return normalized, provenance


def normalize_config(config):
    """Return (adapter name, normalized config, evidence provenance) for known agent schema shapes."""
    if not isinstance(config, dict):
        return "generic", {}, {}
    if isinstance(config.get("mcpServers"), dict) or isinstance(config.get("mcp_servers"), dict):
        normalized, provenance = _normalize_mcp_config(config)
        return "mcp", normalized, provenance
    if isinstance(config.get("jobs"), dict) and (
        "permissions" in config or any(isinstance(job, dict) and "steps" in job for job in config.get("jobs", {}).values())
    ):
        normalized, provenance = _normalize_github_actions_config(config)
        return "github_actions", normalized, provenance
    if isinstance(config.get("hermes"), dict):
        normalized, provenance = _normalize_hermes_config(config)
        return "hermes", normalized, provenance
    if isinstance(config.get("openclaw"), dict):
        normalized, provenance = _normalize_openclaw_config(config)
        return "openclaw", normalized, provenance
    if isinstance(config.get("tools"), list):
        normalized, provenance = _normalize_openai_config(config)
        return "openai", normalized, provenance
    return "generic", deepcopy(config), {}


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
    return sorted(set(broad_paths)), sorted(set(write_paths))


def _filesystem_broad(config):
    broad_paths, _write_paths = _filesystem_access_paths(config)
    return bool(broad_paths)


def _browser_private_network_paths(config):
    paths = []
    for path, value in walk_items(config):
        if "browser" in path.lower() and isinstance(value, dict) and is_enabled(value):
            if is_enabled(value.get("private_network")) or is_enabled(value.get("localhost")) or is_enabled(value.get("lan")):
                paths.append(path)
    return sorted(set(paths))


def _browser_private_network(config):
    return bool(_browser_private_network_paths(config))


def _approval_missing_paths(config):
    approvals = config.get("approvals") if isinstance(config, dict) else None
    if approvals is False or approvals == "none":
        return ["approvals"]
    paths = []
    if isinstance(approvals, dict):
        dangerous = ["send_email", "email", "shell", "exec", "delete", "trade", "purchase", "force_push", "force-push"]
        for name in dangerous:
            if name in approvals and not is_enabled(approvals[name]):
                paths.append(f"approvals.{name}")
    return paths


def _approval_missing(config):
    return bool(_approval_missing_paths(config))


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


def _source_paths_for(evidence_paths, provenance):
    source_paths = []
    for evidence_path in evidence_paths:
        source_paths.extend(provenance.get(evidence_path, [evidence_path]))
    return list(dict.fromkeys(source_paths))


def _add(findings, finding_id, evidence_paths=None, source_evidence_paths=None, severity=None):
    rule = RULE_REGISTRY[finding_id]
    unique_evidence_paths = list(dict.fromkeys(evidence_paths or []))
    unique_source_paths = list(dict.fromkeys(source_evidence_paths or unique_evidence_paths))
    findings.append(
        {
            "id": finding_id,
            "rule_id": rule.rule_id,
            "rule_name": rule.rule_name,
            "severity": severity or rule.default_severity,
            "confidence": rule.confidence,
            "title": rule.title,
            "evidence": rule.evidence,
            "evidence_paths": unique_evidence_paths,
            "source_evidence_paths": unique_source_paths,
            "remediation": rule.remediation,
        }
    )


def lint_config(config):
    """Return a deterministic risk report for one config mapping."""
    adapter, normalized_config, provenance = normalize_config(config)
    config = normalized_config

    capabilities = []
    findings = []
    helpers = {
        "tool_paths": _tool_paths,
        "filesystem_access_paths": _filesystem_access_paths,
        "browser_private_network_paths": _browser_private_network_paths,
        "approval_missing_paths": _approval_missing_paths,
        "model_risk_paths": _model_risk_paths,
    }

    def add_finding(finding_id, evidence_paths=None, severity=None):
        evidence_paths = list(dict.fromkeys(evidence_paths or []))
        _add(
            findings,
            finding_id,
            evidence_paths=evidence_paths,
            source_evidence_paths=_source_paths_for(evidence_paths, provenance),
            severity=severity,
        )

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
    shell_paths = RULE_REGISTRY["shell_enabled"].collect_evidence(config, helpers)
    code_execution = bool(shell_paths)
    network_egress_paths = _network_egress_paths(config)
    network_egress = bool(network_egress_paths)
    filesystem_broad_paths = RULE_REGISTRY["filesystem_broad_access"].collect_evidence(config, helpers)
    filesystem_write_paths = RULE_REGISTRY["filesystem_write_access"].collect_evidence(config, helpers)
    browser_private_network_paths = RULE_REGISTRY["browser_private_network"].collect_evidence(config, helpers)
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
        add_finding("shell_enabled", shell_paths)

    if filesystem_broad_paths:
        capabilities.append("filesystem_broad_access")
        add_finding("filesystem_broad_access", filesystem_broad_paths)

    if filesystem_write_paths:
        capabilities.append("filesystem_write_access")
        add_finding("filesystem_write_access", filesystem_write_paths)

    if browser_private_network_paths:
        capabilities.append("browser_private_network")
        add_finding("browser_private_network", browser_private_network_paths)

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
        add_finding("lethal_trifecta", untrusted_input_paths + private_data_paths + outbound_action_paths)

    if untrusted_inputs and code_execution and secrets_access and network_egress:
        add_finding(
            "prompt_injection_exfiltration_bridge",
            shell_paths + untrusted_input_paths + secrets_access_paths + network_egress_paths,
        )

    if unattended_autonomy and (code_execution or destructive_actions or outbound_actions) and not _approval_configured(config):
        add_finding(
            "unattended_dangerous_tools",
            unattended_autonomy_paths + shell_paths + destructive_action_paths + outbound_action_paths,
        )

    if privileged_infra and secrets_access and network_egress:
        add_finding("privileged_infra_control", privileged_infra_paths + secrets_access_paths + network_egress_paths)

    approval_missing_paths = RULE_REGISTRY["approval_gate_missing"].collect_evidence(config, helpers)
    if approval_missing_paths:
        add_finding("approval_gate_missing", approval_missing_paths)

    model_risk_paths = RULE_REGISTRY["weak_model_risk"].collect_evidence(config, helpers)
    if model_risk_paths:
        add_finding("weak_model_risk", model_risk_paths)

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
