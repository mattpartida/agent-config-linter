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


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _pin_looks_stable(value):
    text = str(value).strip().lower()
    if "@sha256:" in text or "?sha=" in text or "#sha" in text:
        return True
    if "://" in text and any(marker in text for marker in ("/commit/", "@sha", "?ref=")):
        return True
    parts = text.rsplit("@", 1)
    return len(parts) == 2 and any(char.isdigit() for char in parts[1]) and parts[1] not in {"latest", "main", "master"}


def _source_path_join(prefix, *parts):
    path = prefix
    for part in parts:
        if isinstance(part, int):
            path = f"{path}[{part}]"
        else:
            path = f"{path}.{part}" if path else str(part)
    return path


def _merge_agent_tools(agent, source_prefix, normalized, provenance):
    tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
    secrets = dict(normalized.get("secrets", {})) if isinstance(normalized.get("secrets"), dict) else {}
    network = dict(normalized.get("network", {})) if isinstance(normalized.get("network"), dict) else {}
    autonomy = dict(normalized.get("autonomy", {})) if isinstance(normalized.get("autonomy"), dict) else {}

    tool_values = agent.get("tools", {}) if isinstance(agent, dict) else {}
    iterable_tools = []
    if isinstance(tool_values, dict):
        iterable_tools.extend((name, value, _source_path_join(source_prefix, "tools", name)) for name, value in tool_values.items())
    elif isinstance(tool_values, list):
        iterable_tools.extend((str(value), True, _source_path_join(source_prefix, "tools", index)) for index, value in enumerate(tool_values))

    for name, value, source_path in iterable_tools:
        normalized_name = str(name).lower().replace("-", "_")
        if normalized_name in {"terminal", "shell", "bash", "exec", "python", "code_interpreter"} and is_enabled(value):
            tools.setdefault("shell", {"enabled": True})
            provenance.setdefault("tools.shell", []).append(source_path)
        if normalized_name in {"http", "requests", "browser", "web", "webhook", "send_email", "email", "slack", "discord", "telegram"} and is_enabled(value):
            tool_key = "browser" if normalized_name == "browser" else "http"
            tools.setdefault(tool_key, {"enabled": True})
            provenance.setdefault(f"tools.{tool_key}", []).append(source_path)
        if normalized_name in {"filesystem", "file_system", "files", "fs"} and is_enabled(value):
            filesystem_value = value if isinstance(value, dict) else {"enabled": True}
            tools["filesystem"] = filesystem_value
            provenance.setdefault("tools.filesystem", []).append(source_path)
        if any(fragment in normalized_name for fragment in ("git_write", "write", "delete", "deploy")) and is_enabled(value):
            tools.setdefault(normalized_name, {"enabled": True, "write": True})
            provenance.setdefault(f"tools.{normalized_name}", []).append(source_path)

    approvals = agent.get("approvals") if isinstance(agent, dict) else None
    if approvals is not None and "approvals" not in normalized:
        normalized["approvals"] = False if str(approvals).lower() in {"none", "never", "false"} else approvals
        provenance["approvals"] = [_source_path_join(source_prefix, "approvals")]

    agent_network = agent.get("network") if isinstance(agent, dict) else None
    if isinstance(agent_network, dict) and "egress" in agent_network:
        network["egress"] = agent_network["egress"]
        provenance["network.egress"] = [_source_path_join(source_prefix, "network", "egress")]

    package_install = agent.get("package_install") or (agent.get("runtime", {}) if isinstance(agent.get("runtime"), dict) else {}).get("package_install")
    if package_install is not None:
        normalized["package_install"] = package_install
        provenance["package_install"] = [
            _source_path_join(source_prefix, "package_install")
            if "package_install" in agent
            else _source_path_join(source_prefix, "runtime", "package_install")
        ]
    runtime = agent.get("runtime") if isinstance(agent.get("runtime"), dict) else {}
    if isinstance(runtime, dict) and "install_commands" in runtime:
        normalized["install_commands"] = runtime["install_commands"]
        provenance.update(_list_provenance("install_commands", _source_path_join(source_prefix, "runtime", "install_commands"), runtime["install_commands"]))

    for secret_key in ("secrets", "env"):
        secret_value = agent.get(secret_key) if isinstance(agent, dict) else None
        if secret_value:
            secrets.setdefault("env", True)
            provenance.setdefault("secrets.env", []).append(_source_path_join(source_prefix, secret_key))

    for mode_key in ("autonomy", "mode", "schedule"):
        if mode_key in agent:
            value = agent[mode_key]
            if mode_key == "schedule" or _text_contains_any(value, {"unattended", "autonomous", "auto"}):
                autonomy.setdefault("enabled", True)
                autonomy.setdefault("mode", "unattended")
                provenance.setdefault("autonomy", []).append(_source_path_join(source_prefix, mode_key))
    triggers = agent.get("triggers") if isinstance(agent.get("triggers"), dict) else {}
    if any(name in triggers for name in ("webhook", "http", "email", "slack", "discord")):
        inputs = dict(normalized.get("inputs", {})) if isinstance(normalized.get("inputs"), dict) else {}
        inputs.setdefault("webhook", True)
        normalized["inputs"] = inputs
        provenance.setdefault("inputs.webhook", []).append(_source_path_join(source_prefix, "triggers"))

    if tools:
        normalized["tools"] = tools
    if secrets:
        normalized["secrets"] = secrets
    if network:
        normalized["network"] = network
    if autonomy:
        normalized["autonomy"] = autonomy


def _merge_mcp_servers(servers, source_prefix, normalized, provenance):
    if not isinstance(servers, dict):
        return
    tools = dict(normalized.get("tools", {})) if isinstance(normalized.get("tools"), dict) else {}
    remote_sources = list(normalized.get("remote_tool_sources", [])) if isinstance(normalized.get("remote_tool_sources"), list) else []
    secrets = dict(normalized.get("secrets", {})) if isinstance(normalized.get("secrets"), dict) else {}
    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        server_prefix = _source_path_join(source_prefix, server_name)
        command = server.get("command") or server.get("url") or ""
        args = server.get("args", [])
        server_text = [server_name, command, *_as_list(args)]
        remote_sources.append({"source": command, "pinned": _pin_looks_stable(command)})
        provenance.setdefault(f"remote_tool_sources[{len(remote_sources) - 1}]", []).append(
            _source_path_join(server_prefix, "command") if "command" in server else _source_path_join(server_prefix, "url")
        )
        if _text_contains_any(server_text, {"shell", "terminal", "exec", "deploy"}):
            tools.setdefault("shell", {"enabled": True})
            provenance.setdefault("tools.shell", []).append(_source_path_join(server_prefix, "command"))
        if _text_contains_any(server_text, {"http", "browser", "webhook", "send"}):
            tools.setdefault("http", {"enabled": True})
            provenance.setdefault("tools.http", []).append(_source_path_join(server_prefix, "command"))
        if server.get("env"):
            secrets.setdefault("env", True)
            provenance.setdefault("secrets.env", []).append(_source_path_join(server_prefix, "env"))
    if remote_sources:
        normalized["remote_tool_sources"] = remote_sources
    if tools:
        normalized["tools"] = tools
    if secrets:
        normalized["secrets"] = secrets


def _normalize_editor_agent_config(config, adapter_key):
    normalized = deepcopy(config)
    provenance = {}
    root = normalized.get(adapter_key)
    if not isinstance(root, dict):
        return normalized, provenance
    agent = root.get("agent", root)
    if isinstance(agent, dict):
        _merge_agent_tools(agent, f"{adapter_key}.agent" if "agent" in root else adapter_key, normalized, provenance)
        _merge_mcp_servers(agent.get("mcpServers") or agent.get("mcp_servers"), f"{adapter_key}.agent.mcpServers", normalized, provenance)
    return normalized, provenance


def _normalize_langgraph_config(config):
    normalized = deepcopy(config)
    provenance = {}
    root = normalized.get("langgraph") or normalized.get("langchain")
    root_key = "langgraph" if isinstance(normalized.get("langgraph"), dict) else "langchain"
    if isinstance(root, dict):
        agent = root.get("deployment", root)
        _merge_agent_tools(agent, f"{root_key}.deployment" if "deployment" in root else root_key, normalized, provenance)
    return normalized, provenance


def _normalize_crewai_autogen_config(config, adapter_key):
    normalized = deepcopy(config)
    provenance = {}
    root = normalized.get(adapter_key)
    if not isinstance(root, dict):
        return normalized, provenance
    agent = root.get("crew") or root.get("group_chat") or root
    source_prefix = f"{adapter_key}.crew" if "crew" in root else f"{adapter_key}.group_chat" if "group_chat" in root else adapter_key
    _merge_agent_tools(agent, source_prefix, normalized, provenance)
    agents = agent.get("agents", []) if isinstance(agent, dict) else []
    if isinstance(agents, list):
        for index, child in enumerate(agents):
            if isinstance(child, dict):
                child_prefix = _source_path_join(source_prefix, "agents", index)
                _merge_agent_tools(child, child_prefix, normalized, provenance)
                _merge_mcp_servers(child.get("mcp_servers") or child.get("mcpServers"), _source_path_join(child_prefix, "mcp_servers"), normalized, provenance)
    return normalized, provenance


def normalize_config(config):
    """Return (adapter name, normalized config, evidence provenance) for known agent schema shapes."""
    if not isinstance(config, dict):
        return "generic", {}, {}
    for adapter_key in ("cursor", "windsurf"):
        if isinstance(config.get(adapter_key), dict):
            normalized, provenance = _normalize_editor_agent_config(config, adapter_key)
            return adapter_key, normalized, provenance
    if isinstance(config.get("langgraph"), dict) or isinstance(config.get("langchain"), dict):
        normalized, provenance = _normalize_langgraph_config(config)
        return "langgraph" if isinstance(config.get("langgraph"), dict) else "langchain", normalized, provenance
    for adapter_key in ("crewai", "autogen"):
        if isinstance(config.get(adapter_key), dict):
            normalized, provenance = _normalize_crewai_autogen_config(config, adapter_key)
            return adapter_key, normalized, provenance
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


def _path_has_any(path, fragments):
    lower_path = path.lower().replace("-", "_")
    return any(fragment in lower_path for fragment in fragments)


def _value_allows_unrestricted_egress(value):
    unrestricted = {"*", "any", "all", "unrestricted", "0.0.0.0/0", "::/0", "internet"}
    if isinstance(value, str):
        return value.strip().lower() in unrestricted
    if isinstance(value, list):
        return any(_value_allows_unrestricted_egress(item) for item in value)
    if isinstance(value, dict):
        if any(key in value for key in ("allow", "allowlist", "domains", "egress", "destinations")):
            return any(_value_allows_unrestricted_egress(value.get(key)) for key in ("allow", "allowlist", "domains", "egress", "destinations"))
        if "mode" in value and str(value.get("mode", "")).lower() in unrestricted:
            return True
    return False


def _unrestricted_network_egress_paths(config):
    paths = []
    for path, value in walk_items(config):
        if _path_has_any(path, {"network", "egress", "allowlist", "domains"}) and _value_allows_unrestricted_egress(value):
            paths.append(path)
    return sorted(set(paths))


def _runtime_package_install_paths(config):
    paths = []
    install_fragments = ("pip install", "npm install", "pnpm install", "yarn add", "uv add", "uv pip install")
    for path, value in walk_items(config):
        lower_value = str(value).lower()
        if _path_has_any(path, {"package_install", "install_commands", "dependencies_runtime"}) and is_enabled(value):
            paths.append(path)
        elif isinstance(value, str) and any(fragment in lower_value for fragment in install_fragments):
            paths.append(path)
    return sorted(set(paths))


def _unpinned_remote_tool_source_paths(config):
    paths = []
    for path, value in walk_items(config):
        if _path_has_any(path, {"remote_tool_sources", "mcpservers", "mcp_servers", "tool_sources"}):
            if isinstance(value, dict) and "pinned" in value and value.get("pinned") is False:
                paths.append(path)
            elif isinstance(value, str) and ("://" in value or "@" in value or value.startswith(("npx ", "uvx "))):
                if not _pin_looks_stable(value):
                    paths.append(path)
    return sorted(set(paths))


def _secret_env_to_dangerous_tool_paths(config):
    secret_paths = _secrets_or_credentials_access_paths(config)
    if not secret_paths:
        return []
    dangerous_paths = []
    dangerous_paths.extend(_tool_paths(config, {"shell", "exec", "terminal", "python", "node"}))
    dangerous_paths.extend(_tool_paths(config, {"mcp", "http", "browser"}))
    dangerous_paths.extend(_runtime_package_install_paths(config))
    dangerous_paths.extend(_network_egress_paths(config))
    if not dangerous_paths:
        return []
    return sorted(set(secret_paths + dangerous_paths))


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
        "unpinned_remote_tool_source_paths": _unpinned_remote_tool_source_paths,
        "runtime_package_install_paths": _runtime_package_install_paths,
        "unrestricted_network_egress_paths": _unrestricted_network_egress_paths,
        "secret_env_to_dangerous_tool_paths": _secret_env_to_dangerous_tool_paths,
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
    unpinned_remote_tool_source_paths = RULE_REGISTRY["unpinned_remote_tool_source"].collect_evidence(config, helpers)
    runtime_package_install_paths = RULE_REGISTRY["runtime_package_install"].collect_evidence(config, helpers)
    unrestricted_network_egress_paths = RULE_REGISTRY["unrestricted_network_egress"].collect_evidence(config, helpers)
    secret_env_to_dangerous_tool_paths = RULE_REGISTRY["secret_env_to_dangerous_tool"].collect_evidence(config, helpers)

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
    if unpinned_remote_tool_source_paths:
        capabilities.append("unpinned_remote_tool_source")
    if runtime_package_install_paths:
        capabilities.append("runtime_package_install")
    if unrestricted_network_egress_paths:
        capabilities.append("unrestricted_network_egress")
    if secret_env_to_dangerous_tool_paths:
        capabilities.append("secret_env_to_dangerous_tool")

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

    if unpinned_remote_tool_source_paths:
        add_finding("unpinned_remote_tool_source", unpinned_remote_tool_source_paths)

    if runtime_package_install_paths:
        add_finding("runtime_package_install", runtime_package_install_paths)

    if unrestricted_network_egress_paths:
        add_finding("unrestricted_network_egress", unrestricted_network_egress_paths)

    if secret_env_to_dangerous_tool_paths:
        add_finding("secret_env_to_dangerous_tool", secret_env_to_dangerous_tool_paths)

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
