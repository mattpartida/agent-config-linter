# Examples gallery

The examples gallery points users at realistic configurations and policy bundles. Each entry is labeled as `safe`, `risky`, or `intentionally-vulnerable` and has an Expected result so downstream users know whether a finding is desired.

The machine-readable index lives at [`examples/gallery.json`](../examples/gallery.json). Tests load the index and smoke-lint every config entry so gallery drift is caught before release.

| Stack | Label | Path | Expected result |
| --- | --- | --- | --- |
| Local coding agent | safe | `examples/config-shapes/hermes-personal-local.yaml` | Should avoid high/critical findings for guarded local development. |
| CI agent | risky | `examples/config-shapes/github-actions-agent-risky.yml` | Should demonstrate risky CI automation and stable `ACL-*` rule IDs. |
| MCP desktop config | risky | `examples/config-shapes/claude-desktop-risky-mcp.json` | Should demonstrate shell-like MCP tool exposure with secret environment context. |
| Editor agent | safe | `examples/config-shapes/cursor-safe-agent-settings.json` | Should show an editor-agent profile that remains scoped and approval-oriented. |
| Framework deployment | risky | `examples/config-shapes/langgraph-risky-deployment.yaml` | Should demonstrate framework agent risks from dangerous tools, weak gates, or broad egress. |
| Organization policy bundle | safe | `examples/policies/staged-ci.yaml` | Should demonstrate staged enforcement without changing built-in rule semantics. |
| Intentionally vulnerable demo | intentionally-vulnerable | `examples/high-risk-agent.json` | Should trigger the full high-risk demo corpus and is meant for docs/tests only. |

## Usage

```bash
agent-config-lint examples/config-shapes/hermes-personal-local.yaml --format json
agent-config-lint examples/config-shapes/langgraph-risky-deployment.yaml --format markdown
agent-config-lint examples/high-risk-agent.json --format sarif > agent-config-linter.sarif
```

Treat risky and intentionally-vulnerable examples as fixtures, not deployment templates. Do not copy secrets, broad filesystem roots, unrestricted egress, or unattended tool-use patterns into production configs.
