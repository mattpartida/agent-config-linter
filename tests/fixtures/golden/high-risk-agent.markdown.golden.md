# Agent Config Linter Report

## high-risk-agent.json

- Risk level: **critical**
- Score: **130**
- Lethal trifecta: **true**

| Rule | Severity | Finding | Title |
| --- | --- | --- | --- |
| ACL-001 | high | shell_enabled | Shell execution is enabled |
| ACL-002 | high | filesystem_broad_access | Broad filesystem access |
| ACL-003 | high | browser_private_network | Browser can reach private network |
| ACL-004 | critical | lethal_trifecta | Lethal trifecta present |
| ACL-008 | critical | approval_gate_missing | Approval gate disabled for dangerous action |
| ACL-009 | medium | weak_model_risk | Model may be weaker against prompt injection |
