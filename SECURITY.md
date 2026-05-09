# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately by opening a GitHub security advisory for this repository or by emailing the maintainer listed in `pyproject.toml`.

Include:

- A concise description of the vulnerability and impact.
- A minimal reproduction or affected config/report example when possible.
- Whether the issue affects CLI execution, report output, policy/baseline suppression, package distribution, or GitHub Actions examples.

Do not include live secrets, tokens, credentials, or customer data in reports. Redact sensitive values and keep only the field names or paths required to reproduce the issue.

## Supported versions

Until the first stable release, security fixes target the latest `main` branch and the most recent published package version, if any.

## Disclosure expectations

The project aims to acknowledge vulnerability reports within 5 business days and coordinate public disclosure after a fix or documented mitigation is available.
