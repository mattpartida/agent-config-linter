# Baseline review workflows

Baselines suppress accepted findings without hiding them from machine-readable output. Review them regularly so accepted risk keeps a current owner, ticket, and expiration date.

## Owner review

Run this during security review or before a release to inspect suppressions grouped by owner and expiration status:

```bash
agent-config-lint configs/ --baseline agent-config-linter-baseline.json --format json
```

The JSON `baseline.owner_summary` object groups suppressions by `owner` with `active`, `expired`, `stale`, and `total` counts. `baseline.expired_suppressions` lists entries whose `expires_at` date has passed. `baseline.stale_suppressions` lists unexpired entries that no longer match any active finding and can usually be deleted.

## Expiration gate

Use this gate when expired accepted-risk entries should fail CI, but stale cleanup should remain informational:

```bash
agent-config-lint configs/ --baseline agent-config-linter-baseline.json --fail-on-expired-baseline --format json
```

## Cleanup gate

Use this stricter scheduled job to fail on both expired suppressions and stale suppressions:

```bash
agent-config-lint configs/ --baseline agent-config-linter-baseline.json --fail-on-expired-baseline --fail-on-stale-baseline --format json
```

The example workflow in `examples/github-actions/baseline-cleanup.yml` runs the cleanup gate on a weekly schedule.
