"""Command-line interface for agent-config-linter."""

import argparse
import json
import sys
from pathlib import Path

from .linter import lint_config


def _load_json(path):
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def run(argv=None):
    parser = argparse.ArgumentParser(description="Lint autonomous-agent config files for risky capability combinations")
    parser.add_argument("paths", nargs="+", help="JSON config file paths")
    parser.add_argument("--format", choices=["json"], default="json")
    args = parser.parse_args(argv)

    result = {"schema_version": "0.1", "files": [], "errors": []}
    exit_code = 0

    for raw_path in args.paths:
        path = Path(raw_path)
        try:
            config = _load_json(path)
            report = lint_config(config)
            report["path"] = str(path)
            result["files"].append(report)
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(path), "message": str(exc)})
        except ValueError as exc:
            exit_code = 2
            result["errors"].append({"path": str(path), "message": str(exc)})

    return exit_code, json.dumps(result, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    exit_code, output = run(argv)
    stream = sys.stderr if exit_code else sys.stdout
    stream.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
