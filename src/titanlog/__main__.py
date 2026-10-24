"""CLI: python -m titanlog triage <file.jsonl>."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from titanlog import triage
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="titanlog")
    commands = parser.add_subparsers(dest="command", required=True)
    triage_cmd = commands.add_parser("triage", help="Triage one JSONL file and print the incident JSON")
    triage_cmd.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    path: Path = args.file
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        return 1
    try:
        events, _report = OtrfSysmonAdapter().to_events(path)
    except OSError as exc:
        print(f"Could not read {path}: {exc}", file=sys.stderr)
        return 1
    print(triage(events).model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
