from __future__ import annotations

import argparse
from pathlib import Path

from .report import write_report
from .verify import verify_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m keyrotate.cli",
        description="Normalize key registries and evaluate signature states.",
    )
    parser.add_argument("--keys", required=True, type=Path)
    parser.add_argument("--signatures", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = verify_files(args.keys, args.signatures)
    write_report(report, args.out)

    by_state = report["summary"]["by_state"]
    state_summary = " ".join(f"{state}={by_state[state]}" for state in sorted(by_state))
    print(
        f"signatures={report['summary']['signatures']} "
        f"verified={report['summary']['verified']} {state_summary}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
