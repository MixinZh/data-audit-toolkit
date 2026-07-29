from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .benchmark import run_benchmark
from .engine import scan_paths
from .models import DEFAULT_LIMITS, ScanLimits
from .output import (
    OutputExistsError,
    OutputInputConflictError,
    OutputPathError,
    OutputWriteError,
    _protected_input_snapshot,
    existing_regular_file_identities,
    prepare_output_target,
    validate_output_target,
    write_report_atomic_to_target,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="data-audit",
        description="Scan local files for reproducible consistency leads.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan local files and directories.",
    )
    scan_parser.add_argument("inputs", nargs="+", metavar="INPUT")
    scan_parser.add_argument("--output", required=True, metavar="REPORT")
    scan_parser.add_argument("--overwrite", action="store_true")
    scan_parser.add_argument("--min-n", type=int, default=DEFAULT_LIMITS.min_n)
    scan_parser.add_argument(
        "--min-group-n",
        type=int,
        default=DEFAULT_LIMITS.min_group_n,
    )
    scan_parser.add_argument(
        "--min-sequence",
        type=int,
        default=DEFAULT_LIMITS.min_sequence,
    )
    scan_parser.add_argument(
        "--max-sequence-values",
        type=int,
        default=DEFAULT_LIMITS.max_sequence_values,
    )
    scan_parser.add_argument(
        "--max-pair-rows",
        type=int,
        default=DEFAULT_LIMITS.max_pair_rows,
    )
    scan_parser.add_argument(
        "--tile-size",
        type=int,
        default=DEFAULT_LIMITS.tile_size,
    )

    subparsers.add_parser(
        "benchmark",
        help="Run the packaged deterministic benchmark.",
    )
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    limits = ScanLimits(
        min_n=args.min_n,
        min_group_n=args.min_group_n,
        min_sequence=args.min_sequence,
        max_sequence_values=args.max_sequence_values,
        max_pair_rows=args.max_pair_rows,
        tile_size=args.tile_size,
    )
    explicit_identities = existing_regular_file_identities(args.inputs)
    explicit_paths = _protected_input_snapshot(args.inputs, args.output)
    with prepare_output_target(args.output) as output_target:
        validate_output_target(
            output_target,
            overwrite=args.overwrite,
            protected_identities=explicit_identities,
            protected_paths=explicit_paths,
        )
        report = scan_paths(
            args.inputs,
            limits=limits,
            excluded_paths=output_target.excluded_paths,
        )
        write_report_atomic_to_target(
            report,
            output_target,
            overwrite=args.overwrite,
            protected_identities=explicit_identities,
            protected_paths=explicit_paths,
        )

    print(f"Files inventoried: {len(report['inventory'])}")
    print(f"Files checked: {len(report['scanned_files'])}")
    consistency_leads = sum(
        finding.get("classification") == "consistency_lead"
        for finding in report["findings"]
    )
    print(f"Consistency leads: {consistency_leads}")
    print(f"Not checked: {len(report['not_checked'])}")
    print(f"Report: {args.output}")
    print("Review the report before drawing conclusions.")
    return 0


def _run_benchmark() -> int:
    print(
        json.dumps(
            run_benchmark(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        return _run_benchmark()
    except (
        OutputExistsError,
        OutputInputConflictError,
        OutputPathError,
        OutputWriteError,
    ) as exc:
        print(f"data-audit: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("data-audit: operation failed", file=sys.stderr)
        return 1
