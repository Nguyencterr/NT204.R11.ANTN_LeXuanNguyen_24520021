"""Command line entry point for the Assignment 3 Rule Loader.

Examples::

    python -m core_engine.rule_loader --config rules/rule_loader.json --stats
    python -m core_engine.rule_loader --rules rules/web.rules --list

Exit codes:

* ``0`` - loading finished without error diagnostics
* ``1`` - loading finished but at least one file/candidate failed
* ``2`` - the configuration itself is unusable (nothing was loaded)
"""

import argparse
import logging
import sys
from pathlib import Path

from common.jsonl import JsonlWriter, reset_file

from .config import RuleFileConfig, RuleLoaderConfig, RuleLoaderConfigError
from .loader import RuleLoader


DEFAULT_CONFIG = "rules/rule_loader.json"

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def build_parser() -> argparse.ArgumentParser:
    """Build the loader CLI parser."""

    parser = argparse.ArgumentParser(
        prog="python -m core_engine.rule_loader",
        description=(
            "Load Snort-style .rules files into rule candidates "
            "(Assignment 3, section 4.1 Rule Loader)."
        ),
    )

    parser.add_argument(
        "--config",
        default=None,
        help=(
            "JSON loader configuration "
            f"(default: {DEFAULT_CONFIG})"
        ),
    )

    parser.add_argument(
        "--rules",
        action="append",
        metavar="PATH",
        help=(
            "rule file to load; repeatable. When given it replaces the "
            "rule_files list from --config"
        ),
    )

    parser.add_argument(
        "--base-dir",
        default=None,
        help=(
            "base directory for relative rule paths "
            "(default: configuration file directory, else current directory)"
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
        help="write the emitted candidates as JSON Lines to this path",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="print every emitted candidate (rule_ref and raw text)",
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help="print loader statistics (always printed when --list is absent)",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=LOG_LEVELS,
        help="level for loader diagnostics (default: %(default)s)",
    )

    return parser


def build_config(args: argparse.Namespace) -> RuleLoaderConfig:
    """Turn parsed CLI arguments into a loader configuration."""

    base_dir = Path(args.base_dir) if args.base_dir else None

    if args.rules:

        return RuleLoaderConfig(
            rule_files=[
                RuleFileConfig(path=path)
                for path in args.rules
            ],
            base_dir=(
                base_dir
                if base_dir is not None
                else Path.cwd()
            ),
        )

    config_path = Path(args.config) if args.config else Path(DEFAULT_CONFIG)

    return RuleLoaderConfig.from_json_file(
        config_path,
        base_dir=base_dir,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the loader CLI and return its exit code."""

    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:

        config = build_config(args)

    except RuleLoaderConfigError as exc:

        print(f"error: {exc}", file=sys.stderr)

        return 2

    result = RuleLoader(config).load()

    if args.output:

        output = Path(args.output)

        reset_file(output)

        with JsonlWriter(output) as writer:

            for candidate in result.rules:

                writer.write(candidate.to_dict())

        print(
            f"candidates written: {output} "
            f"({len(result.rules)} line(s))"
        )

    if args.list:

        print(f"candidates ({len(result.rules)}):")

        for candidate in result.rules:

            print(f"  {candidate.rule_ref}\t{candidate.raw_text}")

    if args.stats or not args.list:

        print("statistics:")

        for key, value in result.statistics.to_dict().items():

            print(f"  {key}: {value}")

    return 1 if result.has_errors else 0


if __name__ == "__main__":

    sys.exit(main())
