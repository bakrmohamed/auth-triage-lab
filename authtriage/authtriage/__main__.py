"""Command-line entry point: python -m authtriage."""
import argparse
import json
from pathlib import Path
import sys

from .core import Config, analyze, read_events
from .report import markdown


def main(argv=None):
    parser = argparse.ArgumentParser(description="Triage normalized authentication JSONL offline.")
    parser.add_argument("input", help="UTF-8 JSONL path, or - for stdin")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", default="-", help="New output path, or - for stdout (default). Existing files are never overwritten.")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--failure-threshold", type=int, default=5)
    parser.add_argument("--spray-users", type=int, default=5)
    parser.add_argument("--max-lines", type=int, default=200000)
    parser.add_argument("--strict", action="store_true", help="Still produce a report, but return 2 if any records were rejected")
    args = parser.parse_args(argv)
    try:
        config = Config(args.window_seconds, args.failure_threshold, args.spray_users, args.max_lines)
        if args.input == "-":
            events, issues, lines = read_events(sys.stdin, config)
        else:
            with open(args.input, encoding="utf-8") as stream:
                events, issues, lines = read_events(stream, config)
        report = analyze(events, config, issues, lines)
        rendered = (json.dumps(report, indent=2, ensure_ascii=True) + "\n"
                    if args.format == "json" else markdown(report))
        if args.output == "-":
            sys.stdout.write(rendered)
        else:
            # Exclusive creation also prevents an accidental input-file overwrite.
            with Path(args.output).open("x", encoding="utf-8", newline="\n") as target:
                target.write(rendered)
        return 2 if args.strict and issues else 0
    except (OSError, ValueError, UnicodeError) as exc:
        # Avoid reflecting arbitrary file content or terminal control characters.
        print(f"authtriage: {type(exc).__name__}. Check paths, UTF-8 input, limits and configuration.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
