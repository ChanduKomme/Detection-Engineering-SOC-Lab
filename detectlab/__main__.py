"""Command-line entry point: ``python -m detectlab <command>``.

Author: Chandu Komme

Commands
--------
lint       Check Sigma and ElastAlert2 rules against the catalog conventions.
test       Run every detection unit test in tests/detections/.
coverage   Regenerate the ATT&CK coverage table and Navigator layer
           (``--check`` fails when the committed files are stale).
eval       Evaluate one Sigma file against an NDJSON or JSON event file.
all        lint + test + coverage --check (the CI gate).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__, coverage, lint, sigma, testing

__author__ = "Chandu Komme"

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = Path("detection-rules/sigma")
TESTS_DIR = Path("tests/detections")
LIVE_DIR = Path("config/elastalert2/rules")


def cmd_lint(_args) -> int:
    findings = lint.lint_sigma(ROOT, SIGMA_DIR, TESTS_DIR) + lint.lint_live(ROOT, LIVE_DIR)
    for finding in findings:
        print(f"LINT  {finding}")
    sigma_files = len(list((ROOT / SIGMA_DIR).rglob("*.yml")))
    live_files = len(list((ROOT / LIVE_DIR).glob("*.y*ml")))
    print(f"lint: {sigma_files} Sigma files, {live_files} live rules, {len(findings)} finding(s)")
    return 1 if findings else 0


def cmd_test(args) -> int:
    results = testing.run_all(TESTS_DIR, ROOT)
    failures = [r for r in results if not r.passed]
    for result in results:
        if args.verbose or not result.passed:
            mark = "PASS" if result.passed else "FAIL"
            print(f"{mark}  {result.test_file.name}: {result.case} "
                  f"(expected {result.expected}, {result.observed_matches} match(es))")
    print(f"test: {len(results)} case(s), {len(results) - len(failures)} passed, {len(failures)} failed")
    return 1 if failures or not results else 0


def cmd_coverage(args) -> int:
    outputs = coverage.render(ROOT, SIGMA_DIR, TESTS_DIR, LIVE_DIR)
    stale = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != content:
            stale.append(path.relative_to(ROOT))
            if not args.check:
                path.write_text(content, encoding="utf-8")
    if args.check:
        for path in stale:
            print(f"STALE {path} - run: python -m detectlab coverage")
        print(f"coverage: {'up to date' if not stale else f'{len(stale)} stale file(s)'}")
        return 1 if stale else 0
    print(f"coverage: wrote {len(stale)} file(s)" if stale else "coverage: already up to date")
    return 0


def _read_events(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def cmd_eval(args) -> int:
    ruleset = sigma.load_file(args.rule)
    rule = ruleset.lookup(args.target) if args.target else ruleset.primary()
    hits = sigma.evaluate(ruleset, rule, _read_events(args.events))
    for hit in hits:
        print(json.dumps({"rule": hit.rule, "time": hit.time.isoformat(),
                          "group": list(hit.group), "events": len(hit.events)}))
    print(f"eval: {rule.title!r} matched {len(hits)} time(s)", file=sys.stderr)
    return 0


def cmd_all(args) -> int:
    status = 0
    for command in (cmd_lint, cmd_test):
        status |= command(args)
    args.check = True
    status |= cmd_coverage(args)
    return status


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="detectlab", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"detectlab {__version__} by Chandu Komme")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("lint").set_defaults(func=cmd_lint)
    test = sub.add_parser("test")
    test.add_argument("-v", "--verbose", action="store_true")
    test.set_defaults(func=cmd_test)
    cov = sub.add_parser("coverage")
    cov.add_argument("--check", action="store_true")
    cov.set_defaults(func=cmd_coverage)
    ev = sub.add_parser("eval")
    ev.add_argument("rule", type=Path)
    ev.add_argument("events", type=Path)
    ev.add_argument("--target", help="Rule title, name or id inside a multi-document file.")
    ev.set_defaults(func=cmd_eval)
    everything = sub.add_parser("all")
    everything.add_argument("-v", "--verbose", action="store_true")
    everything.set_defaults(func=cmd_all, check=True)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
