"""Detection unit tests: positive and negative cases for every Sigma rule.

Author: Chandu Komme

A test file in ``tests/detections/`` looks like this::

    rule: detection-rules/sigma/credential-access/T1110_brute_force.yml
    target: Repeated Windows Logon Failures from One Source   # optional
    cases:
      - name: ten failures from one source
        expect: match            # or: no_match
        events:
          - repeat: 10           # optional, default 1
            every: 5s            # optional spacing, default 1s
            start: 0s            # optional offset; default continues the timeline
            event: {EventID: 4625, IpAddress: 192.0.2.10, TargetUserName: "user{i}"}

``{i}`` inside any string is replaced with the 1-based repeat counter.
Every generated event receives an ``@timestamp`` unless it sets one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import sigma

__author__ = "Chandu Komme"

BASE_TIME = datetime(2026, 11, 17, 9, 0, 0, tzinfo=timezone.utc)


@dataclass
class CaseResult:
    test_file: Path
    rule_title: str
    case: str
    expected: str
    observed_matches: int

    @property
    def passed(self) -> bool:
        hit = self.observed_matches > 0
        return hit if self.expected == "match" else not hit


def _substitute(value: Any, counter: int) -> Any:
    if isinstance(value, str):
        return value.replace("{i}", str(counter))
    if isinstance(value, dict):
        return {key: _substitute(item, counter) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute(item, counter) for item in value]
    return value


def build_events(blocks: list[dict]) -> list[dict]:
    events: list[dict] = []
    cursor = BASE_TIME
    for block in blocks:
        if "event" not in block:
            raise ValueError(f"Event block {block!r} needs an 'event' key.")
        repeat = int(block.get("repeat", 1))
        spacing = sigma.parse_timespan(block.get("every", "1s"))
        if "start" in block:
            cursor = BASE_TIME + sigma.parse_timespan(block["start"])
        for counter in range(1, repeat + 1):
            event = _substitute(block["event"], counter)
            event.setdefault("@timestamp", cursor.isoformat())
            events.append(event)
            cursor += spacing
    return events


def run_test_file(path: str | Path, root: str | Path = ".") -> list[CaseResult]:
    path, root = Path(path), Path(root)
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    ruleset = sigma.load_file(root / spec["rule"])
    rule = ruleset.lookup(spec["target"]) if spec.get("target") else ruleset.primary()
    results = []
    for case in spec.get("cases") or []:
        expected = case.get("expect")
        if expected not in ("match", "no_match"):
            raise ValueError(f"{path}: case {case.get('name')!r} needs expect: match|no_match.")
        hits = sigma.evaluate(ruleset, rule, build_events(case.get("events") or []))
        results.append(CaseResult(path, rule.title, case.get("name", "unnamed"), expected, len(hits)))
    return results


def run_all(tests_dir: str | Path = "tests/detections", root: str | Path = ".") -> list[CaseResult]:
    results: list[CaseResult] = []
    for path in sorted(Path(root, tests_dir).glob("*.yml")):
        results.extend(run_test_file(path, root))
    return results


def tested_rules(tests_dir: str | Path = "tests/detections", root: str | Path = ".") -> dict[str, dict]:
    """Map each tested Sigma file to its count of positive and negative cases."""
    coverage: dict[str, dict] = {}
    for path in sorted(Path(root, tests_dir).glob("*.yml")):
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        entry = coverage.setdefault(str(Path(spec["rule"])), {"positive": 0, "negative": 0})
        for case in spec.get("cases") or []:
            entry["positive" if case.get("expect") == "match" else "negative"] += 1
    return coverage
