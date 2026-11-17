"""Quality gates for the detection catalog.

Author: Chandu Komme

Sigma checks: required metadata, valid and unique UUIDs, allowed status and
level values, ATT&CK tags, false-positive notes, parsable conditions,
resolvable correlation references, and at least one positive and one negative
unit test per file.

ElastAlert2 checks: the ``SOC-NNN | Txxxx | description`` naming convention,
unique SOC IDs, required keys, a filter, a realert window, and a query key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from uuid import UUID

import yaml

from . import sigma, testing

__author__ = "Chandu Komme"

ATTACK_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TACTIC_TAG = re.compile(r"^attack\.[a-z_]+$")
LIVE_NAME = re.compile(r"^(SOC-\d{3}) \| (T\d{4}(?:\.\d{3})?) \| \S.+$")
LIVE_REQUIRED = ("name", "type", "index", "timestamp_field", "filter", "alert", "realert", "query_key")


@dataclass
class Finding:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def lint_sigma(root: Path, sigma_dir: Path, tests_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen_ids: dict[str, str] = {}
    tested = testing.tested_rules(tests_dir, root)
    referenced = set()

    for path in sorted((root / sigma_dir).rglob("*.yml")):
        relative = str(path.relative_to(root))
        try:
            ruleset = sigma.load_file(path)
        except yaml.YAMLError as error:
            findings.append(Finding(relative, f"YAML error: {error}"))
            continue
        for rule in ruleset.rules:
            if rule.is_correlation:
                referenced.update((rule.data["correlation"].get("rules") or []))
        for rule in ruleset.rules:
            label = f"{relative} [{rule.title or 'untitled'}]"
            data = rule.data
            for key in ("title", "id", "status", "description", "author", "level"):
                if not data.get(key):
                    findings.append(Finding(label, f"missing '{key}'"))
            try:
                UUID(rule.id)
            except ValueError:
                findings.append(Finding(label, f"id {rule.id!r} is not a UUID"))
            if rule.id in seen_ids:
                findings.append(Finding(label, f"duplicate id also used in {seen_ids[rule.id]}"))
            seen_ids[rule.id] = relative
            if data.get("status") and data["status"] not in sigma.STATUSES:
                findings.append(Finding(label, f"status must be one of {sigma.STATUSES}"))
            if data.get("level") and data["level"] not in sigma.LEVELS:
                findings.append(Finding(label, f"level must be one of {sigma.LEVELS}"))

            is_building_block = bool(rule.name) and rule.name in referenced
            if not is_building_block:
                techniques = [tag for tag in rule.tags if ATTACK_TAG.match(tag)]
                if not techniques:
                    findings.append(Finding(label, "needs at least one attack.tNNNN tag"))
                if not data.get("falsepositives"):
                    findings.append(Finding(label, "needs falsepositives guidance"))
            for tag in rule.tags:
                if not (ATTACK_TAG.match(tag) or TACTIC_TAG.match(tag)):
                    findings.append(Finding(label, f"unexpected tag format {tag!r}"))

            if rule.is_correlation:
                spec = data["correlation"]
                if spec.get("type") not in sigma.CORRELATION_TYPES:
                    findings.append(Finding(label, f"correlation type must be one of {sigma.CORRELATION_TYPES}"))
                try:
                    sigma.parse_timespan(spec.get("timespan", ""))
                except sigma.SigmaError as error:
                    findings.append(Finding(label, str(error)))
                for reference in spec.get("rules") or []:
                    try:
                        ruleset.lookup(reference)
                    except sigma.SigmaError:
                        findings.append(Finding(label, f"correlation references unknown rule {reference!r}"))
            else:
                if not data.get("logsource"):
                    findings.append(Finding(label, "missing 'logsource'"))
                try:
                    sigma.compile_condition(data.get("detection") or {})
                except sigma.SigmaError as error:
                    findings.append(Finding(label, f"condition: {error}"))

        coverage = tested.get(relative)
        if not coverage:
            findings.append(Finding(relative, "has no unit test in tests/detections/"))
        else:
            if coverage["positive"] < 1:
                findings.append(Finding(relative, "needs at least one 'expect: match' test case"))
            if coverage["negative"] < 1:
                findings.append(Finding(relative, "needs at least one 'expect: no_match' test case"))
    return findings


def lint_live(root: Path, rules_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[str, str] = {}
    for path in sorted((root / rules_dir).glob("*.y*ml")):
        relative = str(path.relative_to(root))
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as error:
            findings.append(Finding(relative, f"YAML error: {error}"))
            continue
        for key in LIVE_REQUIRED:
            if key not in data:
                findings.append(Finding(relative, f"missing '{key}'"))
        match = LIVE_NAME.match(str(data.get("name", "")))
        if not match:
            findings.append(Finding(relative, "name must follow 'SOC-NNN | Txxxx[.xxx] | description'"))
            continue
        soc_id = match.group(1)
        if soc_id in seen:
            findings.append(Finding(relative, f"{soc_id} already used by {seen[soc_id]}"))
        seen[soc_id] = relative
        source = re.search(r"^# Sigma source: (\S+)", path.read_text(encoding="utf-8"), re.M)
        if not source:
            findings.append(Finding(relative, "add a '# Sigma source: <path>' comment linking the reference rule"))
        elif not (root / source.group(1)).is_file():
            findings.append(Finding(relative, f"Sigma source {source.group(1)} does not exist"))
        if not data.get("include_match_in_root"):
            findings.append(Finding(relative, "set include_match_in_root: true so alerts link to evidence"))
    return findings


def live_rules(root: Path, rules_dir: Path) -> list[dict]:
    """Parsed live rules with their SOC ID and technique."""
    rules = []
    for path in sorted((root / rules_dir).glob("*.y*ml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        match = LIVE_NAME.match(str(data.get("name", "")))
        if match:
            rules.append({"soc_id": match.group(1), "technique": match.group(2),
                          "name": data["name"], "type": data.get("type"),
                          "path": str(path.relative_to(root))})
    return rules
