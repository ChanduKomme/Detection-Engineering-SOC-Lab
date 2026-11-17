"""Offline evaluator for the Sigma subset used in this lab.

Author: Chandu Komme

Supported features
------------------
* Detection maps (AND across fields), value lists (OR), lists of maps (OR),
  and keyword lists (free-text search across all string values).
* Field modifiers: contains, startswith, endswith, all, re, cidr,
  gt, gte, lt, lte, exists.
* Conditions: and, or, not, parentheses, ``1 of x*``, ``all of x*``,
  ``1 of them`` and ``all of them``.
* Correlation rules: event_count, value_count, temporal and
  temporal_ordered, including correlations that reference other
  correlations (chaining).

String comparisons are case-insensitive, as in the Sigma specification.
Regular expressions are case-sensitive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from ipaddress import ip_address, ip_network
from pathlib import Path
import re
from typing import Any, Iterable

import yaml

__author__ = "Chandu Komme"

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
CORRELATION_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class SigmaError(ValueError):
    """Raised when a rule uses syntax this evaluator does not support."""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

@dataclass
class Rule:
    """One Sigma document (a detection rule or a correlation rule)."""

    data: dict
    path: Path | None = None

    @property
    def title(self) -> str:
        return self.data.get("title", "")

    @property
    def id(self) -> str:
        return str(self.data.get("id", ""))

    @property
    def name(self) -> str | None:
        return self.data.get("name")

    @property
    def is_correlation(self) -> bool:
        return "correlation" in self.data

    @property
    def tags(self) -> list[str]:
        return list(self.data.get("tags") or [])


@dataclass
class RuleSet:
    """All documents of one Sigma file, addressable by name, id or title."""

    rules: list[Rule] = field(default_factory=list)

    def lookup(self, reference: str) -> Rule:
        for rule in self.rules:
            if reference in (rule.name, rule.id, rule.title):
                return rule
        raise SigmaError(f"Unknown rule reference {reference!r}.")

    def primary(self) -> Rule:
        """The rule an analyst would deploy: the last correlation, else the only rule."""
        correlations = [rule for rule in self.rules if rule.is_correlation]
        if correlations:
            return correlations[-1]
        return self.rules[-1]


def load_file(path: str | Path) -> RuleSet:
    path = Path(path)
    with path.open(encoding="utf-8") as handle:
        documents = [doc for doc in yaml.safe_load_all(handle) if doc]
    return RuleSet([Rule(doc, path) for doc in documents])


def parse_timespan(value: str) -> timedelta:
    match = TIMESPAN.match(str(value))
    if not match:
        raise SigmaError(f"Unsupported timespan {value!r}; use forms like 30s, 5m, 1h.")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


# --------------------------------------------------------------------------
# Field matching
# --------------------------------------------------------------------------

_MISSING = object()


def get_field(event: dict, name: str) -> Any:
    """Return a field by exact key first, then by dotted path."""
    if name in event:
        return event[name]
    current: Any = event
    for part in name.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _match_one(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if expected is None:
        return actual is None or actual is _MISSING
    if actual is _MISSING or actual is None:
        return False
    if "re" in modifiers:
        return re.search(str(expected), _as_text(actual)) is not None
    if "cidr" in modifiers:
        try:
            return ip_address(_as_text(actual)) in ip_network(str(expected), strict=False)
        except ValueError:
            return False
    comparisons = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}
    for name, operator in comparisons.items():
        if name in modifiers:
            left, right = _to_number(actual), _to_number(expected)
            return left is not None and right is not None and operator(left, right)
    if isinstance(expected, bool) or isinstance(actual, bool):
        return _as_text(actual).lower() == _as_text(expected).lower()
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        number = _to_number(actual)
        return number is not None and number == float(expected)

    text, pattern = _as_text(actual).lower(), str(expected).lower()
    if "contains" in modifiers:
        return pattern in text
    if "startswith" in modifiers:
        return text.startswith(pattern)
    if "endswith" in modifiers:
        return text.endswith(pattern)
    if "*" in pattern or "?" in pattern:
        return fnmatchcase(text, pattern)
    return text == pattern


KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "all", "re",
                   "cidr", "gt", "gte", "lt", "lte", "exists"}


def match_field(event: dict, key: str, expected: Any) -> bool:
    name, *modifiers = key.split("|")
    unknown = set(modifiers) - KNOWN_MODIFIERS
    if unknown:
        raise SigmaError(f"Unsupported modifier(s) {sorted(unknown)} on {key!r}.")
    actual = get_field(event, name)
    if "exists" in modifiers:
        return (actual is not _MISSING) == bool(expected)
    values = expected if isinstance(expected, list) else [expected]
    actual_values = actual if isinstance(actual, list) else [actual]
    combine = all if "all" in modifiers else any
    return combine(
        any(_match_one(item, value, modifiers) for item in actual_values) for value in values
    )


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)
    elif value is not None:
        yield _as_text(value)


def match_search(event: dict, search: Any) -> bool:
    """Evaluate one named search identifier from the ``detection`` block."""
    if isinstance(search, dict):
        return all(match_field(event, key, value) for key, value in search.items())
    if isinstance(search, list):
        if all(isinstance(item, dict) for item in search):
            return any(match_search(event, item) for item in search)
        texts = [text.lower() for text in _iter_strings(event)]
        return any(str(keyword).lower() in text for keyword in search for text in texts)
    raise SigmaError(f"Unsupported search definition {search!r}.")


# --------------------------------------------------------------------------
# Condition parsing
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens, position = [], 0
    condition = condition.strip()
    while position < len(condition):
        match = _TOKEN.match(condition, position)
        if not match:
            raise SigmaError(f"Cannot parse condition near {condition[position:]!r}.")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class _ConditionParser:
    """Recursive-descent parser: or < and < not < primary."""

    def __init__(self, condition: str, searches: dict):
        self.tokens = _tokenize(condition)
        self.searches = searches
        self.index = 0

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise SigmaError("Unexpected end of condition.")
        self.index += 1
        return token

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise SigmaError(f"Unexpected token {self.peek()!r} in condition.")
        return node

    def parse_or(self):
        nodes = [self.parse_and()]
        while (self.peek() or "").lower() == "or":
            self.take()
            nodes.append(self.parse_and())
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    def parse_and(self):
        nodes = [self.parse_not()]
        while (self.peek() or "").lower() == "and":
            self.take()
            nodes.append(self.parse_not())
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def parse_not(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        token = self.take()
        if token == "(":
            node = self.parse_or()
            if self.take() != ")":
                raise SigmaError("Missing closing parenthesis in condition.")
            return node
        if token.lower() in ("1", "all") and (self.peek() or "").lower() == "of":
            self.take()
            pattern = self.take()
            names = [name for name in self.searches
                     if pattern.lower() == "them" or fnmatchcase(name, pattern)]
            if not names:
                raise SigmaError(f"No search identifiers match {pattern!r}.")
            return ("or" if token == "1" else "and", [("search", name) for name in names])
        if token not in self.searches:
            raise SigmaError(f"Condition references unknown search {token!r}.")
        return ("search", token)


def _evaluate(node, event: dict, searches: dict) -> bool:
    kind, value = node
    if kind == "search":
        return match_search(event, searches[value])
    if kind == "not":
        return not _evaluate(value, event, searches)
    if kind == "and":
        return all(_evaluate(child, event, searches) for child in value)
    return any(_evaluate(child, event, searches) for child in value)


def compile_condition(detection: dict):
    searches = {key: value for key, value in detection.items() if key != "condition"}
    conditions = detection.get("condition")
    if conditions is None:
        raise SigmaError("Detection block has no condition.")
    if isinstance(conditions, str):
        conditions = [conditions]
    trees = [_ConditionParser(condition, searches).parse() for condition in conditions]
    return searches, trees


def matches(rule: Rule, event: dict) -> bool:
    """True when a single-event detection rule matches the event."""
    if rule.is_correlation:
        raise SigmaError(f"{rule.title!r} is a correlation rule; use evaluate().")
    searches, trees = compile_condition(rule.data["detection"])
    return any(_evaluate(tree, event, searches) for tree in trees)


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------

@dataclass
class Match:
    """A rule hit: the time it fired, its group key, and the supporting events."""

    rule: str
    time: datetime
    group: tuple
    events: list[dict]


def event_time(event: dict) -> datetime:
    raw = get_field(event, "@timestamp")
    if raw is _MISSING:
        raw = get_field(event, "timestamp")
    if raw is _MISSING:
        raise SigmaError("Correlation input events need an @timestamp field.")
    if isinstance(raw, datetime):
        stamp = raw
    elif isinstance(raw, (int, float)):
        stamp = datetime.fromtimestamp(raw, timezone.utc)
    else:
        stamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def _group_key(event: dict, group_by: list[str]) -> tuple:
    return tuple(_as_text(get_field(event, name)) for name in group_by)


def _check(condition: dict, value: float) -> bool:
    tests = {"gt": value.__gt__, "gte": value.__ge__, "lt": value.__lt__,
             "lte": value.__le__, "eq": value.__eq__}
    present = [key for key in condition if key in tests]
    if not present:
        raise SigmaError(f"Correlation condition {condition!r} has no comparison.")
    return all(tests[key](condition[key]) for key in present)


def evaluate(ruleset: RuleSet, rule: Rule, events: list[dict]) -> list[Match]:
    """Evaluate any rule (single-event or correlation) over an event list."""
    if not rule.is_correlation:
        return [Match(rule.title, event_time(event) if _has_time(event) else _EPOCH,
                      (), [event]) for event in events if matches(rule, event)]

    spec = rule.data["correlation"]
    kind = spec.get("type")
    if kind not in CORRELATION_TYPES:
        raise SigmaError(f"Unsupported correlation type {kind!r}.")
    group_by = list(spec.get("group-by") or [])
    window = parse_timespan(spec.get("timespan", "0s"))
    references = spec.get("rules") or []
    if not references:
        raise SigmaError(f"Correlation {rule.title!r} lists no rules.")

    hits: list[tuple[str, Match]] = []
    for reference in references:
        for match in evaluate(ruleset, ruleset.lookup(reference), events):
            hits.append((reference, match))
    hits.sort(key=lambda item: item[1].time)

    def key_of(match: Match) -> tuple:
        source = match.events[-1] if match.events else {}
        if match.group and len(match.group) == len(group_by):
            return match.group
        return _group_key(source, group_by)

    grouped: dict[tuple, list[tuple[str, Match]]] = {}
    for reference, match in hits:
        grouped.setdefault(key_of(match), []).append((reference, match))

    results: list[Match] = []
    for group, items in grouped.items():
        last_fire: datetime | None = None
        for position, (_, current) in enumerate(items):
            if last_fire is not None and current.time - last_fire < window:
                continue  # suppress duplicate hits inside one window
            start = current.time - window
            in_window = [(ref, m) for ref, m in items[: position + 1] if m.time >= start]
            if _correlation_fires(kind, spec, references, in_window):
                supporting = [event for _, m in in_window for event in m.events]
                results.append(Match(rule.title, current.time, group, supporting))
                last_fire = current.time
    results.sort(key=lambda m: m.time)
    return results


def _correlation_fires(kind, spec, references, window_items) -> bool:
    condition = spec.get("condition") or {}
    if kind == "event_count":
        return _check(condition, float(len(window_items)))
    if kind == "value_count":
        field_name = condition.get("field")
        if not field_name:
            raise SigmaError("value_count correlations need condition.field.")
        values = {_as_text(get_field(event, field_name))
                  for _, match in window_items for event in match.events
                  if get_field(event, field_name) is not _MISSING}
        return _check({k: v for k, v in condition.items() if k != "field"}, float(len(values)))
    if kind == "temporal":
        return {ref for ref, _ in window_items} >= set(references)
    # temporal_ordered: each reference must appear after the previous one.
    position = 0
    for ref, _ in window_items:
        if ref == references[position]:
            position += 1
            if position == len(references):
                return True
    return False


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _has_time(event: dict) -> bool:
    return get_field(event, "@timestamp") is not _MISSING or get_field(event, "timestamp") is not _MISSING


def catalog(root: str | Path) -> list[RuleSet]:
    return [load_file(path) for path in sorted(Path(root).rglob("*.yml"))]
