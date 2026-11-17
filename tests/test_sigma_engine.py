"""Unit tests for the offline Sigma evaluator. Author: Chandu Komme"""
import textwrap

import pytest

from detectlab import sigma, testing


def ruleset(text):
    import yaml
    return sigma.RuleSet([sigma.Rule(doc) for doc in yaml.safe_load_all(textwrap.dedent(text)) if doc])


def single(detection):
    return sigma.Rule({"title": "t", "detection": detection})


@pytest.mark.parametrize("key,expected,value,result", [
    ("Image|endswith", "\\cmd.exe", "C:\\Windows\\CMD.EXE", True),
    ("Image|startswith", "c:\\windows", "C:\\Windows\\cmd.exe", True),
    ("CommandLine|contains", "-enc", "x -ENC y", True),
    ("CommandLine|contains|all", ["a", "b"], "a only", False),
    ("CommandLine|contains|all", ["a", "b"], "a and b", True),
    ("query|re", "^.{5,}$", "abcd", False),
    ("bytes|gte", 10, 10, True),
    ("bytes|gt", 10, 10, False),
    ("bytes|lt", 10, "9", True),
    ("ip|cidr", "10.0.0.0/8", "10.2.3.4", True),
    ("ip|cidr", "10.0.0.0/8", "192.0.2.1", False),
    ("Name", "svc*", "SVC-backup", True),
    ("EventID", 4625, "4625", True),
    ("EventID", [4624, 4625], 4624, True),
    ("Flag", True, "true", True),
])
def test_modifiers(key, expected, value, result):
    field = key.split("|")[0]
    assert sigma.matches(single({"s": {key: expected}, "condition": "s"}), {field: value}) is result


def test_exists_and_dotted_fields():
    rule = single({"s": {"alert.severity|lte": 2, "uid|exists": False}, "condition": "s"})
    assert sigma.matches(rule, {"alert": {"severity": 1}})
    assert not sigma.matches(rule, {"alert": {"severity": 1}, "uid": "x"})
    assert not sigma.matches(rule, {"alert": {"severity": 3}})


def test_missing_field_never_matches():
    assert not sigma.matches(single({"s": {"Image|endswith": ".exe"}, "condition": "s"}), {})


def test_unknown_modifier_is_rejected():
    with pytest.raises(sigma.SigmaError):
        sigma.matches(single({"s": {"x|base64offset": "a"}, "condition": "s"}), {"x": "a"})


@pytest.mark.parametrize("condition,event,result", [
    ("a and not b", {"x": 1, "y": 0}, True),
    ("a and not b", {"x": 1, "y": 1}, False),
    ("(a or b) and c", {"x": 0, "y": 1, "z": 1}, True),
    ("(a or b) and c", {"x": 1, "y": 0, "z": 0}, False),
    ("1 of sel_*", {"p": 1}, True),
    ("all of sel_*", {"p": 1, "q": 0}, False),
    ("all of them", {"x": 1, "y": 1, "z": 1, "p": 1, "q": 1}, True),
])
def test_conditions(condition, event, result):
    detection = {"a": {"x": 1}, "b": {"y": 1}, "c": {"z": 1},
                 "sel_1": {"p": 1}, "sel_2": {"q": 1}, "condition": condition}
    assert sigma.matches(single(detection), event) is result


def test_bad_conditions_raise():
    for condition in ("a and", "(a", "missing", "a b"):
        with pytest.raises(sigma.SigmaError):
            sigma.compile_condition({"a": {"x": 1}, "condition": condition})


def test_keyword_search():
    rule = single({"k": ["mimikatz"], "condition": "k"})
    assert sigma.matches(rule, {"CommandLine": "run MimiKatz.exe"})
    assert not sigma.matches(rule, {"CommandLine": "notepad"})


def test_event_count_is_grouped_and_windowed():
    rules = ruleset("""
        title: base
        name: base
        detection: {s: {EventID: 1}, condition: s}
        ---
        title: corr
        correlation: {type: event_count, rules: [base], group-by: [ip], timespan: 1m, condition: {gte: 3}}
    """)
    events = testing.build_events([
        {"repeat": 3, "every": "10s", "event": {"EventID": 1, "ip": "a"}},
        {"repeat": 2, "every": "10s", "event": {"EventID": 1, "ip": "b"}},
    ])
    hits = sigma.evaluate(rules, rules.primary(), events)
    assert [hit.group for hit in hits] == [("a",)]


def test_event_count_suppresses_duplicates_within_window():
    rules = ruleset("""
        title: base
        name: base
        detection: {s: {EventID: 1}, condition: s}
        ---
        title: corr
        correlation: {type: event_count, rules: [base], group-by: [ip], timespan: 1m, condition: {gte: 2}}
    """)
    events = testing.build_events([{"repeat": 6, "every": "5s", "event": {"EventID": 1, "ip": "a"}}])
    assert len(sigma.evaluate(rules, rules.primary(), events)) == 1


def test_value_count_requires_field():
    rules = ruleset("""
        title: base
        name: base
        detection: {s: {EventID: 1}, condition: s}
        ---
        title: corr
        correlation: {type: value_count, rules: [base], group-by: [ip], timespan: 1m, condition: {gte: 2}}
    """)
    with pytest.raises(sigma.SigmaError):
        sigma.evaluate(rules, rules.primary(), testing.build_events([{"event": {"EventID": 1}}]))


def test_temporal_unordered_and_ordered():
    text = """
        title: a
        name: a
        detection: {s: {k: a}, condition: s}
        ---
        title: b
        name: b
        detection: {s: {k: b}, condition: s}
        ---
        title: corr
        correlation: {type: %s, rules: [a, b], group-by: [h], timespan: 5m}
    """
    events = testing.build_events([{"event": {"k": "b", "h": 1}}, {"event": {"k": "a", "h": 1}}])
    unordered = ruleset(text % "temporal")
    ordered = ruleset(text % "temporal_ordered")
    assert len(sigma.evaluate(unordered, unordered.primary(), events)) == 1
    assert sigma.evaluate(ordered, ordered.primary(), events) == []


def test_parse_timespan():
    assert sigma.parse_timespan("90s").total_seconds() == 90
    assert sigma.parse_timespan("2h").total_seconds() == 7200
    with pytest.raises(sigma.SigmaError):
        sigma.parse_timespan("5 minutes")


def test_wrong_expectation_is_reported_as_failure(tmp_path):
    rule = tmp_path / "rule.yml"
    rule.write_text("title: r\ndetection: {s: {EventID: 1}, condition: s}\n")
    test_file = tmp_path / "t.yml"
    test_file.write_text(
        "rule: rule.yml\ncases:\n  - name: wrong\n    expect: no_match\n"
        "    events:\n      - event: {EventID: 1}\n")
    [result] = testing.run_test_file(test_file, tmp_path)
    assert not result.passed and result.observed_matches == 1
