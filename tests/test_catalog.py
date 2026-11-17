"""Catalog-level gates: lint, detection tests and generated coverage. Author: Chandu Komme"""
from pathlib import Path

import pytest
import yaml

from detectlab import coverage, lint, testing

ROOT = Path(__file__).resolve().parents[1]
SIGMA = Path("detection-rules/sigma")
TESTS = Path("tests/detections")
LIVE = Path("config/elastalert2/rules")


def test_catalog_lints_clean():
    findings = lint.lint_sigma(ROOT, SIGMA, TESTS) + lint.lint_live(ROOT, LIVE)
    assert not findings, "\n".join(map(str, findings))


@pytest.mark.parametrize("result", testing.run_all(TESTS, ROOT),
                         ids=lambda r: f"{r.test_file.stem}:{r.case}")
def test_detection_case(result):
    assert result.passed, f"expected {result.expected}, saw {result.observed_matches} match(es)"


def test_generated_coverage_is_current():
    for path, content in coverage.render(ROOT, SIGMA, TESTS, LIVE).items():
        assert path.read_text(encoding="utf-8") == content, f"{path} is stale"


def test_lint_flags_untested_and_untagged_rule(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "rules/bad.yml").write_text(yaml.safe_dump({
        "title": "Bad", "id": "not-a-uuid", "status": "draft", "description": "d",
        "author": "a", "level": "severe", "logsource": {"product": "x"},
        "detection": {"s": {"a": 1}, "condition": "s"},
    }))
    messages = " | ".join(str(f) for f in lint.lint_sigma(tmp_path, Path("rules"), Path("tests")))
    for expected in ("not a UUID", "status must be", "level must be", "attack.tNNNN",
                     "falsepositives", "no unit test"):
        assert expected in messages


def test_lint_flags_bad_live_rule_name(tmp_path):
    (tmp_path / "live").mkdir()
    (tmp_path / "live/r.yml").write_text("name: brute force\ntype: any\n")
    messages = " | ".join(str(f) for f in lint.lint_live(tmp_path, Path("live")))
    assert "SOC-NNN" in messages and "missing 'filter'" in messages
