"""Checks for the generated CyberPulse dashboard. Author: Chandu Komme"""
import json

import build_dashboard


def objects():
    return [json.loads(line) for line in build_dashboard.OUTPUT.read_text(encoding="utf-8").splitlines()]


def test_committed_dashboard_matches_generator():
    assert objects() == json.loads(json.dumps(build_dashboard.build()))


def test_every_reference_resolves():
    saved = {(o["type"], o["id"]) for o in objects()}
    for obj in objects():
        for ref in obj["references"]:
            assert (ref["type"], ref["id"]) in saved, f"{obj['id']} -> {ref['id']}"


def test_visualizations_are_valid_and_colored():
    for obj in objects():
        if obj["type"] == "visualization":
            state = json.loads(obj["attributes"]["visState"])
            assert state["type"] in {"markdown", "metric", "pie", "table", "horizontal_bar"}
            json.loads(obj["attributes"]["uiStateJSON"])
    donut = next(o for o in objects() if o["id"] == "cp-alerts-donut")
    colors = json.loads(donut["attributes"]["uiStateJSON"])["vis"]["colors"]
    assert len(colors) == 5 and all(c.startswith("#") for c in colors.values())


def test_dashboard_lays_out_every_panel_without_overlap():
    dashboard = next(o for o in objects() if o["type"] == "dashboard")
    panels = json.loads(dashboard["attributes"]["panelsJSON"])
    cells = set()
    for panel in panels:
        g = panel["gridData"]
        assert g["x"] + g["w"] <= 48
        for x in range(g["x"], g["x"] + g["w"]):
            for y in range(g["y"], g["y"] + g["h"]):
                assert (x, y) not in cells
                cells.add((x, y))
    assert len(panels) == len(dashboard["references"]) == 11
