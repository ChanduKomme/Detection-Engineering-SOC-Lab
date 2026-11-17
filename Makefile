# Author: Chandu Komme — CyberPulse SOC Lab
# Common lab tasks. Run `make help` for the list.

PYTHON ?= python3
REPORT ?= reports/replay.json

.PHONY: help install check lint test coverage pytest up replay replay-windows replay-network case health down clean coverage-update

help:  ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

install:  ## Install the offline toolchain (PyYAML, pytest)
	$(PYTHON) -m pip install -r requirements-dev.txt

check: lint test coverage pytest  ## Run every offline quality gate (same as CI)

lint:  ## Lint Sigma and ElastAlert2 rules
	$(PYTHON) -m detectlab lint

test:  ## Run detection unit tests
	$(PYTHON) -m detectlab test

coverage:  ## Fail if the ATT&CK coverage files are stale
	$(PYTHON) -m detectlab coverage --check

coverage-update:  ## Regenerate ATT&CK coverage table and Navigator layer
	$(PYTHON) -m detectlab coverage

pytest:  ## Run the Python test suite
	$(PYTHON) -m pytest -q tests

up:  ## Start the Docker Compose lab
	./setup.sh

replay:  ## Replay all telemetry and verify every live rule
	$(PYTHON) tools/replay.py --report $(REPORT)

replay-windows:  ## Replay Windows authentication scenarios only
	$(PYTHON) tools/replay.py --scope windows --report $(REPORT)

replay-network:  ## Replay Zeek and Suricata scenarios only
	$(PYTHON) tools/replay.py --scope network --report $(REPORT)

case:  ## Build a Markdown incident case file from the last replay
	$(PYTHON) tools/case_report.py $(REPORT) -o reports/case.md

health:  ## Show service and cluster health
	./health-check.sh

down:  ## Stop the lab and keep data
	docker compose down

clean:  ## Stop the lab and delete its volumes and reports
	docker compose down --volumes
	rm -rf reports .pytest_cache
