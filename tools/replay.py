#!/usr/bin/env python3
"""Replay synthetic Windows and network telemetry and verify every live rule.

Author: Chandu Komme
Project: CyberPulse SOC Lab

The replay posts Windows Security events to Vector over HTTP and appends
Zeek and Suricata records to the mounted telemetry directory. It then checks
that each record was normalized into OpenSearch, waits until ElastAlert2 has
evaluated every rule past the replay time, and compares the alerts raised per
scenario and per rule with the expected matrix in the fixtures. Any missing
alert or unexpected alert fails the run.

Only the Python standard library is used, so the harness runs on a bare host.
"""

__author__ = "Chandu Komme"

import argparse
import base64
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from ipaddress import IPv6Address
from itertools import count
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
WINDOWS_FIXTURES = ROOT / "fixtures/windows-auth.json"
NETWORK_FIXTURES = ROOT / "fixtures/network-replay.json"
RULES_DIR = ROOT / "config/elastalert2/rules"
TELEMETRY_DIR = ROOT / "telemetry"
TELEMETRY_INDEX = "soc-logs-telemetry"
ALERT_INDEX = "soc-alerts"
RULE_NAME = re.compile(r'^name:\s*"?(?P<name>(?P<id>SOC-\d{3}) \|[^"]+?)"?\s*$', re.M)
WINDOWS_RULES = {"SOC-002", "SOC-003"}


def load_rules(rules_dir=RULES_DIR):
    """Map SOC IDs to ElastAlert2 rule names by reading the rule files."""
    rules = {}
    for path in sorted(rules_dir.glob("*.y*ml")):
        match = RULE_NAME.search(path.read_text(encoding="utf-8"))
        if match:
            rules[match.group("id")] = match.group("name").strip()
    return dict(sorted(rules.items()))


def address_factory(replay_id):
    """Yield unique IPv6 documentation-range addresses scoped to one replay."""
    groups = [replay_id.hex[offset:offset + 4] for offset in range(0, 20, 4)]
    prefix = ":".join(["2001", "db8", *groups])
    numbers = count(1)
    return lambda: str(IPv6Address(f"{prefix}:{next(numbers):x}"))


def make_events(scenarios, replay_id, stamp, next_ip=None):
    """Build Windows 4625/4624 events. ``users`` spreads failures across accounts."""
    next_ip = next_ip or address_factory(replay_id)
    events = []
    for scenario in scenarios:
        for source in scenario["sources"]:
            ip = next_ip()
            user_count = source.get("users", 1)
            users = (["lab-analyst"] if user_count == 1
                     else [f"lab-user-{n:02}" for n in range(1, user_count + 1)])
            codes = [4625] * source["failures"] + [4624] * source.get("successes", 0)
            for position, code in enumerate(codes):
                events.append({
                    "@timestamp": stamp.isoformat(timespec="milliseconds"),
                    "event": {"id": f"{replay_id}-{len(events) + 1:02}"},
                    "host": {"name": "lab-win01"},
                    "winlog": {
                        "event_id": code,
                        "event_data": {"IpAddress": ip,
                                       "TargetUserName": users[position % len(users)]},
                    },
                    "labels": {"replay_id": str(replay_id), "scenario": scenario["name"]},
                })
    return events


def make_network_records(scenarios, replay_id, stamp, next_ip=None):
    """Build Zeek and Suricata JSON lines. Returns (stream, record, event_id) tuples."""
    next_ip = next_ip or address_factory(replay_id)
    base_flow = int(replay_id.hex[:12], 16) * 1000
    records = []
    for number, scenario in enumerate(scenarios, start=1):
        source_ip, dest_ip = next_ip(), f"198.51.100.{number}"
        labels = {"replay_id": str(replay_id), "scenario": scenario["name"]}
        record = dict(scenario["record"])
        stream = scenario["stream"]
        if stream.startswith("zeek/"):
            event_id = f"{replay_id}-n{number:02}"
            record.update({"ts": stamp.timestamp(), "uid": event_id, "labels": labels})
            if stream.endswith("notice.log"):
                record.update({"src": source_ip, "dst": dest_ip})
            else:
                record.update({"id.orig_h": source_ip, "id.resp_h": dest_ip})
        elif stream == "suricata/eve.json":
            flow_id = base_flow + number
            event_id = str(flow_id)
            record.update({
                "timestamp": stamp.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                "flow_id": flow_id, "src_ip": source_ip, "dest_ip": dest_ip, "labels": labels,
            })
        else:
            raise RuntimeError(f"Unsupported network stream {stream!r}.")
        records.append((stream, record, event_id))
    return records


def write_network_records(records, telemetry_dir=TELEMETRY_DIR):
    for stream, record, _ in records:
        path = telemetry_dir / stream
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def env_setting(name, default):
    """Read a setting from the environment, then the lab's .env, then a default."""
    if os.environ.get(name):
        return os.environ[name]
    env_file = ROOT / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name and value.strip():
                return value.strip()
    return default


def admin_password():
    if password := os.environ.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD"):
        return password
    try:
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "opensearch",
             "printenv", "OPENSEARCH_INITIAL_ADMIN_PASSWORD"],
            cwd=ROOT, check=True, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("Start the lab with ./setup.sh before running the replay.") from error
    return result.stdout.rstrip("\n")


def send_to_vector(port, events):
    payload = "".join(json.dumps(event) + "\n" for event in events).encode()
    connection = HTTPConnection("127.0.0.1", port, timeout=30)
    deadline = time.monotonic() + 20
    try:
        while True:
            try:
                connection.connect()
                break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        connection.request("POST", "/windows-auth", payload,
                           {"Content-Type": "application/x-ndjson"})
        response = connection.getresponse()
        response.read()
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Vector rejected the replay with HTTP {response.status}.")
    finally:
        connection.close()


class OpenSearch:
    """Read results from the authenticated loopback lab node."""

    def __init__(self, port, password):
        self.port = port
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # The lab Compose stack uses the OpenSearch bundled demo certificate.
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE
        token = base64.b64encode(f"admin:{password}".encode()).decode("ascii")
        self.headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}

    def search(self, index, query, size, **options):
        connection = HTTPSConnection("127.0.0.1", self.port, context=self.tls, timeout=5)
        try:
            body = json.dumps({"query": query, "size": size, **options})
            connection.request("POST", f"/{index}/_search", body, self.headers)
            response = connection.getresponse()
            data = response.read()
        finally:
            connection.close()
        if response.status == 404:
            return []
        if response.status != 200:
            raise RuntimeError(f"OpenSearch returned HTTP {response.status} for {index}.")
        return json.loads(data)["hits"]["hits"]


def verify_windows(events, hits):
    expected = {event["event"]["id"]: event for event in events}
    hits = [hit for hit in hits if hit["_source"]["event"]["dataset"] == "windows.security"]
    if {hit["_id"] for hit in hits} != expected.keys() or len(hits) != len(events):
        raise RuntimeError("Indexed Windows event IDs differ from the records sent to Vector.")
    for hit in hits:
        normal = hit["_source"]
        raw = expected[hit["_id"]]
        code = raw["winlog"]["event_id"]
        if (normal["event"]["id"] != hit["_id"]
                or normal["event"]["code"] != str(code)
                or normal["event"]["outcome"] != ("failure" if code == 4625 else "success")
                or normal["source"]["ip"] != raw["winlog"]["event_data"]["IpAddress"]
                or normal["user"]["name"] != raw["winlog"]["event_data"]["TargetUserName"]
                or normal["host"] != raw["host"]
                or normal["labels"] != raw["labels"]
                or not normal["pipeline"]["ingested_at"]
                or datetime.fromisoformat(normal["@timestamp"])
                != datetime.fromisoformat(raw["@timestamp"])):
            raise RuntimeError(f"Unexpected normalized fields for {hit['_id']}.")


def verify_network(records, hits):
    indexed = {hit["_source"].get("event", {}).get("id"): hit["_source"] for hit in hits
               if hit["_source"]["event"]["dataset"] != "windows.security"}
    for stream, record, event_id in records:
        normal = indexed.get(event_id)
        if normal is None:
            raise RuntimeError(f"Network record {event_id} from {stream} was not indexed.")
        dataset = ("suricata.eve" if stream.startswith("suricata/")
                   else "zeek." + Path(stream).stem)
        if normal["event"]["dataset"] != dataset or normal.get("labels") != record["labels"]:
            raise RuntimeError(f"Unexpected dataset or labels for network record {event_id}.")
        if "query" in record and normal["dns"]["question"]["length"] != len(record["query"]):
            raise RuntimeError(f"DNS length was not computed for {event_id}.")


def expected_matrix(scenarios, rules):
    return {s["name"]: {rule: s["expected_alerts"].get(rule, 0) for rule in rules} for s in scenarios}


def wait_for_evidence(client, replay_id, events, records, rules, expected, stamp, timeout):
    replay_filter = {"term": {"labels.replay_id": str(replay_id)}}
    total = len(events) + len(records)
    wanted = {rule: sum(row[rule] for row in expected.values()) for rule in rules}
    deadline = time.monotonic() + timeout
    state = "the telemetry documents"
    while time.monotonic() < deadline:
        indexed = client.search(TELEMETRY_INDEX, replay_filter, size=total + 10)
        if len(indexed) >= total:
            verify_windows(events, indexed)
            verify_network(records, indexed)
            pending = []
            statuses = {}
            for soc_id, name in rules.items():
                status = client.search(f"{ALERT_INDEX}_status", {"term": {"rule_name": name}},
                                       size=1, sort=[{"@timestamp": "desc"}])
                if not status or datetime.fromisoformat(status[0]["_source"]["endtime"]) < stamp:
                    pending.append(soc_id)
                else:
                    statuses[soc_id] = status[0]["_source"]["endtime"]
            if pending:
                state = f"an ElastAlert2 evaluation covering the replay for {', '.join(pending)}"
            else:
                alerts = client.search(ALERT_INDEX, replay_filter, size=200)
                seen = {rule: 0 for rule in rules}
                for hit in alerts:
                    soc_id = hit["_source"].get("rule_name", "").split(" |")[0]
                    if soc_id in seen:
                        seen[soc_id] += 1
                missing = [rule for rule in rules if seen[rule] < wanted[rule]]
                if not missing:
                    return indexed, alerts, statuses
                state = f"writeback alerts for {', '.join(missing)}"
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {state} for replay {replay_id}.")


def build_report(replay_id, rules, expected, indexed, alerts, statuses):
    by_name = {name: soc_id for soc_id, name in rules.items()}
    case_map = {name: {"event_ids": [], "alerts": []} for name in expected}
    for hit in indexed:
        scenario = hit["_source"].get("labels", {}).get("scenario")
        if scenario in case_map:
            case_map[scenario]["event_ids"].append(hit["_source"]["event"]["id"])
    for hit in alerts:
        alert = hit["_source"]
        soc_id = by_name.get(alert.get("rule_name"))
        scenario = alert.get("labels", {}).get("scenario")
        if soc_id is None or scenario not in case_map or alert.get("alert_sent") is not True:
            raise RuntimeError(f"Unexpected alert record {hit['_id']}.")
        source_id = alert.get("event", {}).get("id")
        if source_id not in case_map[scenario]["event_ids"]:
            raise RuntimeError(f"Alert {hit['_id']} cannot be linked to an indexed replay event.")
        case_map[scenario]["alerts"].append({"id": hit["_id"], "rule": soc_id,
                                             "rule_name": alert["rule_name"], "event_id": source_id})

    observed = {name: {rule: sum(1 for a in case["alerts"] if a["rule"] == rule) for rule in rules}
                for name, case in case_map.items()}
    if observed != expected:
        differences = {name: {"expected": expected[name], "observed": observed[name]}
                       for name in expected if expected[name] != observed[name]}
        raise RuntimeError(f"Alert matrix differs: {json.dumps(differences)}")
    return {
        "replay_id": str(replay_id),
        "author": "Chandu Komme",
        "telemetry_index": TELEMETRY_INDEX,
        "alert_index": ALERT_INDEX,
        "rules": rules,
        "evaluated_through": statuses,
        "expected_alerts": expected,
        "scenarios": case_map,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--collector-port", type=int, default=int(env_setting("VECTOR_PORT", 8688)),
                        help="Vector HTTP port (default: VECTOR_PORT from .env, else 8688).")
    parser.add_argument("--opensearch-port", type=int, default=int(env_setting("OPENSEARCH_PORT", 9200)),
                        help="OpenSearch port (default: OPENSEARCH_PORT from .env, else 9200).")
    parser.add_argument("--scope", choices=("all", "windows", "network"), default="all",
                        help="Which telemetry to replay (default: all).")
    parser.add_argument("--timeout", type=int, default=150, help="Seconds to wait for alert evidence.")
    parser.add_argument("--report", type=Path, help="Write a JSON report after verification succeeds.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the generated events and expected alert matrix without sending.")
    args = parser.parse_args()
    try:
        all_rules = load_rules()
        windows = json.loads(WINDOWS_FIXTURES.read_text(encoding="utf-8")) if args.scope != "network" else []
        network = json.loads(NETWORK_FIXTURES.read_text(encoding="utf-8")) if args.scope != "windows" else []
        rules = {soc_id: name for soc_id, name in all_rules.items()
                 if (soc_id in WINDOWS_RULES and windows) or (soc_id not in WINDOWS_RULES and network)}
        expected = expected_matrix(windows + network, rules)

        replay_id = uuid4()
        now = datetime.now(timezone.utc)
        stamp = now.replace(microsecond=now.microsecond // 1000 * 1000)
        next_ip = address_factory(replay_id)
        events = make_events(windows, replay_id, stamp, next_ip)
        records = make_network_records(network, replay_id, stamp, next_ip)

        if args.dry_run:
            print(json.dumps({"rules": rules, "expected_alerts": expected,
                              "windows_events": len(events),
                              "network_records": [r for _, r, _ in records]}, indent=2))
            return 0

        client = OpenSearch(args.opensearch_port, admin_password())
        print(f"Replay {replay_id}: {len(events)} Windows events, {len(records)} network records, "
              f"{len(rules)} live rules.", flush=True)
        if events:
            send_to_vector(args.collector_port, events)
        if records:
            write_network_records(records)
        indexed, alerts, statuses = wait_for_evidence(
            client, replay_id, events, records, rules, expected, stamp, args.timeout)
        report = build_report(replay_id, rules, expected, indexed, alerts, statuses)

        print(f"{'scenario':<24}{'events':>7}  alerts")
        for name, case in report["scenarios"].items():
            fired = ", ".join(sorted(a["rule"] for a in case["alerts"])) or "none"
            print(f"{name:<24}{len(case['event_ids']):>7}  {fired}")
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f"Saved evidence to {args.report}")
    except ssl.SSLError as error:
        print(f"Replay failed. {error}\nPort {args.opensearch_port} did not answer with HTTPS, so it is "
              "probably another service, not the lab's OpenSearch. Check `docker compose ps` for the "
              "lab's OpenSearch port and pass it with --opensearch-port.", file=sys.stderr)
        return 1
    except (HTTPException, OSError, RuntimeError, ValueError) as error:
        print(f"Replay failed. {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
