#!/usr/bin/env bash
# Author: Chandu Komme — CyberPulse SOC Lab
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
docker compose version >/dev/null

# Create .env if needed, and add a generated admin password if it has none
# (for example when OPENSEARCH_PORT was written to .env first).
if ! grep -qE '^OPENSEARCH_INITIAL_ADMIN_PASSWORD=.+' .env 2>/dev/null; then
    password_hex=$(openssl rand -hex 18)
    (
        umask 077
        touch .env
        printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD=Lab-%s-aZ9!\n' "$password_hex" >> .env
    )
    printf 'Generated an OpenSearch admin password in .env\n'
fi

docker compose up -d --wait --wait-timeout 240 opensearch

# Install the field mappings before starting the collector.
docker compose exec -T opensearch sh -ec '
    curl --fail --silent --show-error --insecure \
      --user "admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \
      --request PUT --header "Content-Type: application/json" \
      --data-binary @- https://localhost:9200/_index_template/soc-logs
' < config/opensearch/index-template.json
printf '\n'

docker compose up -d --wait --wait-timeout 240

# Import the CyberPulse SOC dashboard once OpenSearch Dashboards answers.
env_value() { grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2- || true; }
admin_password=$(env_value OPENSEARCH_INITIAL_ADMIN_PASSWORD)
dashboards_port=$(env_value DASHBOARDS_PORT)
dashboards_url="http://127.0.0.1:${dashboards_port:-5601}"
printf 'Waiting for OpenSearch Dashboards'
for _ in $(seq 1 60); do
    if curl --fail --silent --user "admin:${admin_password}" "${dashboards_url}/api/status" >/dev/null 2>&1; then
        break
    fi
    printf '.'
    sleep 5
done
printf '\n'
if curl --fail --silent --show-error --user "admin:${admin_password}" \
        --header 'osd-xsrf: true' \
        --form file=@dashboards/cyberpulse-soc-dashboard.ndjson \
        "${dashboards_url}/api/saved_objects/_import?overwrite=true" >/dev/null; then
    printf 'Imported the CyberPulse SOC dashboard.\n'
else
    printf 'Could not import the dashboard yet. Import dashboards/cyberpulse-soc-dashboard.ndjson from Saved objects.\n' >&2
fi

docker compose ps
printf '\nCyberPulse SOC Lab is running.\n'
printf '  Console:  %s  (user admin, password in .env)\n' "$dashboards_url"
printf '  Replay:   python3 tools/replay.py --report reports/replay.json\n'
