#!/usr/bin/env bash
# Author: Chandu Komme — Detection Engineering SOC Lab
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
docker compose version >/dev/null

if [[ ! -e .env ]]; then
    password_hex=$(openssl rand -hex 18)
    (
        umask 077
        set -o noclobber
        printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD=Lab-%s-aZ9!\n' "$password_hex" > .env
    )
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
docker compose ps
printf 'Follow the README quick start to replay and verify a detection.\n'
