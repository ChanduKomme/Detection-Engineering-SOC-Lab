#!/usr/bin/env bash
# Author: Chandu Komme — Detection Engineering SOC Lab
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
docker compose ps
docker compose exec -T opensearch sh -ec '
    curl --fail --silent --show-error --insecure \
      --user "admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \
      "https://localhost:9200/_cluster/health?pretty"
'
