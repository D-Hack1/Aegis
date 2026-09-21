#!/usr/bin/env bash
# reset_dashboard.sh — Wipe all alerts from Elasticsearch and recreate the empty index.
# Run this before a demo to start with a clean dashboard.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ES_URL="${ES_URL:-http://localhost:9200}"

echo "== Deleting alerts index =="
curl -s -X DELETE "$ES_URL/alerts" | python3 -c "import sys,json; r=json.load(sys.stdin); print('Deleted.' if r.get('acknowledged') else f'Warning: {r}')"

echo "== Recreating empty alerts index =="
python3 es/init_index.py

echo "== Verifying index is empty =="
COUNT=$(curl -s "$ES_URL/alerts/_count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
if [[ "$COUNT" -eq 0 ]]; then
    echo "== Dashboard is clean — $COUNT alerts. Ready for demo. =="
else
    echo "!! Warning: $COUNT alerts still present — check Elasticsearch"
    exit 1
fi

echo "== Hard refresh your browser (Ctrl+Shift+R) to clear the frontend cache =="
