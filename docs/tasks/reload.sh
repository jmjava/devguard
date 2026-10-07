#!/usr/bin/env bash
# Reload / verify the DevGuard task store (safe to re-run anytime).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STORE="$ROOT/docs/tasks"

echo "DevGuard task store: $STORE"
test -f "$STORE/backlog-50.md"
test -f "$STORE/manifest.json"

COUNT="$(grep -cE '^- \[[ x]\]' "$STORE/backlog-50.md")"
TOTAL="$(python3 -c 'import json; print(json.load(open("'"$STORE/manifest.json"'"))["total"])')"
DONE="$(python3 -c 'import json; print(json.load(open("'"$STORE/manifest.json"'"))["done"])')"
OPEN="$(python3 -c 'import json; print(json.load(open("'"$STORE/manifest.json"'"))["open"])')"

echo "markdown checkboxes: $COUNT"
echo "manifest total/done/open: $TOTAL / $DONE / $OPEN"

if [[ "$COUNT" != "50" || "$TOTAL" != "50" ]]; then
  echo "error: expected exactly 50 tasks" >&2
  exit 1
fi

echo "OK — reload paths:"
echo "  markdown: $STORE/backlog-50.md"
echo "  json:     $STORE/manifest.json"
echo "  status:   $STORE/STATUS.md"
