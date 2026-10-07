#!/usr/bin/env bash
# Reload / verify the DevGuard task store (safe to re-run anytime).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STORE="$ROOT/docs/tasks"

echo "DevGuard task store: $STORE"
test -f "$STORE/backlog-deep.md"
test -f "$STORE/manifest.json"
test -f "$STORE/SYNERGIES.md"

DEEP="$(grep -cE '^- \[[ x]\]' "$STORE/backlog-deep.md" || true)"
SLICE="$(grep -cE '^- \[[ x]\]' "$STORE/backlog-50.md" || true)"
TOTAL="$(python3 -c 'import json; print(json.load(open("'"$STORE/manifest.json"'"))["total"])')"
DONE="$(python3 -c 'import json; print(json.load(open("'"$STORE/manifest.json"'"))["done"])')"
OPEN="$(python3 -c 'import json; print(json.load(open("'"$STORE/manifest.json"'"))["open"])')"

echo "backlog-deep.md checkboxes: $DEEP"
echo "backlog-50.md checkboxes:    $SLICE"
echo "manifest total/done/open:   $TOTAL / $DONE / $OPEN"

if [[ "$DEEP" != "$TOTAL" ]]; then
  echo "error: deep markdown ($DEEP) != manifest total ($TOTAL) — regenerate" >&2
  exit 1
fi

echo "OK — reload paths:"
echo "  deep:      $STORE/backlog-deep.md"
echo "  priority:  $STORE/backlog-50.md"
echo "  json:      $STORE/manifest.json"
echo "  synergies: $STORE/SYNERGIES.md"
echo "  status:    $STORE/STATUS.md"
