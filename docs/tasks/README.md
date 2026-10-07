# DevGuard task store

Canonical, reloadable task backlog for Obsidian MCP / local planning.

| File | Purpose |
|---|---|
| [`backlog-50.md`](backlog-50.md) | Human + Obsidian Tasks checklist (exactly 50) |
| [`manifest.json`](manifest.json) | Machine-readable copy for MCP reload / scripting |
| [`STATUS.md`](STATUS.md) | Progress snapshot (update when checking items off) |

## Reload

```bash
# From repo root — always the source of truth
cat docs/tasks/backlog-50.md
python3 -c 'import json; print(json.load(open("docs/tasks/manifest.json"))["total"])'
```

Obsidian: copy or symlink `backlog-50.md` into your vault (e.g. `Projects/DevGuard/DevGuard-50-Tasks.md`), or have your Obsidian MCP read this path from the cloned repo.

## Conventions

- Tags: `#devguard` plus `#m0`…`#m7` or `#slm`
- Check off only with tests + real commands (SPEC §11)
- Keep `manifest.json` in sync when editing the markdown backlog
