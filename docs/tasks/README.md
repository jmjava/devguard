# DevGuard task store

Reloadable backlog for **Obsidian MCP**, planning, and Cursor slices.

| File | Purpose |
|---|---|
| [`backlog-deep.md`](backlog-deep.md) | **Canonical deep checklist** (hundreds of tasks) |
| [`backlog-50.md`](backlog-50.md) | Short priority slice (kept for focused sprints) |
| [`manifest.json`](manifest.json) | Machine-readable deep backlog for MCP reload |
| [`SYNERGIES.md`](SYNERGIES.md) | Your repos + external tools to exploit |
| [`STATUS.md`](STATUS.md) | Progress snapshot |
| [`reload.sh`](reload.sh) | Verify counts anytime |
| [`../../scripts/generate_task_backlog.py`](../../scripts/generate_task_backlog.py) | Regenerate deep backlog + manifest |

## Reload

```bash
./docs/tasks/reload.sh
# or regenerate from source of truth:
python3 scripts/generate_task_backlog.py && ./docs/tasks/reload.sh
```

Obsidian MCP: point at `docs/tasks/backlog-deep.md` or import `manifest.json`.

## Synergy-first next slices

1. `#slm` NVIDIA/host collectors  
2. `#synergy/slm-setup` bracket live Ollama harness  
3. `#synergy/embabel-slm` paper export tables  
4. `#synergy/obsidian-mcp` vault reload of this store  
5. `#m1` SQLite + snapshots  

See [`SYNERGIES.md`](SYNERGIES.md).
