---
title: DevGuard tasks — Obsidian entrypoint
project: DevGuard
canonical: docs/tasks/backlog-deep.md
tags:
  - devguard
  - backlog
  - obsidian
---

# DevGuard tasks — Obsidian entrypoint

## Canonical store (reload)

| Path | Use |
|---|---|
| [`docs/tasks/backlog-deep.md`](../tasks/backlog-deep.md) | Full deep backlog (Obsidian Tasks) |
| [`docs/tasks/backlog-50.md`](../tasks/backlog-50.md) | Short priority slice |
| [`docs/tasks/manifest.json`](../tasks/manifest.json) | MCP / machine reload |
| [`docs/tasks/SYNERGIES.md`](../tasks/SYNERGIES.md) | Related work map |
| [`docs/tasks/STATUS.md`](../tasks/STATUS.md) | Progress |

```bash
python3 scripts/generate_task_backlog.py
./docs/tasks/reload.sh
```

## Related vault projects

Link from Obsidian MCP memory:

- `jmjava/slm-setup` — bracket Ollama MCP runs with DevGuard metrics
- `jmjava/embabel-slm` — paper efficiency tables
- `jmjava/obsidian-mcp` — this note + capture_work_session
- `jmjava/sdlc-spdd-orchestrator` — Work IDs for slices
- `jmjava/documentation-generator` — demo videos
