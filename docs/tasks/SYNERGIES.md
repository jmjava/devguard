# Related work & synergies

Map of **your repos** and **external research/tools** that amplify DevGuard. Use tags `#synergy/<id>` in the deep backlog.

## Your portfolio (highest leverage)

| Repo | What it is | Synergy with DevGuard |
|---|---|---|
| [jmjava/slm-setup](https://github.com/jmjava/slm-setup) | stdio MCP bridge → private Ollama GPU host; eval protocol + deployment safety | **Instrument the Ollama host during MCP/harness runs**; feed TTFT/TPOT/VRAM into `SlmRunRecord`; reuse deployment-safety posture (no public Ollama) |
| [jmjava/embabel-slm](https://github.com/jmjava/embabel-slm) | Local coding-model research program; paper calendar; controlled experiments | **Paper-grade efficiency tables** for base/retrieval/LoRA cells; lock `(model, backend, quant, ctx, gen)`; export CSV for Zenodo preprint |
| [jmjava/obsidian-mcp](https://github.com/jmjava/obsidian-mcp) | Obsidian vault as AI engineering memory (MCP) | **Reload task store + capture run sessions/decisions** into vault; `capture_work_session` after `devguard slm run end` |
| [jmjava/sdlc-spdd-orchestrator](https://github.com/jmjava/sdlc-spdd-orchestrator) | Work-ID / REASONS canvas / phase gates | Track DevGuard milestones as SPDD work items; ledger lessons from metric failures |
| [jmjava/documentation-generator](https://github.com/jmjava/documentation-generator) | Narrated Manim/TTS demo videos | Demo videos of `doctor` → `slm run` → paper export for embabel-slm / courseware |
| [jmjava/embabel-learning](https://github.com/jmjava/embabel-learning) / embabel-v1-learning | Embabel learning materials | Corpus hygiene checks via `dev repos` / snapshot of toolchain when training |

### Synergy loops (do these)

1. **slm-setup live accept → DevGuard bracket**  
   `prove_acceptance.py` / harness profiles wrap with `devguard slm run begin/end` so every live Ollama call gets GPU-rail samples.

2. **embabel-slm experiment cell → DevGuard export**  
   Each research phase row writes `ExperimentMeta` + harness latency; DevGuard fills system/energy; `slm export` feeds paper tables.

3. **DevGuard task store → obsidian-mcp**  
   Vault note mirrors `docs/tasks/backlog-deep.md` + `manifest.json`; check off via MCP; `record_decision` for restic/SQLite/etc.

4. **Halo / downstairs GPU hosts (slm-setup examples)**  
   Same collectors on WSL-GPU and future Ryzen AI Max/Halo; DevGuard M7 stays read-only metrics (matches slm-setup “no public Ollama”).

5. **docgen demos**  
   Scripted walkthrough of upgrade snapshot + SLM energy Pareto for talks/preprints.

## External ecosystem (integrate, don’t reinvent)

| Tool / paper | Role | DevGuard stance |
|---|---|---|
| **llama-bench** (llama.cpp) | pp/tg/pg tok/s, JSON/CSV | Import adapter → latency fields; DevGuard adds VRAM/power/temp |
| **vLLM `/metrics`** | TTFT/TPOT histograms, KV cache | Optional scrape during `slm run` when backend=vllm |
| **Zeus (ml-energy)** | Windowed GPU/CPU/DRAM energy, NVML | Prefer Zeus windows when available; else nvidia-smi rail; label plane |
| **ML.ENERGY Benchmark** | Energy–latency Pareto | Align export columns with their comparison style |
| **DCGM / nvidia-smi** | Util, VRAM, power, energy counters | Primary Linux workstation collectors |
| **llm-inference-benchmark** | TTFT/VRAM/tok/J harness | Compatible JSON ingest path |
| **LLenergyMeasure** | Multi-engine energy studies | Interop via shared CSV schema, not a dependency |
| **MLPerf Inference/Power** | TTFT/TPOT p99, tokens/s, wall AC | Document honesty: DevGuard ≠ wall meter unless external |

## Academic metric contract (shared across embabel-slm + DevGuard)

Every publishable row should include:

1. model_id + params + quantization + backend  
2. hardware (GPU name, driver, host RAM)  
3. prompt_tokens, output_tokens, batch, context  
4. TTFT (+ p99), TPOT (+ p99), tokens/s  
5. peak VRAM  
6. mean GPU power + J/token (plane labeled)  
7. GPU temp during run  
8. task_name + task_score  
9. git commit / run_label  
10. cool-down / power-mode notes  

See `docs/slm-research-metrics.md`.

## Non-goals (avoid duplicate work)

- Do not fork Ollama or implement a second MCP coding bridge (that’s slm-setup).
- Do not train/fine-tune models (that’s embabel-slm).
- Do not replace Obsidian or SPDD process tooling.
- Do not claim MLPerf Power wall-AC equivalence from nvidia-smi alone.
