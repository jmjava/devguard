# Academic SLM metrics → DevGuard capture plan

Goal: produce **reproducible, paper-comparable** workstation measurements for small language model (SLM) experiments. DevGuard focuses on **system/efficiency instrumentation** and a structured run record; task-quality scores remain the job of your eval harness (lm-eval, custom scripts, etc.).

## What papers actually report

Across recent SLM/efficiency literature, metrics fall into four buckets. Sources below are representative, not exhaustive.

| Bucket | Common metrics | Representative sources |
|---|---|---|
| **Task quality** | Accuracy / F1 / exact match on MMLU, GSM8K, HellaSwag, Winogrande, SuperGLUE, XSum, etc. | Wang et al. SLM survey ([arXiv:2410.20011](https://arxiv.org/pdf/2410.20011)); Lu et al. measurements ([arXiv:2409.15790](https://arxiv.org/abs/2409.15790)); IJCAI efficiency landscape (2026) |
| **Latency & throughput** | Prefill / **TTFT** (time to first token); decode **TPOT** / ITL (time per output token); **tokens/s**; requests/s; e2e latency; **p50/p99** percentiles | Lu et al.; MLPerf Inference LLM (TTFT + TPOT); Edge-first inference ([arXiv:2505.16508](https://arxiv.org/html/2505.16508v2)); serving study ([arXiv:2404.03353](https://arxiv.org/pdf/2404.03353)) |
| **Memory & config** | Parameter count; quantization (e.g. 4-bit); peak **RAM/VRAM**; KV-cache footprint; batch size; prompt length; generation length; backend | Lu et al.; TokenPowerBench; ML.ENERGY |
| **Energy & thermals** | Average **power (W)**; **J/token** or J/query; tokens/J or tokens/Wh; throughput/Watt; Energy-Delay Product; idle power; GPU/junction **temperature** (throttling) | ML.ENERGY ([arXiv:2505.06371](https://arxiv.org/pdf/2505.06371v2)); MLPerf Power ([arXiv:2410.12032](https://arxiv.org/pdf/2410.12032)); edge energy footprint ([arXiv:2511.11624](https://arxiv.org/html/2511.11624)); IJCAI Pareto energy–accuracy |

### Design lessons from those papers

1. **Always pair quality with cost.** Accuracy alone is not an efficiency result; energy–performance **Pareto** curves are the academic norm (IJCAI efficiency landscape; ML.ENERGY).
2. **Split prefill vs decode.** First-token latency and per-token decode latency are not interchangeable (Lu et al.; MLPerf).
3. **Lock the experimental cell.** Comparable rows need fixed `(device, backend, power mode, quantization, context length, generation length, batch)` — smolperf / edge benchmarks emphasize this.
4. **Report percentiles for interactive serving.** MLPerf LLM uses **p99 TTFT** and **p99 TPOT**, not only means.
5. **Normalize energy to service units.** Prefer **J/token**, **J/request**, or **tokens/J** over raw joules without workload shape (TokenPowerBench; MLPerf Power).
6. **Watch thermals.** Cool-down intervals (e.g. 10s between runs in Lu et al.) matter; temperature/throttling must be logged or results are not reproducible on workstations/edge GPUs.
7. **Smaller ≠ automatically more efficient.** Several studies show energy and utilization can be non-monotonic with parameter count; measure, don’t assume.

## What DevGuard will capture

### A. Automatic host/GPU observations (DevGuard collectors)

These map directly to paper “system analysis” columns and do **not** require the model harness:

| Field | Unit | Why papers need it |
|---|---|---|
| `gpu.name`, `gpu.driver_version` | — | Hardware cell identity |
| `gpu.utilization_percent` | % | Load / underutilization (see serving papers) |
| `gpu.memory_used_bytes`, `gpu.memory_total_bytes` | B | Peak VRAM / footprint |
| `gpu.temperature_c` | °C | Thermal throttling evidence |
| `gpu.power_draw_w`, `gpu.power_limit_w` | W | Instantaneous power for J≈P·Δt |
| `gpu.clocks` (SM/mem if available) | MHz | Power-mode / boost state |
| `host.cpu_percent`, `host.memory_*`, `host.swap_*` | % / B | Contention, CPU offload |
| `host.disk_*` | B | Model weight residency |
| `sensors.fans` / package temps | RPM / °C | Workstation stability (DevGuard health) |
| `observed_at`, `collection_status` | RFC3339 / enum | Never mark missing sensors “healthy” |

Derived when a timed run window is known:

- `energy_gpu_approx_j` ≈ mean(`power_draw_w`) × `duration_s` (GPU-rail estimate; **not** wall AC power)
- `tokens_per_joule` if the harness supplies output token count
- `throughput_per_watt` if tokens/s and mean power are both present

> Caveat (academic honesty): `nvidia-smi` power is **GPU board power**, not MLPerf-style whole-system AC watt-meters. Label the measurement plane explicitly in exports.

### B. Experiment annotations (supplied by your harness / CLI flags)

DevGuard stores these as structured metadata so a run folder is paper-ready:

| Field | Unit | Notes |
|---|---|---|
| `model_id`, `parameter_count`, `quantization` | — | e.g. `Q4_K_M` |
| `backend` | — | `llama.cpp`, `vllm`, `ollama`, `huggingface`, … |
| `batch_size`, `context_length`, `prompt_tokens`, `output_tokens` | count | Lock the cell |
| `ttft_ms` / `ttft_p50_ms` / `ttft_p99_ms` | ms | Prefill / first token |
| `tpot_ms` / `tpot_p50_ms` / `tpot_p99_ms` | ms | Decode |
| `tokens_per_second` | tok/s | Decode or e2e — set `throughput_kind` |
| `e2e_latency_ms` | ms | Full request |
| `task_name`, `task_metric`, `task_score` | — | Optional quality pointer (MMLU acc, etc.) |
| `energy_j_external` | J | Optional wall-meter / external logger |
| `notes`, `git_commit`, `run_label` | — | Reproducibility |

Schema: [`schemas/slm-run-metrics.schema.json`](schemas/slm-run-metrics.schema.json). Rust types live in `devguard_core::slm`.

### C. Out of scope for DevGuard (by design)

- Running MMLU/GSM8K or claiming model quality
- Replacing MLPerf load generators or calibrated AC power analyzers
- Training FLOPs accounting (paper-specific; can be annotated manually)

## Minimal “paper table” checklist

For each published configuration row, retain at least:

1. Model id + params + quantization + backend  
2. Hardware id (GPU name, driver, host CPU/RAM)  
3. Prompt length, generation length, batch size  
4. TTFT and TPOT (mean **and** p99 if interactive)  
5. Tokens/s  
6. Peak VRAM (and host RAM if relevant)  
7. Mean GPU power + estimated J/token (and wall energy if available)  
8. Mean/max GPU temperature during the run  
9. Task score + benchmark name (from harness)  
10. Timestamp, code commit, and any cool-down / power-mode notes  

## Mapping to DevGuard commands (roadmap)

| Command | Role |
|---|---|
| `doctor` | Coverage: is `nvidia-smi` / sensors available? |
| `gpu scan` / `health scan` | One-shot system snapshot for a moment in time |
| `slm host` | Host companion sample: CPU %, RAM/swap, disk free bytes, RFC3339 |
| `health watch` | Time series during an experiment (bounded interval) |
| `slm run begin/end` *(planned)* | Bracket a harness run; sample GPU/host; merge annotations; write JSONL/JSON under state dir |
| `slm export` *(planned)* | Emit a paper-oriented CSV/JSON table from stored runs |

## Key references

1. Lu et al., *Small Language Models: Survey, Measurements, and Insights* — [arXiv:2409.15790](https://arxiv.org/abs/2409.15790)  
2. Wang et al., *A Survey of Small Language Models* — [arXiv:2410.20011](https://arxiv.org/abs/2410.20011) / [ACL Anthology](https://aclanthology.org/2025.ranlp-1.93/)  
3. *Mapping the Efficiency Landscape of Small Language Models* — [IJCAI 2026 PDF](https://www.ijcai.org/proceedings/2026/0627.pdf)  
4. Wilkins et al. / ML.ENERGY — [arXiv:2505.06371](https://arxiv.org/abs/2505.06371)  
5. SLM serving characterisation — [arXiv:2404.03353](https://arxiv.org/abs/2404.03353)  
6. Edge-first LM inference metrics — [arXiv:2505.16508](https://arxiv.org/abs/2505.16508)  
7. Edge SLM energy footprint — [arXiv:2511.11624](https://arxiv.org/abs/2511.11624)  
8. MLPerf Power — [arXiv:2410.12032](https://arxiv.org/abs/2410.12032)  
9. TokenPowerBench — [arXiv:2512.03024](https://arxiv.org/abs/2512.03024)  
10. MLPerf Inference LLM metrics (TTFT/TPOT, tokens/s) — [MLCommons](https://mlcommons.org/2025/04/llm-inference-v5/)
