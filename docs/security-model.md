# Security model (MVP)

DevGuard observes; it does not remediate by default.

## Guardrails

- Least privilege: no root required for doctor/config/status.
- No secrets in config, argv, logs, or default JSON (`redact` helpers + tests).
- No listening sockets or agents in M0–M5.
- Backup credentials stay outside config (engine password file / OS mechanisms).
- Failures surface as `unavailable` / warnings, never as clean.

## SLM-specific

- `model_dirs` are opt-in path inventories only.
- Process hints match names, not full command lines with tokens.
- GPU queries use bounded `nvidia-smi` flags; output is truncated in doctor.
