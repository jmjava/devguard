# Security model (MVP)

DevGuard observes; it does not remediate by default.

## Guardrails

- Least privilege: no root required for doctor/config/status.
- No secrets in config, argv, logs, or default JSON (`redact` helpers + tests).
- No listening sockets or agents in M0–M5.
- Backup credentials stay outside config (engine password file / OS mechanisms).
- Failures surface as `unavailable` / warnings, never as clean.
- `security paths` checks only `security.sensitive_path_allowlist`. It reads mode bits and, when the local account database has them, owner and group names. It does not recurse, use sudo, or read file contents. An empty allowlist is not a clean disk scan.

## Downstairs WSL helper

`devguard remote` is off until the local config names an SSH host and user. Those values stay in that file and are not printed.

The allowlist is host up or down, tunnel up or down, Ollama tags through the local forward, a fixed GPU sample, and a fixed fan sample (`devguard health fan` on the remote, when that command exists). If SSH has no route, status reports host down.

The tunnel is an SSH local-forward to Ollama on `127.0.0.1` inside WSL. DevGuard does not bind `0.0.0.0`, open a public tunnel, run an arbitrary remote command, upload files, change firewall rules, or install a daemon. The operator opens the forward and closes it.

## SLM-specific

- `model_dirs` are opt-in path inventories only.
- Process hints match names, not full command lines with tokens.
- GPU queries use bounded `nvidia-smi` flags; output is truncated in doctor.
