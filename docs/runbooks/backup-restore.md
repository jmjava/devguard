# Runbook: Backup / restore (planned M4)

1. Configure `[backup]` paths and repository (no passwords in config)
2. `devguard backup plan`
3. `devguard backup run`
4. `devguard backup verify --sample`
5. `devguard backup restore --snapshot ID --target /safe/path --dry-run`
6. Actual restore requires `--apply` and confirmation

Not implemented in M0.
