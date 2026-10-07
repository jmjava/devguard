# Runbook: Ubuntu upgrade baseline (planned M1)

1. `devguard config validate`
2. `devguard snapshot create --label pre-upgrade`
3. Perform the Ubuntu upgrade
4. `devguard snapshot create --label post-upgrade`
5. `devguard snapshot diff <pre-id> <post-id>`

Not implemented in M0 — snapshot collectors arrive in M1.
