# Scenario manifests (Component 4)

| Scenario | Status | Notes |
|---|---|---|
| `file-ops-smoke/v1` | Smoke (local) | mkdir + two writes + one delete; phase `record` |
| `file-ops-smoke/v1/manifest.remote.json` | Smoke (SSH) | Same ops; `login-pod` target; bounded remote helper |
| `unauthorized-data-write/v1` | Ready (offline) | First security integration; fake-adapter demo |
| `admin-credential-exposure/v1` | Ready (inert canary) | Synthetic exposure only |
| `unauthorized-compute/v1` | Feasibility gated | Unauthorized partition authorization (replaces older detached-process draft); not live |

The original project's validation guide and trace runbook are not part of this
public edition; each scenario's README and manifest describe it in full.
