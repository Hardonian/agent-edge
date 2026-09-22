# Capture Difference Engine

AgentPCAP provides a structural comparison engine between two `.apcap` runs.

## 1. CLI Diff Command

```bash
agentpcap diff baseline.apcap candidate.apcap
```

Output:
```text
AGENT RUN DIFF
=========================================================
METRIC                        BEFORE           AFTER     CHANGE
---------------------------------------------------------
Model calls                        1               1         +0
Tool calls                         6               2         -4
Delegations                        2               1         -1
Errors                             2               0         -2
---------------------------------------------------------
Latency                         1.5s            0.8s     -46.9%
Tokens                          2490            1650     -33.7%
Cost                         0.0055$         0.0037$     -32.7%
=========================================================

CHANGED OPERATIONS:
  - tools/call:analytics_query          (before: 3, after: 1)
  - tools/list                          (before: 2, after: 1)

RESOLVED PATHOLOGIES:
  ✓ RETRY_STORM resolved
  ✓ DUPLICATE_DISCOVERY resolved
```

---

## 2. JSON Output Mode

For automated CI analysis and bot comments:

```bash
agentpcap diff baseline.apcap candidate.apcap --json
```

Outputs structured `DiffResult` JSON.
