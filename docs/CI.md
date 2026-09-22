# Continuous Integration with AgentPCAP

AgentPCAP provides native assertions and diffing capabilities for continuous integration environments. You can run automated tests of agent systems, capture `.apcap` bundles, assert against runtime pathologies, and detect latency/cost regressions on pull requests.

---

## 1. Automated Assertions (`agentpcap check`)

The `agentpcap check` command parses an `.apcap` file and evaluates it against rules defined in `.agentpcap.yml`. If any violation occurs, the command exits with code `1`.

### Configuration (`.agentpcap.yml`)

```yaml
version: 1

capture:
  content: false

limits:
  max_events: 100000

checks:
  fail_on:
    - loop
    - retry_storm
    - duplicate_discovery
  max:
    cost: 0.50
    latency: 15s
    tokens: 50000
    errors: 0
```

### Running the Check

```bash
agentpcap check test_run.apcap
```

Output when passing:

```text
AgentPCAP CI Check: PASS (test_run.apcap)
No blocking pathology findings or budget limits exceeded.
```

Output when failing:

```text
AgentPCAP CI Check: FAIL (test_run.apcap)
Violations:
  - Disallowed finding detected: RETRY_STORM (Severity: HIGH)
  - Cost exceeded budget: $0.72 > $0.50 max
```

---

## 2. Regression Diffing in PRs (`agentpcap diff`)

Compare a baseline run against candidate runs from feature branches:

```bash
agentpcap diff baseline.apcap candidate.apcap --json > diff_report.json
```

Or print human-readable output to terminal logs:

```bash
agentpcap diff baseline.apcap candidate.apcap
```

---

## 3. GitHub Actions Integration Example

```yaml
name: Agent Evaluation & Trace Regression

on:
  pull_request:
    branches: [ main ]

jobs:
  eval-agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download AgentPCAP
        run: |
          curl -sSL https://github.com/agentpcap/agentpcap/releases/latest/download/agentpcap-linux-amd64.tar.gz | tar -xz
          sudo mv agentpcap /usr/local/bin/

      - name: Run Agent Under Capture
        run: |
          agentpcap run --output pr_run.apcap --no-browser -- go run ./cmd/agent-eval

      - name: Run Quality Gate Checks
        run: |
          agentpcap check pr_run.apcap

      - name: Generate Offline Report
        if: always()
        run: |
          agentpcap report pr_run.apcap -o report.html

      - name: Upload Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agentpcap-trace
          path: |
            pr_run.apcap
            report.html
```

---

## 4. PR Summary Comment Template

When running comparisons against a main baseline:

```markdown
### 🔍 AgentPCAP Run Comparison

| Metric | Baseline | Candidate | Delta |
| :--- | :--- | :--- | :--- |
| **Latency** | 8.2s | 4.1s | 🟢 -50.0% |
| **Tokens** | 21,440 | 13,210 | 🟢 -38.4% |
| **Cost** | $0.120 | $0.074 | 🟢 -38.3% |
| **Errors** | 2 | 0 | 🟢 -100% |
| **Pathologies** | 1 (Retry Storm) | 0 | 🟢 Clean |

*Full capture and standalone report uploaded to run artifacts.*
```
