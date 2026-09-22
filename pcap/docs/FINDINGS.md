# Pathology Detection & Forensic Findings

AgentPCAP features a deterministic, rule-based anomaly detection engine that identifies common agent anti-patterns without invoking external LLMs.

## Detected Pathologies

### 1. `RETRY_STORM` (Severity: HIGH)
- **Condition**: 2 or more consecutive errors followed by retries on the same logical target or operation.
- **Evidence**: Operation name, failure count, affected event IDs.
- **Suggested Fix**: Verify upstream endpoint health, rate limits, or adjust exponential backoff parameters.

### 2. `LOOP` (Severity: HIGH)
- **Condition**: Cyclic delegation chain where Agent A delegates to Agent B, which subsequently delegates back to Agent A.
- **Evidence**: Call pairs establishing the cycle.
- **Suggested Fix**: Establish clear hierarchical delegation boundaries.

### 3. `REPEATED_IDENTICAL_TOOL_CALL` (Severity: MEDIUM)
- **Condition**: Multiple invocations of the same tool with identical argument fingerprints.
- **Evidence**: Tool name, SHA-256 argument hash, occurrence count.
- **Suggested Fix**: Enable client-side memoization or tool caching.

### 4. `DUPLICATE_DISCOVERY` (Severity: LOW)
- **Condition**: Excessive polling of `tools/list` or server handshakes against the same MCP server.
- **Evidence**: Server name, poll count.
- **Suggested Fix**: Cache tool definitions at agent boot.

### 5. `MODEL_FALLBACK` (Severity: MEDIUM)
- **Condition**: Model failure immediately followed by invocation of an alternate fallback model.
- **Evidence**: Primary model name, fallback model name.
- **Suggested Fix**: Investigate primary model error codes (quota, context length, rate limit).

### 6. `UNBOUNDED_OR_DEEP_DELEGATION` (Severity: MEDIUM)
- **Condition**: Delegation tree depth >= 3 levels.
- **Evidence**: Observed depth.
- **Suggested Fix**: Flatten orchestration or configure depth limits.

### 7. `TOKEN_SPIKE` (Severity: MEDIUM)
- **Condition**: A single span consumes >65% of all tokens in the capture.
- **Evidence**: Token count, percentage of session total.
- **Suggested Fix**: Prune prompt context, compress conversation history, or summarize upstream outputs.

### 8. `SLOW_TOOL` (Severity: MEDIUM)
- **Condition**: Tool call execution exceeding 4,000ms.
- **Evidence**: Duration in milliseconds.
- **Suggested Fix**: Optimize query indexes or implement asynchronous polling.

### 9. `POSSIBLE_PARALLELIZATION` (Severity: LOW)
- **Condition**: 3 or more sequential tool calls that could potentially run concurrently if inputs are independent.
- **Evidence**: Cumulative serial duration.
- **Suggested Fix**: Evaluate if tool dispatches can be parallelized with `Promise.all` or Go `errgroup`.
