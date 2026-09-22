package pathology

import (
	"fmt"
	"strings"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// Severity represents the impact level of a detected finding.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// Confidence indicates heuristic certainty.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Finding represents a deterministic runtime anomaly.
type Finding struct {
	Type            string         `json:"type"`
	Severity        Severity       `json:"severity"`
	Confidence      Confidence     `json:"confidence"`
	Title           string         `json:"title"`
	Explanation     string         `json:"explanation"`
	Evidence        map[string]any `json:"evidence,omitempty"`
	EventIDs        []string       `json:"event_ids"`
	SuggestedFix    string         `json:"suggested_fix"`
	AnalyzerVersion string         `json:"analyzer_version"`
}

// Engine scans captures for known anti-patterns and performance pathologies.
type Engine struct {
	version string
}

// NewEngine creates a pathology analyzer.
func NewEngine() *Engine {
	return &Engine{version: "1.0.0"}
}

// Analyze runs all deterministic detectors on the given events.
func (e *Engine) Analyze(events []apcap.Event) []Finding {
	var findings []Finding

	findings = append(findings, e.detectRetryStorm(events)...)
	findings = append(findings, e.detectLoops(events)...)
	findings = append(findings, e.detectDuplicateToolCalls(events)...)
	findings = append(findings, e.detectDuplicateDiscovery(events)...)
	findings = append(findings, e.detectModelFallback(events)...)
	findings = append(findings, e.detectDeepDelegation(events)...)
	findings = append(findings, e.detectTokenSpikes(events)...)
	findings = append(findings, e.detectSlowTools(events)...)
	findings = append(findings, e.detectPossibleParallelization(events)...)

	return findings
}

// 1. RETRY_STORM
func (e *Engine) detectRetryStorm(events []apcap.Event) []Finding {
	var findings []Finding
	opErrors := make(map[string][]string) // op -> list of event IDs with errors

	for _, ev := range events {
		if ev.Status == apcap.StatusError || ev.Status == apcap.StatusTimeout || ev.Type == apcap.EventRetry {
			opErrors[ev.Operation] = append(opErrors[ev.Operation], ev.ID)
		}
	}

	for op, ids := range opErrors {
		if len(ids) >= 2 {
			findings = append(findings, Finding{
				Type:            "RETRY_STORM",
				Severity:        SeverityHigh,
				Confidence:      ConfidenceHigh,
				Title:           fmt.Sprintf("Retry storm detected on '%s'", op),
				Explanation:     fmt.Sprintf("Operation '%s' experienced %d consecutive failures/retries.", op, len(ids)),
				Evidence:        map[string]any{"operation": op, "failure_count": len(ids)},
				EventIDs:        ids,
				SuggestedFix:    "Check upstream endpoint health, rate limits, or adjust exponential backoff parameters.",
				AnalyzerVersion: e.version,
			})
		}
	}
	return findings
}

// 2. LOOP DETECTION
func (e *Engine) detectLoops(events []apcap.Event) []Finding {
	var findings []Finding
	seenPairs := make(map[string]string) // B->A -> eventID

	for _, ev := range events {
		if ev.Type == apcap.EventA2ARequest || ev.Type == apcap.EventDelegation {
			src := ev.Source.Name
			dst := ev.Destination.Name
			if src == "" || dst == "" || src == dst {
				continue
			}

			pair := fmt.Sprintf("%s->%s", src, dst)
			reversePair := fmt.Sprintf("%s->%s", dst, src)

			if origID, exists := seenPairs[reversePair]; exists {
				findings = append(findings, Finding{
					Type:            "LOOP",
					Severity:        SeverityHigh,
					Confidence:      ConfidenceHigh,
					Title:           fmt.Sprintf("Cyclic delegation loop between '%s' and '%s'", src, dst),
					Explanation:     fmt.Sprintf("Agent '%s' called '%s', which subsequently called back to '%s'.", dst, src, dst),
					Evidence:        map[string]any{"cycle": fmt.Sprintf("%s <-> %s", src, dst)},
					EventIDs:        []string{origID, ev.ID},
					SuggestedFix:    "Establish clear hierarchical delegation boundaries to prevent ping-pong loops.",
					AnalyzerVersion: e.version,
				})
			}
			seenPairs[pair] = ev.ID
		}
	}
	return findings
}

// 3. REPEATED_IDENTICAL_TOOL_CALL
func (e *Engine) detectDuplicateToolCalls(events []apcap.Event) []Finding {
	var findings []Finding
	type toolSig struct {
		name string
		hash string
	}
	seen := make(map[toolSig][]string)

	for _, ev := range events {
		if ev.Protocol == apcap.ProtocolTool || ev.Type == apcap.EventMCPToolCall {
			toolName, _ := ev.Attributes["tool.name"].(string)
			if toolName == "" {
				toolName = ev.Destination.Name
			}
			argHash, _ := ev.Attributes["tool.args_hash"].(string)
			if toolName != "" && argHash != "" {
				sig := toolSig{name: toolName, hash: argHash}
				seen[sig] = append(seen[sig], ev.ID)
			}
		}
	}

	for sig, ids := range seen {
		if len(ids) >= 2 {
			findings = append(findings, Finding{
				Type:            "REPEATED_IDENTICAL_TOOL_CALL",
				Severity:        SeverityMedium,
				Confidence:      ConfidenceHigh,
				Title:           fmt.Sprintf("Redundant tool call to '%s' with identical arguments", sig.name),
				Explanation:     fmt.Sprintf("Tool '%s' was called %d times with the exact same input fingerprint (%s).", sig.name, len(ids), sig.hash),
				Evidence:        map[string]any{"tool": sig.name, "hash": sig.hash, "occurrences": len(ids)},
				EventIDs:        ids,
				SuggestedFix:    "Enable client-side tool caching or memoization to save latency and tokens.",
				AnalyzerVersion: e.version,
			})
		}
	}
	return findings
}

// 4. DUPLICATE_DISCOVERY
func (e *Engine) detectDuplicateDiscovery(events []apcap.Event) []Finding {
	var findings []Finding
	serverDiscovery := make(map[string][]string) // server -> event IDs

	for _, ev := range events {
		if ev.Type == apcap.EventMCPToolsList || ev.Type == apcap.EventMCPDiscover {
			server := ev.Destination.Name
			serverDiscovery[server] = append(serverDiscovery[server], ev.ID)
		}
	}

	for srv, ids := range serverDiscovery {
		if len(ids) > 1 {
			findings = append(findings, Finding{
				Type:            "DUPLICATE_DISCOVERY",
				Severity:        SeverityLow,
				Confidence:      ConfidenceHigh,
				Title:           fmt.Sprintf("Repeated MCP tool discovery against server '%s'", srv),
				Explanation:     fmt.Sprintf("MCP tools/list was polled %d times during the session.", len(ids)),
				Evidence:        map[string]any{"server": srv, "count": len(ids)},
				EventIDs:        ids,
				SuggestedFix:    "Cache MCP server tool specifications at agent boot rather than re-discovering before every call.",
				AnalyzerVersion: e.version,
			})
		}
	}
	return findings
}

// 5. MODEL_FALLBACK
func (e *Engine) detectModelFallback(events []apcap.Event) []Finding {
	var findings []Finding
	for i := 0; i < len(events)-1; i++ {
		cur := events[i]
		next := events[i+1]
		if cur.Protocol == apcap.ProtocolModel && cur.Status == apcap.StatusError {
			if next.Protocol == apcap.ProtocolModel && next.Destination.Name != cur.Destination.Name {
				findings = append(findings, Finding{
					Type:            "MODEL_FALLBACK",
					Severity:        SeverityMedium,
					Confidence:      ConfidenceHigh,
					Title:           fmt.Sprintf("Model fallback: '%s' -> '%s'", cur.Destination.Name, next.Destination.Name),
					Explanation:     fmt.Sprintf("Model '%s' failed, followed by fallback invocation of '%s'.", cur.Destination.Name, next.Destination.Name),
					Evidence:        map[string]any{"primary_model": cur.Destination.Name, "fallback_model": next.Destination.Name},
					EventIDs:        []string{cur.ID, next.ID},
					SuggestedFix:    "Investigate the primary model failure reason (e.g. quota, context length, content filter).",
					AnalyzerVersion: e.version,
				})
			}
		}
	}
	return findings
}

// 6. UNBOUNDED_OR_DEEP_DELEGATION
func (e *Engine) detectDeepDelegation(events []apcap.Event) []Finding {
	var findings []Finding
	for _, ev := range events {
		if ev.Type == apcap.EventDelegation {
			depth, _ := ev.Attributes["a2a.delegation_depth"].(int)
			if depth >= 3 {
				findings = append(findings, Finding{
					Type:            "UNBOUNDED_OR_DEEP_DELEGATION",
					Severity:        SeverityMedium,
					Confidence:      ConfidenceHigh,
					Title:           fmt.Sprintf("Deep delegation hierarchy (depth %d)", depth),
					Explanation:     fmt.Sprintf("Delegation chain reached depth %d, increasing latency and cost risk.", depth),
					Evidence:        map[string]any{"depth": depth},
					EventIDs:        []string{ev.ID},
					SuggestedFix:    "Flatten agent delegation structure or establish a maximum delegation depth policy.",
					AnalyzerVersion: e.version,
				})
			}
		}
	}
	return findings
}

// 7. TOKEN_SPIKE
func (e *Engine) detectTokenSpikes(events []apcap.Event) []Finding {
	var findings []Finding
	var totalTokens int64
	for _, ev := range events {
		if ev.Tokens != nil {
			totalTokens += ev.Tokens.TotalTokens
		}
	}

	if totalTokens < 1000 {
		return findings
	}

	for _, ev := range events {
		if ev.Tokens != nil && float64(ev.Tokens.TotalTokens)/float64(totalTokens) > 0.65 {
			pct := (float64(ev.Tokens.TotalTokens) / float64(totalTokens)) * 100.0
			findings = append(findings, Finding{
				Type:            "TOKEN_SPIKE",
				Severity:        SeverityMedium,
				Confidence:      ConfidenceHigh,
				Title:           fmt.Sprintf("Token spike in %s: %d tokens (%.1f%% of run)", ev.Operation, ev.Tokens.TotalTokens, pct),
				Explanation:     fmt.Sprintf("A single operation consumed %.1f%% of all tokens spent across the entire capture.", pct),
				Evidence:        map[string]any{"tokens": ev.Tokens.TotalTokens, "total": totalTokens, "percent": pct},
				EventIDs:        []string{ev.ID},
				SuggestedFix:    "Optimize prompt context size, prune conversation history, or summarize upstream outputs.",
				AnalyzerVersion: e.version,
			})
		}
	}
	return findings
}

// 8. SLOW_TOOL
func (e *Engine) detectSlowTools(events []apcap.Event) []Finding {
	var findings []Finding
	for _, ev := range events {
		if (ev.Protocol == apcap.ProtocolTool || ev.Type == apcap.EventMCPToolCall) && ev.DurationMs > 4000.0 {
			findings = append(findings, Finding{
				Type:            "SLOW_TOOL",
				Severity:        SeverityMedium,
				Confidence:      ConfidenceHigh,
				Title:           fmt.Sprintf("Slow tool execution: '%s' took %.1fms", ev.Destination.Name, ev.DurationMs),
				Explanation:     fmt.Sprintf("Tool call exceeded 4 seconds (%.1fms), blocking the agent execution path.", ev.DurationMs),
				Evidence:        map[string]any{"tool": ev.Destination.Name, "duration_ms": ev.DurationMs},
				EventIDs:        []string{ev.ID},
				SuggestedFix:    "Add server-side indexes, optimize payload sizes, or make tool invocation asynchronous.",
				AnalyzerVersion: e.version,
			})
		}
	}
	return findings
}

// 9. POSSIBLE_PARALLELIZATION
func (e *Engine) detectPossibleParallelization(events []apcap.Event) []Finding {
	var findings []Finding
	var consecutiveTools []apcap.Event

	for _, ev := range events {
		if ev.Protocol == apcap.ProtocolTool || ev.Type == apcap.EventMCPToolCall {
			consecutiveTools = append(consecutiveTools, ev)
		} else {
			if len(consecutiveTools) >= 3 {
				var ids []string
				var totalDuration float64
				for _, t := range consecutiveTools {
					ids = append(ids, t.ID)
					totalDuration += t.DurationMs
				}
				findings = append(findings, Finding{
					Type:            "POSSIBLE_PARALLELIZATION",
					Severity:        SeverityLow,
					Confidence:      ConfidenceMedium,
					Title:           fmt.Sprintf("Potential parallelization opportunity (%d sequential tool calls)", len(consecutiveTools)),
					Explanation:     fmt.Sprintf("Detected %d sequential tool calls totaling %.1fms. If inputs are independent, concurrent execution could reduce wall-clock time.", len(consecutiveTools), totalDuration),
					Evidence:        map[string]any{"count": len(consecutiveTools), "serial_duration_ms": totalDuration},
					EventIDs:        ids,
					SuggestedFix:    "Evaluate if tool arguments can be computed concurrently and dispatched via Promise.all / errgroup.",
					AnalyzerVersion: e.version,
				})
			}
			consecutiveTools = nil
		}
	}
	return findings
}

// FormatTerminal returns a formatted report string for CLI.
func FormatTerminal(findings []Finding) string {
	if len(findings) == 0 {
		return "\n✓ No runtime pathologies detected.\n"
	}

	var sb strings.Builder
	sb.WriteString("\nRUNTIME PATHOLOGIES DETECTED\n")
	sb.WriteString("============================\n")

	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("\n%d. [%-6s] %s\n", i+1, f.Severity, f.Title))
		sb.WriteString(fmt.Sprintf("   Explanation:  %s\n", f.Explanation))
		sb.WriteString(fmt.Sprintf("   Suggested:    %s\n", f.SuggestedFix))
		if len(f.EventIDs) > 0 {
			sb.WriteString(fmt.Sprintf("   Event IDs:    %s\n", strings.Join(f.EventIDs, ", ")))
		}
	}
	sb.WriteString("\n")
	return sb.String()
}
