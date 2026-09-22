package diff

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentpcap/agentpcap/internal/pathology"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// MetricDelta represents a numerical comparison.
type MetricDelta struct {
	Before float64 `json:"before"`
	After  float64 `json:"after"`
	Delta  float64 `json:"delta"`
	Pct    float64 `json:"pct"`
}

// OpDelta tracks changes in call counts for an operation.
type OpDelta struct {
	Operation string `json:"operation"`
	Before    int    `json:"before"`
	After     int    `json:"after"`
	Delta     int    `json:"delta"`
}

// DiffResult encapsulates comparison between two captures.
type DiffResult struct {
	BeforeID    string      `json:"before_id"`
	AfterID     string      `json:"after_id"`
	LatencyMs   MetricDelta `json:"latency_ms"`
	Tokens      MetricDelta `json:"tokens"`
	Cost        MetricDelta `json:"cost"`
	Errors      MetricDelta `json:"errors"`
	ModelCalls  MetricDelta `json:"model_calls"`
	ToolCalls   MetricDelta `json:"tool_calls"`
	Delegations MetricDelta `json:"delegations"`

	ChangedOps []OpDelta `json:"changed_ops"`

	ResolvedPathologies   []string `json:"resolved_pathologies"`
	IntroducedPathologies []string `json:"introduced_pathologies"`
}

// Compare computes differences between two APCAP captures.
func Compare(before, after *apcap.Capture) *DiffResult {
	res := &DiffResult{
		BeforeID: before.Manifest.CaptureID,
		AfterID:  after.Manifest.CaptureID,
	}

	// 1. Duration / Latency
	bDur := before.Metadata.TotalDurationMs
	aDur := after.Metadata.TotalDurationMs
	res.LatencyMs = makeDelta(bDur, aDur)

	// 2. Tokens
	bTok := float64(before.Metadata.TotalTokens.TotalTokens)
	aTok := float64(after.Metadata.TotalTokens.TotalTokens)
	res.Tokens = makeDelta(bTok, aTok)

	// 3. Cost
	bCost := before.Metadata.TotalCost
	aCost := after.Metadata.TotalCost
	res.Cost = makeDelta(bCost, aCost)

	// 4. Errors
	bErr := float64(before.Metadata.ErrorCount)
	aErr := float64(after.Metadata.ErrorCount)
	res.Errors = makeDelta(bErr, aErr)

	// 5. Counts by category & operations
	bOps := make(map[string]int)
	bModel, bTool, bDeleg := 0, 0, 0
	for _, ev := range before.Events {
		bOps[ev.Operation]++
		if ev.Protocol == apcap.ProtocolModel {
			bModel++
		} else if ev.Protocol == apcap.ProtocolTool || ev.Protocol == apcap.ProtocolMCP {
			bTool++
		} else if ev.Type == apcap.EventDelegation {
			bDeleg++
		}
	}

	aOps := make(map[string]int)
	aModel, aTool, aDeleg := 0, 0, 0
	for _, ev := range after.Events {
		aOps[ev.Operation]++
		if ev.Protocol == apcap.ProtocolModel {
			aModel++
		} else if ev.Protocol == apcap.ProtocolTool || ev.Protocol == apcap.ProtocolMCP {
			aTool++
		} else if ev.Type == apcap.EventDelegation {
			aDeleg++
		}
	}

	res.ModelCalls = makeDelta(float64(bModel), float64(aModel))
	res.ToolCalls = makeDelta(float64(bTool), float64(aTool))
	res.Delegations = makeDelta(float64(bDeleg), float64(aDeleg))

	// Changed operations
	allOps := make(map[string]bool)
	for k := range bOps {
		allOps[k] = true
	}
	for k := range aOps {
		allOps[k] = true
	}

	for op := range allOps {
		bc := bOps[op]
		ac := aOps[op]
		if bc != ac {
			res.ChangedOps = append(res.ChangedOps, OpDelta{
				Operation: op,
				Before:    bc,
				After:     ac,
				Delta:     ac - bc,
			})
		}
	}

	// Compare Pathologies
	eng := pathology.NewEngine()
	bFindings := eng.Analyze(before.Events)
	aFindings := eng.Analyze(after.Events)

	bTypes := make(map[string]bool)
	for _, f := range bFindings {
		bTypes[f.Type] = true
	}
	aTypes := make(map[string]bool)
	for _, f := range aFindings {
		aTypes[f.Type] = true
	}

	for t := range bTypes {
		if !aTypes[t] {
			res.ResolvedPathologies = append(res.ResolvedPathologies, t)
		}
	}
	for t := range aTypes {
		if !bTypes[t] {
			res.IntroducedPathologies = append(res.IntroducedPathologies, t)
		}
	}

	return res
}

func makeDelta(before, after float64) MetricDelta {
	delta := after - before
	var pct float64
	if before > 0 {
		pct = (delta / before) * 100.0
	}
	return MetricDelta{
		Before: before,
		After:  after,
		Delta:  delta,
		Pct:    pct,
	}
}

// FormatTerminal outputs the screenshot-worthy text comparison.
func (d *DiffResult) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("\nAGENT RUN DIFF\n")
	sb.WriteString("=========================================================\n")
	sb.WriteString(fmt.Sprintf("%-20s %15s %15s %10s\n", "METRIC", "BEFORE", "AFTER", "CHANGE"))
	sb.WriteString("---------------------------------------------------------\n")

	sb.WriteString(fmt.Sprintf("%-20s %15d %15d %+10d\n", "Model calls", int(d.ModelCalls.Before), int(d.ModelCalls.After), int(d.ModelCalls.Delta)))
	sb.WriteString(fmt.Sprintf("%-20s %15d %15d %+10d\n", "Tool calls", int(d.ToolCalls.Before), int(d.ToolCalls.After), int(d.ToolCalls.Delta)))
	sb.WriteString(fmt.Sprintf("%-20s %15d %15d %+10d\n", "Delegations", int(d.Delegations.Before), int(d.Delegations.After), int(d.Delegations.Delta)))
	sb.WriteString(fmt.Sprintf("%-20s %15d %15d %+10d\n", "Errors", int(d.Errors.Before), int(d.Errors.After), int(d.Errors.Delta)))
	sb.WriteString("---------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("%-20s %14.1fs %14.1fs %+9.1f%%\n", "Latency", d.LatencyMs.Before/1000.0, d.LatencyMs.After/1000.0, d.LatencyMs.Pct))
	sb.WriteString(fmt.Sprintf("%-20s %15d %15d %+9.1f%%\n", "Tokens", int(d.Tokens.Before), int(d.Tokens.After), d.Tokens.Pct))
	sb.WriteString(fmt.Sprintf("%-20s %14.4f$ %14.4f$ %+9.1f%%\n", "Cost", d.Cost.Before, d.Cost.After, d.Cost.Pct))
	sb.WriteString("=========================================================\n")

	if len(d.ChangedOps) > 0 {
		sb.WriteString("\nCHANGED OPERATIONS:\n")
		for _, op := range d.ChangedOps {
			sign := "+"
			if op.Delta < 0 {
				sign = "-"
			}
			sb.WriteString(fmt.Sprintf("  %s %-35s (before: %d, after: %d)\n", sign, op.Operation, op.Before, op.After))
		}
	}

	if len(d.ResolvedPathologies) > 0 {
		sb.WriteString("\nRESOLVED PATHOLOGIES:\n")
		for _, p := range d.ResolvedPathologies {
			sb.WriteString(fmt.Sprintf("  ✓ %s resolved\n", p))
		}
	}

	if len(d.IntroducedPathologies) > 0 {
		sb.WriteString("\nNEW PATHOLOGIES INTRODUCED:\n")
		for _, p := range d.IntroducedPathologies {
			sb.WriteString(fmt.Sprintf("  ⚠ %s introduced\n", p))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// ToJSON formats result as JSON.
func (d *DiffResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
