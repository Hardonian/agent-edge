package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// CriticalPathStep details one step on the execution critical path.
type CriticalPathStep struct {
	EventID        string  `json:"event_id"`
	Operation      string  `json:"operation"`
	Protocol       string  `json:"protocol"`
	DurationMs     float64 `json:"duration_ms"`
	PercentOfTotal float64 `json:"percent_of_total"`
	Status         string  `json:"status"`
}

// CriticalPathReport summarizes the execution bottleneck.
type CriticalPathReport struct {
	TotalWallClockMs float64            `json:"total_wall_clock_ms"`
	DominantEvent    CriticalPathStep   `json:"dominant_event"`
	Steps            []CriticalPathStep `json:"steps"`
	BottleneckType   string             `json:"bottleneck_type"` // e.g. "MODEL_LATENCY", "TOOL_LATENCY", "RETRY_DELAY"
	Summary          string             `json:"summary"`
}

// AnalyzeCriticalPath computes the longest duration path and identifies wall-clock bottlenecks.
func AnalyzeCriticalPath(events []apcap.Event) *CriticalPathReport {
	if len(events) == 0 {
		return &CriticalPathReport{
			Summary: "No events recorded in capture.",
		}
	}

	// Calculate total wall-clock duration
	minStart := events[0].Timestamp
	maxEnd := events[0].Timestamp.Add(floatToDuration(events[0].DurationMs))

	for _, ev := range events {
		if ev.Timestamp.Before(minStart) {
			minStart = ev.Timestamp
		}
		end := ev.Timestamp.Add(floatToDuration(ev.DurationMs))
		if end.After(maxEnd) {
			maxEnd = end
		}
	}
	wallClockMs := float64(maxEnd.Sub(minStart).Milliseconds())
	if wallClockMs <= 0 {
		wallClockMs = 1.0
	}

	// Sort events by duration descending to find dominant components
	sortedEvents := make([]apcap.Event, len(events))
	copy(sortedEvents, events)
	sort.Slice(sortedEvents, func(i, j int) bool {
		return sortedEvents[i].DurationMs > sortedEvents[j].DurationMs
	})

	var steps []CriticalPathStep
	limit := 5
	if len(sortedEvents) < limit {
		limit = len(sortedEvents)
	}

	for i := 0; i < limit; i++ {
		ev := sortedEvents[i]
		pct := (ev.DurationMs / wallClockMs) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
		steps = append(steps, CriticalPathStep{
			EventID:        ev.ID,
			Operation:      ev.Operation,
			Protocol:       string(ev.Protocol),
			DurationMs:     ev.DurationMs,
			PercentOfTotal: pct,
			Status:         string(ev.Status),
		})
	}

	dominant := steps[0]
	bottleneckType := "GENERAL"
	if dominant.Protocol == string(apcap.ProtocolModel) {
		bottleneckType = "MODEL_INFERENCE_LATENCY"
	} else if dominant.Protocol == string(apcap.ProtocolTool) || dominant.Protocol == string(apcap.ProtocolMCP) {
		bottleneckType = "TOOL_EXECUTION_LATENCY"
	}

	summary := fmt.Sprintf("Critical path dominated by %s (%s) taking %.1fms (%.1f%% of total run).",
		dominant.Operation, dominant.Protocol, dominant.DurationMs, dominant.PercentOfTotal)

	return &CriticalPathReport{
		TotalWallClockMs: wallClockMs,
		DominantEvent:    dominant,
		Steps:            steps,
		BottleneckType:   bottleneckType,
		Summary:          summary,
	}
}

func floatToDuration(ms float64) time.Duration {
	return time.Duration(ms * float64(time.Millisecond))
}

// FormatTerminal outputs a clean ASCII representation of the critical path.
func (r *CriticalPathReport) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("\nCRITICAL PATH ANALYSIS\n")
	sb.WriteString("======================\n")
	sb.WriteString(fmt.Sprintf("Total Wall Clock: %.2f ms\n", r.TotalWallClockMs))
	sb.WriteString(fmt.Sprintf("Primary Bottleneck: %s\n", r.BottleneckType))
	sb.WriteString(fmt.Sprintf("%s\n\n", r.Summary))

	sb.WriteString("LONGEST OPERATIONS:\n")
	for i, s := range r.Steps {
		sb.WriteString(fmt.Sprintf("  %d. [%-5s] %-30s %.1fms (%.1f%%)\n",
			i+1, s.Protocol, s.Operation, s.DurationMs, s.PercentOfTotal))
	}
	return sb.String()
}
