package analyzer_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/analyzer"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestAnalyzer_LargeCaptureScalability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large capture test in short mode")
	}

	counts := []int{10000, 50000}

	for _, count := range counts {
		t.Run(fmt.Sprintf("%d_events", count), func(t *testing.T) {
			events := make([]apcap.Event, count)
			baseTime := time.Now().UTC()

			for i := 0; i < count; i++ {
				proto := apcap.ProtocolModel
				op := "generate"
				kind := "model"
				if i%2 == 0 {
					proto = apcap.ProtocolMCP
					op = "tools/call"
					kind = "tool"
				}

				events[i] = apcap.Event{
					ID:         fmt.Sprintf("ev_%d", i),
					TraceID:    "trace_bulk",
					Timestamp:  baseTime.Add(time.Duration(i) * time.Millisecond),
					DurationMs: float64(1 + (i % 20)),
					Type:       apcap.EventToolCall,
					Protocol:   proto,
					Operation:  op,
					Source:     apcap.Endpoint{Name: "agent-worker", Kind: "agent"},
					Destination: apcap.Endpoint{
						Name: fmt.Sprintf("endpoint_%d", i%10),
						Kind: kind,
					},
					Status: apcap.StatusOK,
					Tokens: &apcap.TokenUsage{
						InputTokens:  10,
						OutputTokens: 5,
						TotalTokens:  15,
					},
					Cost: &apcap.Money{
						Amount: 0.0001,
					},
				}
			}

			start := time.Now()

			// 1. Critical path calculation
			cp := analyzer.AnalyzeCriticalPath(events)
			if cp == nil || cp.TotalWallClockMs <= 0 {
				t.Errorf("critical path calculation failed")
			}

			// 2. Flamegraph generation (Cost)
			flameCost := analyzer.BuildFlamegraph(events, analyzer.FlameModeCost)
			if flameCost == nil {
				t.Errorf("flamegraph cost calculation failed")
			}

			// 3. Flamegraph generation (Tokens)
			flameTokens := analyzer.BuildFlamegraph(events, analyzer.FlameModeTokens)
			if flameTokens == nil {
				t.Errorf("flamegraph tokens calculation failed")
			}

			elapsed := time.Since(start)
			t.Logf("Processed %d events in %v", count, elapsed)
		})
	}
}
