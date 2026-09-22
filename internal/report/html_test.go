package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/report"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestGenerateHTMLReport(t *testing.T) {
	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "report.html")

	now := time.Now().UTC()
	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			CaptureID: "cap_report_test",
		},
		Metadata: apcap.CaptureMetadata{
			TotalDurationMs: 1200.0,
			TotalTokens:     apcap.TokenUsage{TotalTokens: 2500},
			TotalCost:       0.045,
			ErrorCount:      1,
		},
		Events: []apcap.Event{
			{
				ID:          "e1",
				Timestamp:   now,
				DurationMs:  400.0,
				Protocol:    apcap.ProtocolModel,
				Operation:   "generate",
				Source:      apcap.Endpoint{Name: "agent-a"},
				Destination: apcap.Endpoint{Name: "gemini"},
				Status:      apcap.StatusOK,
			},
			{
				ID:          "e2",
				Timestamp:   now.Add(400 * time.Millisecond),
				DurationMs:  800.0,
				Protocol:    apcap.ProtocolTool,
				Operation:   "lookup",
				Source:      apcap.Endpoint{Name: "agent-a"},
				Destination: apcap.Endpoint{Name: "db"},
				Status:      apcap.StatusError,
			},
		},
	}

	if err := report.GenerateHTMLReport(cap, outPath); err != nil {
		t.Fatalf("failed generating report: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed reading report: %v", err)
	}
	htmlStr := string(content)

	// Invariant: zero external scripts or remote resource fetches
	if strings.Contains(htmlStr, "<script src=") {
		t.Errorf("report contains external script tag")
	}
	if strings.Contains(htmlStr, "http://") || strings.Contains(htmlStr, "https://") {
		t.Errorf("report contains remote URLs, must be fully self-contained offline HTML")
	}

	// Invariant: contains metrics and capture ID
	if !strings.Contains(htmlStr, "cap_report_test") {
		t.Errorf("report missing capture ID")
	}
	if !strings.Contains(htmlStr, "Agent<span>PCAP</span> Forensic Report") {
		t.Errorf("report missing header brand")
	}
}
