package apcap_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestCrashRecovery_PartialCaptureFile(t *testing.T) {
	tempDir := t.TempDir()
	crashPath := filepath.Join(tempDir, "crash_recovery.apcap")

	// Simulate a process crash mid-capture:
	// 1. Manifest was written at start (no completed_at, no events.jsonl hash yet)
	// 2. events.jsonl wrote 3 full events, and crashed while writing event 4
	f, err := os.Create(crashPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)

	// Incomplete manifest written at capture initiation
	mw, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = mw.Write([]byte(`{
		"format": "apcap",
		"format_version": "1.0.0",
		"capture_id": "cap_interrupted_001",
		"created_at": "2026-09-04T12:00:00Z",
		"agentpcap_version": "1.0.0",
		"capture_mode": "child_process",
		"redaction_mode": "metadata_only",
		"protocols_seen": ["MCP", "MODEL"],
		"event_count": 0,
		"hashes": {}
	}`))

	// Interrupted events stream with valid initial lines and partial trailing line
	ew, err := zw.Create("events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ew.Write([]byte(`{"id":"ev_1","trace_id":"tr_1","timestamp":"2026-09-04T12:00:01Z","duration_ms":10,"type":"AGENT_START","protocol":"A2A","operation":"start","source":{"name":"orch","kind":"agent"},"destination":{"name":"agent-1","kind":"agent"},"status":"OK","provenance":"OBSERVED"}` + "\n"))
	_, _ = ew.Write([]byte(`{"id":"ev_2","trace_id":"tr_1","timestamp":"2026-09-04T12:00:02Z","duration_ms":25,"type":"MCP_TOOL_CALL","protocol":"MCP","operation":"tools/call","source":{"name":"agent-1","kind":"agent"},"destination":{"name":"tool-1","kind":"mcp_server"},"status":"OK","provenance":"OBSERVED"}` + "\n"))
	_, _ = ew.Write([]byte(`{"id":"ev_3","trace_id":"tr_1","timestamp":"2026-09-04T12:00:03Z","duration_ms":50,"type":"MODEL_RESPONSE","protocol":"MODEL","operation":"chat","source":{"name":"agent-1","kind":"agent"},"destination":{"name":"gemini","kind":"model"},"status":"OK","provenance":"OBSERVED"}` + "\n"))
	// Partial trailing truncated JSON (SIGKILL simulated)
	_, _ = ew.Write([]byte(`{"id":"ev_4","trace_id":"tr_1","timestamp":"2026-09-04T12:00:04Z","duration_ms":`))

	_ = zw.Close()
	_ = f.Close()

	// Open the crashed capture
	cap, err := apcap.Open(crashPath)
	if err != nil {
		t.Fatalf("crash recovery failed: %v", err)
	}

	// Verification:
	// 1. Should successfully recover all 3 valid events
	if len(cap.Events) != 3 {
		t.Fatalf("expected 3 recovered events, got %d", len(cap.Events))
	}
	if cap.Events[0].ID != "ev_1" || cap.Events[1].ID != "ev_2" || cap.Events[2].ID != "ev_3" {
		t.Errorf("unexpected event sequence: %+v", cap.Events)
	}

	// 2. Capture is identified as unfinalized (completed_at is zero)
	if !cap.Manifest.CompletedAt.IsZero() {
		t.Errorf("expected zero CompletedAt for incomplete capture")
	}
}
