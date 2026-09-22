package apcap_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	capPath := filepath.Join(tempDir, "test.apcap")

	w, err := apcap.NewWriter(capPath, apcap.WriterOptions{
		CaptureID:     "cap_test_123",
		CaptureMode:   "proxy",
		RedactionMode: "metadata_only",
		Title:         "Test Capture",
		Description:   "A test capture for roundtrip",
	})
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	event1 := apcap.Event{
		ID:          "ev_1",
		TraceID:     "tr_1",
		Timestamp:   now,
		DurationMs:  15.5,
		Type:        apcap.EventA2ARequest,
		Protocol:    apcap.ProtocolA2A,
		Operation:   "task/create",
		Source:      apcap.Endpoint{Name: "agent-a", Kind: "agent"},
		Destination: apcap.Endpoint{Name: "agent-b", Kind: "agent"},
		Status:      apcap.StatusOK,
		Tokens: &apcap.TokenUsage{
			InputTokens:  100,
			OutputTokens: 50,
			TotalTokens:  150,
		},
		Cost: &apcap.Money{
			Amount:   0.0005,
			Currency: "USD",
			Status:   apcap.CostStatusEstimated,
		},
		Provenance: apcap.ProvenanceProtocolParsed,
	}

	event2 := apcap.Event{
		ID:          "ev_2",
		TraceID:     "tr_1",
		ParentID:    "ev_1",
		Timestamp:   now.Add(16 * time.Millisecond),
		DurationMs:  42.0,
		Type:        apcap.EventMCPToolCall,
		Protocol:    apcap.ProtocolMCP,
		Operation:   "tools/call",
		Source:      apcap.Endpoint{Name: "agent-b", Kind: "agent"},
		Destination: apcap.Endpoint{Name: "mcp-analytics", Kind: "mcp_server"},
		Status:      apcap.StatusOK,
		Provenance:  apcap.ProvenanceProtocolParsed,
	}

	w.WriteEvent(event1)
	w.WriteEvent(event2)

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	// Verify file exists
	fi, err := os.Stat(capPath)
	if err != nil {
		t.Fatalf("file not found: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("capture file is empty")
	}

	// Read back
	cap, err := apcap.Open(capPath)
	if err != nil {
		t.Fatalf("failed to open capture: %v", err)
	}

	if cap.Manifest.Format != apcap.FormatIdentifier {
		t.Errorf("expected format %s, got %s", apcap.FormatIdentifier, cap.Manifest.Format)
	}
	if cap.Manifest.CaptureID != "cap_test_123" {
		t.Errorf("expected capture_id cap_test_123, got %s", cap.Manifest.CaptureID)
	}
	if len(cap.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(cap.Events))
	}
	if cap.Events[0].ID != "ev_1" || cap.Events[1].ID != "ev_2" {
		t.Errorf("event IDs mismatch: %+v", cap.Events)
	}
	if cap.Metadata.TotalTokens.TotalTokens != 150 {
		t.Errorf("expected 150 total tokens, got %d", cap.Metadata.TotalTokens.TotalTokens)
	}
	if cap.Metadata.AgentCount != 2 {
		t.Errorf("expected 2 agents in metadata, got %d", cap.Metadata.AgentCount)
	}
}

func TestHostileZipSlip(t *testing.T) {
	tempDir := t.TempDir()
	maliciousPath := filepath.Join(tempDir, "zipslip.apcap")

	f, err := os.Create(maliciousPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	// Add malicious entry
	w, err := zw.Create("../../../../../../../../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))

	_ = zw.Close()
	_ = f.Close()

	_, err = apcap.Open(maliciousPath)
	if err == nil {
		t.Fatal("expected error for zip slip attempt, got nil")
	}
	if !containsError(err, apcap.ErrPathTraversal) {
		t.Errorf("expected ErrPathTraversal, got: %v", err)
	}
}

func TestHostileWindowsPathTraversal(t *testing.T) {
	tempDir := t.TempDir()
	maliciousPath := filepath.Join(tempDir, "win_traversal.apcap")

	f, err := os.Create(maliciousPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	w, err := zw.Create(`C:\Windows\System32\cmd.exe`)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("evil"))

	_ = zw.Close()
	_ = f.Close()

	_, err = apcap.Open(maliciousPath)
	if err == nil {
		t.Fatal("expected error for Windows absolute path traversal, got nil")
	}
	if !containsError(err, apcap.ErrPathTraversal) {
		t.Errorf("expected ErrPathTraversal, got: %v", err)
	}
}

func TestDecompressionBombDefense(t *testing.T) {
	tempDir := t.TempDir()
	bombPath := filepath.Join(tempDir, "bomb.apcap")

	f, err := os.Create(bombPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	// Write valid manifest
	mw, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"1.0.0","capture_id":"c1","hashes":{}}`))

	// Write massive events file using repetitive compressed bytes (a zip bomb)
	ew, err := zw.Create("events.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	// 100MB of zeroes compresses to very few bytes but decompresses past limit when repeated
	zeroes := make([]byte, 1024*1024)
	for i := 0; i < 300; i++ { // 300MB uncompressed exceeds MaxUncompressedBytes (256MB)
		if _, err := ew.Write(zeroes); err != nil {
			break
		}
	}

	_ = zw.Close()
	_ = f.Close()

	_, err = apcap.Open(bombPath)
	if err == nil {
		t.Fatal("expected decompression bomb error, got nil")
	}
	if !containsError(err, apcap.ErrDecompressionBomb) {
		t.Errorf("expected ErrDecompressionBomb, got: %v", err)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "future.apcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	mw, _ := zw.Create("manifest.json")
	_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"99.0.0","capture_id":"future"}`))

	ew, _ := zw.Create("events.jsonl")
	_, _ = ew.Write([]byte("{}\n"))

	_ = zw.Close()
	_ = f.Close()

	_, err = apcap.Open(path)
	if err == nil {
		t.Fatal("expected error on future major version, got nil")
	}
	if !containsError(err, apcap.ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion, got: %v", err)
	}
}

func containsError(err, target error) bool {
	if err == nil || target == nil {
		return false
	}
	return bytes.Contains([]byte(err.Error()), []byte(target.Error()))
}
