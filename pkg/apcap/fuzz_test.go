package apcap_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func FuzzApcapReader(f *testing.F) {
	// Seed corpus with empty or partial zip data
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04not-a-valid-zip"))
	f.Add([]byte(`{"format":"apcap"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tempDir := t.TempDir()
		p := filepath.Join(tempDir, "fuzz.apcap")
		if err := os.WriteFile(p, data, 0600); err != nil {
			return
		}

		// Reader must NEVER panic on malformed data
		_, _ = apcap.Open(p)
	})
}

func FuzzEventJSONL(f *testing.F) {
	f.Add([]byte(`{"id":"e1","timestamp":"2026-09-04T12:00:00Z","type":"TOOL_CALL","protocol":"MCP","operation":"tools/call","status":"OK"}`))
	f.Add([]byte(`{"id": 123, "duration_ms": -50}`))
	f.Add([]byte(`{"attributes": {"nested": {"a": [1, 2, 3]}}}`))
	f.Add([]byte(`{"tokens": {"total_tokens": 99999999999}}`))
	f.Add([]byte(`\x00\x01\x02`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ev apcap.Event
		_ = json.Unmarshal(data, &ev)
	})
}
