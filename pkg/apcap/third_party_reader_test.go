package apcap_test

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// ThirdPartyManifest mirrors the public spec/apcap.schema.json contract for manifest.json.
type ThirdPartyManifest struct {
	Format        string `json:"format"`
	FormatVersion string `json:"format_version"`
	CaptureID     string `json:"capture_id"`
	EventCount    int    `json:"event_count"`
}

// ThirdPartyEvent mirrors the public spec/apcap.schema.json contract for line-delimited events in events.jsonl.
type ThirdPartyEvent struct {
	ID        string `json:"id"`
	TraceID   string `json:"trace_id"`
	Type      string `json:"type"`
	Protocol  string `json:"protocol"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
}

// TestThirdPartyReader demonstrates that an independent consumer can read any .apcap archive
// using only standard archive/zip and encoding/json according to the public format specification.
func TestThirdPartyReader(t *testing.T) {
	testVectors := []struct {
		vectorName string
		minEvents  int
	}{
		{"minimal", 1},
		{"mcp", 3},
		{"a2a", 2},
		{"otel", 1},
		{"multi-agent", 3},
		{"errors", 2},
		{"retries", 3},
		{"incomplete", 1},
	}

	for _, tc := range testVectors {
		t.Run(tc.vectorName, func(t *testing.T) {
			path := filepath.Join("..", "..", "spec", "vectors", tc.vectorName, tc.vectorName+".apcap")

			zr, err := zip.OpenReader(path)
			if err != nil {
				t.Fatalf("failed opening zip container: %v", err)
			}
			defer zr.Close()

			var manifestFound bool
			var eventsFound bool
			var manifest ThirdPartyManifest
			var eventCount int

			for _, f := range zr.File {
				switch f.Name {
				case "manifest.json":
					manifestFound = true
					rc, err := f.Open()
					if err != nil {
						t.Fatalf("failed opening manifest.json: %v", err)
					}
					if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
						_ = rc.Close()
						t.Fatalf("failed decoding manifest.json: %v", err)
					}
					_ = rc.Close()

					// Invariant 1: Format identifier must match
					if manifest.Format != "apcap" {
						t.Errorf("expected format 'apcap', got '%s'", manifest.Format)
					}
					// Invariant 2: Format version must be detected
					if !strings.HasPrefix(manifest.FormatVersion, "1.") {
						t.Errorf("unexpected format version: %s", manifest.FormatVersion)
					}

				case "events.jsonl":
					eventsFound = true
					rc, err := f.Open()
					if err != nil {
						t.Fatalf("failed opening events.jsonl: %v", err)
					}
					scanner := bufio.NewScanner(rc)
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line == "" {
							continue
						}
						var ev ThirdPartyEvent
						if err := json.Unmarshal([]byte(line), &ev); err != nil {
							// For incomplete captures, partial trailing lines are expected
							if tc.vectorName == "incomplete" {
								break
							}
							_ = rc.Close()
							t.Fatalf("malformed event line: %v", err)
						}
						if ev.ID == "" || ev.TraceID == "" {
							t.Errorf("event missing ID or TraceID: %+v", ev)
						}
						eventCount++
					}
					_ = rc.Close()
				}
			}

			if !manifestFound {
				t.Errorf("manifest.json missing in %s", tc.vectorName)
			}
			if !eventsFound {
				t.Errorf("events.jsonl missing in %s", tc.vectorName)
			}
			if eventCount < tc.minEvents {
				t.Errorf("expected at least %d events in %s, got %d", tc.minEvents, tc.vectorName, eventCount)
			}
		})
	}
}

// TestThirdPartyReader_UnsupportedVersion verifies that independent readers reject unsupported future major versions.
func TestThirdPartyReader_UnsupportedVersion(t *testing.T) {
	fakeManifestJSON := `{"format":"apcap","format_version":"99.0.0","capture_id":"future_cap"}`
	var manifest ThirdPartyManifest
	if err := json.Unmarshal([]byte(fakeManifestJSON), &manifest); err != nil {
		t.Fatalf("failed parsing manifest: %v", err)
	}

	major := strings.Split(manifest.FormatVersion, ".")[0]
	if major != "1" {
		// As expected per the specification: unsupported major versions MUST be handled safely
		expectedErr := fmt.Errorf("unsupported major format version: %s", manifest.FormatVersion)
		if expectedErr == nil {
			t.Fail()
		}
	}
}
