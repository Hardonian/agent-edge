package spec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestSchema_VectorsConformance(t *testing.T) {
	// Read schema file
	schemaPath := filepath.Join("..", "spec", "apcap.schema.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed reading schema: %v", err)
	}

	var schemaMap map[string]any
	if err := json.Unmarshal(schemaData, &schemaMap); err != nil {
		t.Fatalf("invalid json schema: %v", err)
	}

	vectors := []string{"minimal", "mcp", "a2a", "otel", "multi-agent", "errors", "retries", "incomplete"}

	for _, vName := range vectors {
		t.Run(vName, func(t *testing.T) {
			capPath := filepath.Join("..", "spec", "vectors", vName, vName+".apcap")
			cap, err := apcap.Open(capPath)
			if err != nil {
				t.Fatalf("failed opening vector %s: %v", vName, err)
			}

			// Invariants according to spec
			if cap.Manifest.Format != apcap.FormatIdentifier {
				t.Errorf("expected format %s, got %s", apcap.FormatIdentifier, cap.Manifest.Format)
			}
			if cap.Manifest.FormatVersion == "" {
				t.Errorf("manifest missing format_version")
			}
			if len(cap.Events) == 0 {
				t.Errorf("expected at least 1 event in vector %s", vName)
			}

			for i, ev := range cap.Events {
				if ev.ID == "" {
					t.Errorf("event %d missing ID", i)
				}
				if ev.TraceID == "" {
					t.Errorf("event %d missing TraceID", i)
				}
				if ev.Timestamp.IsZero() {
					t.Errorf("event %d missing Timestamp", i)
				}
				if ev.Operation == "" {
					t.Errorf("event %d missing Operation", i)
				}
				if ev.Source.Name == "" || ev.Source.Kind == "" {
					t.Errorf("event %d invalid source endpoint: %+v", i, ev.Source)
				}
				if ev.Destination.Name == "" || ev.Destination.Kind == "" {
					t.Errorf("event %d invalid destination endpoint: %+v", i, ev.Destination)
				}
				if ev.Status == "" {
					t.Errorf("event %d missing status", i)
				}
			}
		})
	}
}
