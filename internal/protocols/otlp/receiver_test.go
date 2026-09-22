package otlp_test

import (
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/cost"
	"github.com/agentpcap/agentpcap/internal/protocols/otlp"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestOTLPReceiver_StandardGenAITrace(t *testing.T) {
	ce := cost.NewEngine()
	rec := otlp.NewReceiver(ce)

	sampleJSON := []byte(`{
		"resourceSpans": [{
			"resource": {
				"attributes": [
					{"key": "service.name", "value": {"stringValue": "research-agent"}}
				]
			},
			"scopeSpans": [{
				"spans": [{
					"traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
					"spanId": "00f067aa0ba902b7",
					"name": "chat gemini-1.5-pro",
					"kind": 3,
					"startTimeUnixNano": "1700000000000000000",
					"endTimeUnixNano": "1700000001500000000",
					"attributes": [
						{"key": "gen_ai.system", "value": {"stringValue": "google"}},
						{"key": "gen_ai.request.model", "value": {"stringValue": "gemini-1.5-pro"}},
						{"key": "gen_ai.usage.input_tokens", "value": {"intValue": "1500"}},
						{"key": "gen_ai.usage.output_tokens", "value": {"intValue": "500"}}
					],
					"status": {"code": 1}
				}]
			}]
		}]
	}`)

	events, err := rec.ParseTracesJSON(sampleJSON)
	if err != nil {
		t.Fatalf("unexpected error parsing OTLP: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Protocol != apcap.ProtocolModel {
		t.Errorf("expected ProtocolModel, got %v", ev.Protocol)
	}
	if ev.Source.Name != "research-agent" {
		t.Errorf("expected source research-agent, got %s", ev.Source.Name)
	}
	if ev.Destination.Name != "gemini-1.5-pro" {
		t.Errorf("expected destination gemini-1.5-pro, got %s", ev.Destination.Name)
	}
	if ev.DurationMs != 1500.0 {
		t.Errorf("expected duration 1500ms, got %f", ev.DurationMs)
	}
	if ev.Tokens == nil || ev.Tokens.TotalTokens != 2000 {
		t.Errorf("expected 2000 total tokens, got %+v", ev.Tokens)
	}
	if ev.Cost == nil || ev.Cost.Amount <= 0 {
		t.Errorf("expected estimated cost, got %+v", ev.Cost)
	}
}

func TestOTLPReceiver_ErrorStatus(t *testing.T) {
	rec := otlp.NewReceiver(nil)

	errJSON := []byte(`{
		"resourceSpans": [{
			"scopeSpans": [{
				"spans": [{
					"traceId": "t1",
					"spanId": "s1",
					"name": "agent.call",
					"startTimeUnixNano": "1700000000000000000",
					"endTimeUnixNano": "1700000000100000000",
					"status": {"code": 2, "message": "Connection refused"}
				}]
			}]
		}]
	}`)

	events, err := rec.ParseTracesJSON(errJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Status != apcap.StatusError {
		t.Errorf("expected StatusError for code 2, got %v", events[0].Status)
	}
}

func TestOTLPReceiver_TortureInputs(t *testing.T) {
	rec := otlp.NewReceiver(nil)

	tortureCases := []struct {
		name        string
		body        []byte
		expectError bool
		expectCount int
	}{
		{"Empty body", []byte{}, true, 0},
		{"Malformed JSON", []byte(`{"resourceSpans": [`), true, 0},
		{"Empty resourceSpans array", []byte(`{"resourceSpans": []}`), false, 0},
		{"Empty spans array", []byte(`{"resourceSpans": [{"scopeSpans": [{"spans": []}]}]}`), false, 0},
		{"Missing startTime", []byte(`{"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "test"}]}]}]}`), false, 1},
		{"Clock skew (end before start)", []byte(`{
			"resourceSpans": [{
				"scopeSpans": [{
					"spans": [{
						"name": "skewed",
						"startTimeUnixNano": "2000000000000000000",
						"endTimeUnixNano": "1000000000000000000"
					}]
				}]
			}]
		}`), false, 1},
		{"Mixed attribute types", []byte(`{
			"resourceSpans": [{
				"scopeSpans": [{
					"spans": [{
						"name": "mixed",
						"startTimeUnixNano": "1000",
						"endTimeUnixNano": "2000",
						"attributes": [
							{"key": "str", "value": {"stringValue": "val"}},
							{"key": "int", "value": {"intValue": "123"}},
							{"key": "dbl", "value": {"doubleValue": 45.67}},
							{"key": "bool", "value": {"boolValue": true}}
						]
					}]
				}]
			}]
		}`), false, 1},
	}

	for _, tc := range tortureCases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := rec.ParseTracesJSON(tc.body)
			if tc.expectError && err == nil {
				t.Errorf("expected error for case %q, got nil", tc.name)
			}
			if !tc.expectError && err != nil {
				t.Errorf("expected success for case %q, got err: %v", tc.name, err)
			}
			if !tc.expectError && len(evs) != tc.expectCount {
				t.Errorf("expected %d events, got %d", tc.expectCount, len(evs))
			}
		})
	}
}

func TestOTLPExporter(t *testing.T) {
	now := time.Now().UTC()
	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			CaptureID: "cap_export_test",
		},
		Events: []apcap.Event{
			{
				ID:         "ev_test_1",
				TraceID:    "trace_test_1",
				Timestamp:  now,
				DurationMs: 100.0,
				Type:       apcap.EventModelResponse,
				Protocol:   apcap.ProtocolModel,
				Operation:  "chat",
				Source:     apcap.Endpoint{Name: "agent-a", Kind: "agent"},
				Status:     apcap.StatusOK,
			},
		},
	}

	b, err := otlp.ExportCaptureToOTLP(cap)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("exported OTLP JSON is empty")
	}

	// Re-ingest the exported JSON with receiver to verify roundtrip
	rec := otlp.NewReceiver(nil)
	evs, err := rec.ParseTracesJSON(b)
	if err != nil {
		t.Fatalf("failed re-parsing exported OTLP: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 re-parsed event, got %d", len(evs))
	}
}
