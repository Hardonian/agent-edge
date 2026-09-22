package a2a_test

import (
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/internal/protocols/a2a"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestA2AParser_TaskDispatchAndDelegation(t *testing.T) {
	p := a2a.NewParser()

	rawReq := []byte(`{
		"taskId": "task-99",
		"sourceAgent": "orchestrator",
		"targetAgent": "worker-1",
		"instruction": "analyze dataset",
		"delegation": {
			"depth": 2,
			"initiator": "client",
			"chain": ["client", "orchestrator", "worker-1"]
		}
	}`)

	ev, err := p.ParseTaskRequest(rawReq, "default-src", "default-dst", 15.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Type != apcap.EventDelegation {
		t.Errorf("expected EventDelegation, got %s", ev.Type)
	}
	if ev.Protocol != apcap.ProtocolA2A {
		t.Errorf("expected ProtocolA2A, got %s", ev.Protocol)
	}
	if ev.Source.Name != "orchestrator" {
		t.Errorf("expected source orchestrator, got %s", ev.Source.Name)
	}
	if ev.Destination.Name != "worker-1" {
		t.Errorf("expected destination worker-1, got %s", ev.Destination.Name)
	}
	if ev.Attributes["a2a.delegation_depth"] != 2 {
		t.Errorf("expected delegation depth 2, got %v", ev.Attributes["a2a.delegation_depth"])
	}
	if ev.Attributes["a2a.delegation_chain"] != "client -> orchestrator -> worker-1" {
		t.Errorf("expected formatted chain, got %v", ev.Attributes["a2a.delegation_chain"])
	}
}

func TestA2AParser_TaskResponse(t *testing.T) {
	p := a2a.NewParser()

	// Success response
	rawOk := []byte(`{
		"taskId": "task-99",
		"status": "completed",
		"artifactsCount": 3
	}`)
	evOk, err := p.ParseTaskResponse(rawOk, "worker-1", "orchestrator", 30.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evOk.Type != apcap.EventA2AResponse {
		t.Errorf("expected EventA2AResponse, got %s", evOk.Type)
	}
	if evOk.Status != apcap.StatusOK {
		t.Errorf("expected StatusOK, got %s", evOk.Status)
	}

	// Error response
	rawErr := []byte(`{
		"taskId": "task-99",
		"status": "failed",
		"error": "Out of memory during model fine-tuning"
	}`)
	evErr, err := p.ParseTaskResponse(rawErr, "worker-1", "orchestrator", 45.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evErr.Type != apcap.EventA2AError {
		t.Errorf("expected EventA2AError, got %s", evErr.Type)
	}
	if evErr.Status != apcap.StatusError {
		t.Errorf("expected StatusError, got %s", evErr.Status)
	}
	if evErr.Attributes["a2a.error"] != "Out of memory during model fine-tuning" {
		t.Errorf("expected error attribute, got %v", evErr.Attributes["a2a.error"])
	}
}

func TestA2AParser_TortureInputs(t *testing.T) {
	p := a2a.NewParser()

	tortureCases := []struct {
		name        string
		payload     []byte
		isResponse  bool
		expectError bool
	}{
		{"Empty slice request", []byte{}, false, true},
		{"Empty slice response", []byte{}, true, true},
		{"Non-JSON string", []byte("arbitrary unformatted text"), false, true},
		{"Truncated JSON", []byte(`{"taskId": "123", `), false, true},
		{"Missing taskId request", []byte(`{"instruction": "do something"}`), false, false},
		{"Missing taskId response", []byte(`{"status": "completed"}`), true, false},
		{"Oversized metadata", []byte(`{"taskId": "t1", "instruction": "` + strings.Repeat("X", 50000) + `"}`), false, false},
		{"Unexpected data types in context", []byte(`{"taskId": "t1", "context": {"nested": [1, true, null, {"a": "b"}]}}`), false, false},
		{"HTML in instruction", []byte(`{"taskId": "t1", "instruction": "<script>alert('xss')</script>"}`), false, false},
	}

	for _, tc := range tortureCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.isResponse {
				ev, err := p.ParseTaskResponse(tc.payload, "a1", "a2", 10.0)
				if tc.expectError && err == nil {
					t.Errorf("expected error, got nil")
				}
				if !tc.expectError && err != nil {
					t.Errorf("expected success, got err: %v", err)
				}
				if !tc.expectError && ev == nil {
					t.Errorf("expected event, got nil")
				}
			} else {
				ev, err := p.ParseTaskRequest(tc.payload, "a1", "a2", 10.0)
				if tc.expectError && err == nil {
					t.Errorf("expected error, got nil")
				}
				if !tc.expectError && err != nil {
					t.Errorf("expected success, got err: %v", err)
				}
				if !tc.expectError && ev == nil {
					t.Errorf("expected event, got nil")
				}
			}
		})
	}
}
