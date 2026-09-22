package spec_test

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// TestGenerateCanonicalVectors creates and validates the 6 public canonical test vectors in spec/vectors/.
func TestGenerateCanonicalVectors(t *testing.T) {
	vectorsDir := filepath.Join("..", "spec", "vectors")
	if err := os.MkdirAll(vectorsDir, 0755); err != nil {
		t.Fatalf("failed creating vectors dir: %v", err)
	}

	baseTime, _ := time.Parse(time.RFC3339, "2026-09-04T12:00:00Z")

	// 1. MINIMAL VECTOR
	generateMinimalVector(t, vectorsDir, baseTime)

	// 2. MCP VECTOR
	generateMCPVector(t, vectorsDir, baseTime)

	// 3. A2A VECTOR
	generateA2AVector(t, vectorsDir, baseTime)

	// 4. MULTI-AGENT VECTOR
	generateMultiAgentVector(t, vectorsDir, baseTime)

	// 5. ERRORS VECTOR
	generateErrorsVector(t, vectorsDir, baseTime)

	// 6. INCOMPLETE VECTOR
	generateIncompleteVector(t, vectorsDir, baseTime)

	// 7. OTEL VECTOR
	generateOTELVector(t, vectorsDir, baseTime)

	// 8. RETRIES VECTOR
	generateRetriesVector(t, vectorsDir, baseTime)
}

func generateMinimalVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "minimal")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "minimal.apcap")

	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_minimal",
			CaptureMode:   "simulation",
			RedactionMode: "metadata_only",
			CreatedAt:     baseTime,
			CompletedAt:   baseTime.Add(10 * time.Millisecond),
		},
		Metadata: apcap.CaptureMetadata{
			Title: "Minimal Single-Event Vector",
		},
		Events: []apcap.Event{
			{
				ID:          "ev_001",
				TraceID:     "tr_001",
				Timestamp:   baseTime,
				DurationMs:  10.0,
				Type:        apcap.EventAgentInvoke,
				Protocol:    apcap.ProtocolA2A,
				Operation:   "ping",
				Source:      apcap.Endpoint{Name: "client", Kind: "client"},
				Destination: apcap.Endpoint{Name: "agent-echo", Kind: "agent"},
				Status:      apcap.StatusOK,
				Provenance:  apcap.ProvenanceObserved,
			},
		},
	}

	if err := apcap.Save(capPath, cap); err != nil {
		t.Fatalf("failed saving minimal vector: %v", err)
	}
	saveExpectedJSON(t, vDir, cap)
}

func generateMCPVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "mcp")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "mcp.apcap")

	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_mcp",
			CaptureMode:   "simulation",
			RedactionMode: "metadata_only",
			CreatedAt:     baseTime,
			CompletedAt:   baseTime.Add(100 * time.Millisecond),
		},
		Metadata: apcap.CaptureMetadata{
			Title: "MCP Tool Call & Discovery Vector",
		},
		Events: []apcap.Event{
			{
				ID:          "mcp_01",
				TraceID:     "tr_mcp",
				Timestamp:   baseTime,
				DurationMs:  20.0,
				Type:        apcap.EventMCPToolsList,
				Protocol:    apcap.ProtocolMCP,
				Operation:   "tools/list",
				Source:      apcap.Endpoint{Name: "researcher", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "db-server", Kind: "mcp_server"},
				Status:      apcap.StatusOK,
				Attributes:  map[string]any{"mcp.tool_count": 3},
				Provenance:  apcap.ProvenanceProtocolParsed,
			},
			{
				ID:          "mcp_02",
				TraceID:     "tr_mcp",
				ParentID:    "mcp_01",
				Timestamp:   baseTime.Add(25 * time.Millisecond),
				DurationMs:  45.0,
				Type:        apcap.EventMCPToolCall,
				Protocol:    apcap.ProtocolMCP,
				Operation:   "tools/call:query_records",
				Source:      apcap.Endpoint{Name: "researcher", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "db-server", Kind: "mcp_server"},
				Status:      apcap.StatusOK,
				Attributes:  map[string]any{"tool.name": "query_records", "tool.args_hash": "a1b2c3d4"},
				Provenance:  apcap.ProvenanceProtocolParsed,
			},
			{
				ID:          "mcp_03",
				TraceID:     "tr_mcp",
				ParentID:    "mcp_02",
				Timestamp:   baseTime.Add(75 * time.Millisecond),
				DurationMs:  15.0,
				Type:        apcap.EventMCPToolResult,
				Protocol:    apcap.ProtocolMCP,
				Operation:   "tools/result:query_records",
				Source:      apcap.Endpoint{Name: "db-server", Kind: "mcp_server"},
				Destination: apcap.Endpoint{Name: "researcher", Kind: "agent"},
				Status:      apcap.StatusOK,
				Attributes:  map[string]any{"result_count": 12},
				Provenance:  apcap.ProvenanceProtocolParsed,
			},
		},
	}

	if err := apcap.Save(capPath, cap); err != nil {
		t.Fatalf("failed saving mcp vector: %v", err)
	}
	saveExpectedJSON(t, vDir, cap)
}

func generateA2AVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "a2a")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "a2a.apcap")

	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_a2a",
			CaptureMode:   "simulation",
			RedactionMode: "metadata_only",
			CreatedAt:     baseTime,
			CompletedAt:   baseTime.Add(80 * time.Millisecond),
		},
		Metadata: apcap.CaptureMetadata{
			Title: "Agent-to-Agent Delegation Vector",
		},
		Events: []apcap.Event{
			{
				ID:          "a2a_01",
				TraceID:     "tr_a2a",
				Timestamp:   baseTime,
				DurationMs:  30.0,
				Type:        apcap.EventDelegation,
				Protocol:    apcap.ProtocolA2A,
				Operation:   "task/delegate",
				Source:      apcap.Endpoint{Name: "orchestrator", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "summarizer", Kind: "agent"},
				Status:      apcap.StatusOK,
				Attributes: map[string]any{
					"a2a.delegation_depth": 1,
					"a2a.delegation_chain": "orchestrator -> summarizer",
					"a2a.task_id":          "task_sum_01",
				},
				Provenance: apcap.ProvenanceProtocolParsed,
			},
			{
				ID:          "a2a_02",
				TraceID:     "tr_a2a",
				ParentID:    "a2a_01",
				Timestamp:   baseTime.Add(35 * time.Millisecond),
				DurationMs:  40.0,
				Type:        apcap.EventA2AResponse,
				Protocol:    apcap.ProtocolA2A,
				Operation:   "task/result",
				Source:      apcap.Endpoint{Name: "summarizer", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "orchestrator", Kind: "agent"},
				Status:      apcap.StatusOK,
				Attributes: map[string]any{
					"a2a.status":  "completed",
					"a2a.task_id": "task_sum_01",
				},
				Provenance: apcap.ProvenanceProtocolParsed,
			},
		},
	}

	if err := apcap.Save(capPath, cap); err != nil {
		t.Fatalf("failed saving a2a vector: %v", err)
	}
	saveExpectedJSON(t, vDir, cap)
}

func generateMultiAgentVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "multi-agent")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "multi-agent.apcap")

	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_multi_agent",
			CaptureMode:   "simulation",
			RedactionMode: "metadata_only",
			CreatedAt:     baseTime,
			CompletedAt:   baseTime.Add(500 * time.Millisecond),
		},
		Metadata: apcap.CaptureMetadata{
			Title: "Multi-Agent Research & Procurement Flow",
		},
		Events: []apcap.Event{
			{
				ID:          "ma_01",
				TraceID:     "tr_ma",
				Timestamp:   baseTime,
				DurationMs:  25.0,
				Type:        apcap.EventA2ARequest,
				Protocol:    apcap.ProtocolA2A,
				Operation:   "task/dispatch",
				Source:      apcap.Endpoint{Name: "planner", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "researcher", Kind: "agent"},
				Status:      apcap.StatusOK,
				Provenance:  apcap.ProvenanceObserved,
			},
			{
				ID:          "ma_02",
				TraceID:     "tr_ma",
				ParentID:    "ma_01",
				Timestamp:   baseTime.Add(30 * time.Millisecond),
				DurationMs:  300.0,
				Type:        apcap.EventModelResponse,
				Protocol:    apcap.ProtocolModel,
				Operation:   "gemini:gemini-1.5-pro",
				Source:      apcap.Endpoint{Name: "researcher", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "gemini-1.5-pro", Kind: "model"},
				Status:      apcap.StatusOK,
				Tokens: &apcap.TokenUsage{
					InputTokens:  1200,
					OutputTokens: 350,
					TotalTokens:  1550,
				},
				Cost: &apcap.Money{
					Amount:   0.0035,
					Currency: "USD",
					Status:   apcap.CostStatusEstimated,
				},
				Provenance: apcap.ProvenanceProtocolParsed,
			},
			{
				ID:          "ma_03",
				TraceID:     "tr_ma",
				ParentID:    "ma_02",
				Timestamp:   baseTime.Add(340 * time.Millisecond),
				DurationMs:  80.0,
				Type:        apcap.EventToolCall,
				Protocol:    apcap.ProtocolTool,
				Operation:   "tool:store_findings",
				Source:      apcap.Endpoint{Name: "researcher", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "storage-system", Kind: "tool"},
				Status:      apcap.StatusOK,
				Provenance:  apcap.ProvenanceObserved,
			},
		},
	}

	if err := apcap.Save(capPath, cap); err != nil {
		t.Fatalf("failed saving multi-agent vector: %v", err)
	}
	saveExpectedJSON(t, vDir, cap)
}

func generateErrorsVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "errors")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "errors.apcap")

	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_errors",
			CaptureMode:   "simulation",
			RedactionMode: "metadata_only",
			CreatedAt:     baseTime,
			CompletedAt:   baseTime.Add(250 * time.Millisecond),
		},
		Metadata: apcap.CaptureMetadata{
			Title: "Error & Retry Storm Vector",
		},
		Events: []apcap.Event{
			{
				ID:          "err_01",
				TraceID:     "tr_err",
				Timestamp:   baseTime,
				DurationMs:  50.0,
				Type:        apcap.EventMCPToolCall,
				Protocol:    apcap.ProtocolMCP,
				Operation:   "tools/call:fetch_rate",
				Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "rate-service", Kind: "mcp_server"},
				Status:      apcap.StatusError,
				Attributes: map[string]any{
					"mcp.error_message": "Service unavailable (503)",
				},
				Provenance: apcap.ProvenanceProtocolParsed,
			},
			{
				ID:          "err_02",
				TraceID:     "tr_err",
				Timestamp:   baseTime.Add(60 * time.Millisecond),
				DurationMs:  80.0,
				Type:        apcap.EventRetry,
				Protocol:    apcap.ProtocolMCP,
				Operation:   "tools/call:fetch_rate",
				Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "rate-service", Kind: "mcp_server"},
				Status:      apcap.StatusError,
				Attributes: map[string]any{
					"mcp.error_message": "Connection timeout",
				},
				Provenance: apcap.ProvenanceProtocolParsed,
			},
		},
	}

	if err := apcap.Save(capPath, cap); err != nil {
		t.Fatalf("failed saving errors vector: %v", err)
	}
	saveExpectedJSON(t, vDir, cap)
}

func generateIncompleteVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "incomplete")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "incomplete.apcap")

	f, err := os.Create(capPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)

	mw, _ := zw.Create("manifest.json")
	_, _ = mw.Write([]byte(`{
		"format": "apcap",
		"format_version": "1.0.0",
		"capture_id": "vector_incomplete",
		"created_at": "2026-09-04T12:00:00Z",
		"agentpcap_version": "1.0.0",
		"capture_mode": "simulation",
		"redaction_mode": "metadata_only",
		"protocols_seen": ["A2A"],
		"event_count": 0,
		"hashes": {}
	}`))

	ew, _ := zw.Create("events.jsonl")
	// One valid event followed by truncated line
	_, _ = ew.Write([]byte(`{"id":"inc_01","trace_id":"tr_inc","timestamp":"2026-09-04T12:00:00Z","duration_ms":15,"type":"A2A_REQUEST","protocol":"A2A","operation":"start","source":{"name":"orch","kind":"agent"},"destination":{"name":"agent-1","kind":"agent"},"status":"OK","provenance":"OBSERVED"}` + "\n" + `{"id":"inc_02","trace_id":`))

	_ = zw.Close()

	// Also write expected recovered JSON
	expectedCap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_incomplete",
			CreatedAt:     baseTime,
		},
		Events: []apcap.Event{
			{
				ID:          "inc_01",
				TraceID:     "tr_inc",
				Timestamp:   baseTime,
				DurationMs:  15.0,
				Type:        apcap.EventA2ARequest,
				Protocol:    apcap.ProtocolA2A,
				Operation:   "start",
				Source:      apcap.Endpoint{Name: "orch", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "agent-1", Kind: "agent"},
				Status:      apcap.StatusOK,
				Provenance:  apcap.ProvenanceObserved,
			},
		},
	}
	saveExpectedJSON(t, vDir, expectedCap)
}

func saveExpectedJSON(t *testing.T, dir string, cap *apcap.Capture) {
	b, err := json.MarshalIndent(cap, "", "  ")
	if err != nil {
		t.Fatalf("failed marshaling expected json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected.json"), b, 0644); err != nil {
		t.Fatalf("failed writing expected json: %v", err)
	}
}

func generateOTELVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "otel")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "otel.apcap")

	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_otel",
			CaptureMode:   "proxy",
			RedactionMode: "metadata_only",
			CreatedAt:     baseTime,
			CompletedAt:   baseTime.Add(250 * time.Millisecond),
		},
		Metadata: apcap.CaptureMetadata{
			Title:           "OpenTelemetry GenAI Ingestion Vector",
			TotalDurationMs: 250.0,
			TotalCost:       0.0015,
			TotalTokens: apcap.TokenUsage{
				InputTokens:  120,
				OutputTokens: 80,
				TotalTokens:  200,
			},
		},
		Events: []apcap.Event{
			{
				ID:          "span_001",
				TraceID:     "4bf92f3577b34da6a3ce929d0e0e4736",
				Timestamp:   baseTime,
				DurationMs:  250.0,
				Type:        apcap.EventModelRequest,
				Protocol:    apcap.ProtocolOTLP,
				Operation:   "chat",
				Source:      apcap.Endpoint{Name: "researcher-agent", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "gemini-1.5-pro", Kind: "model"},
				Status:      apcap.StatusOK,
				Provenance:  apcap.ProvenanceOTel,
				Tokens: &apcap.TokenUsage{
					InputTokens:  120,
					OutputTokens: 80,
					TotalTokens:  200,
				},
				Attributes: map[string]any{
					"gen_ai.system":              "gemini",
					"gen_ai.request.model":       "gemini-1.5-pro",
					"gen_ai.usage.prompt_tokens": float64(120),
					"gen_ai.usage.output_tokens": float64(80),
				},
			},
		},
	}

	if err := apcap.Save(capPath, cap); err != nil {
		t.Fatalf("failed saving otel vector: %v", err)
	}
	saveExpectedJSON(t, vDir, cap)
}

func generateRetriesVector(t *testing.T, dir string, baseTime time.Time) {
	vDir := filepath.Join(dir, "retries")
	_ = os.MkdirAll(vDir, 0755)
	capPath := filepath.Join(vDir, "retries.apcap")

	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			Format:        apcap.FormatIdentifier,
			FormatVersion: "1.0.0",
			CaptureID:     "vector_retries",
			CaptureMode:   "simulation",
			RedactionMode: "metadata_only",
			CreatedAt:     baseTime,
			CompletedAt:   baseTime.Add(1800 * time.Millisecond),
		},
		Metadata: apcap.CaptureMetadata{
			Title:           "Deterministic Retry Storm Pathology Vector",
			TotalDurationMs: 1800.0,
			ErrorCount:      2,
			TotalCost:       0.003,
			TotalTokens: apcap.TokenUsage{
				InputTokens:  300,
				OutputTokens: 50,
				TotalTokens:  350,
			},
		},
		Events: []apcap.Event{
			{
				ID:          "ev_retry_1",
				TraceID:     "tr_retry",
				ParentID:    "task_root",
				Timestamp:   baseTime,
				DurationMs:  400.0,
				Type:        apcap.EventModelRequest,
				Protocol:    apcap.ProtocolModel,
				Operation:   "generateContent",
				Source:      apcap.Endpoint{Name: "data-agent", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "gemini-1.5-flash", Kind: "model"},
				Status:      apcap.StatusError,
				Provenance:  apcap.ProvenanceObserved,
				Attributes: map[string]any{
					"http.status_code": float64(429),
					"error.reason":     "RESOURCE_EXHAUSTED",
					"model":            "gemini-1.5-flash",
				},
			},
			{
				ID:          "ev_retry_2",
				TraceID:     "tr_retry",
				ParentID:    "task_root",
				Timestamp:   baseTime.Add(500 * time.Millisecond),
				DurationMs:  450.0,
				Type:        apcap.EventModelRequest,
				Protocol:    apcap.ProtocolModel,
				Operation:   "generateContent",
				Source:      apcap.Endpoint{Name: "data-agent", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "gemini-1.5-flash", Kind: "model"},
				Status:      apcap.StatusError,
				Provenance:  apcap.ProvenanceObserved,
				Attributes: map[string]any{
					"http.status_code": float64(429),
					"error.reason":     "RESOURCE_EXHAUSTED",
					"model":            "gemini-1.5-flash",
				},
			},
			{
				ID:          "ev_retry_3",
				TraceID:     "tr_retry",
				ParentID:    "task_root",
				Timestamp:   baseTime.Add(1100 * time.Millisecond),
				DurationMs:  700.0,
				Type:        apcap.EventModelRequest,
				Protocol:    apcap.ProtocolModel,
				Operation:   "generateContent",
				Source:      apcap.Endpoint{Name: "data-agent", Kind: "agent"},
				Destination: apcap.Endpoint{Name: "gemini-1.5-flash", Kind: "model"},
				Status:      apcap.StatusOK,
				Provenance:  apcap.ProvenanceObserved,
				Tokens: &apcap.TokenUsage{
					InputTokens:  100,
					OutputTokens: 50,
					TotalTokens:  150,
				},
				Attributes: map[string]any{
					"http.status_code": float64(200),
					"model":            "gemini-1.5-flash",
				},
			},
		},
	}

	if err := apcap.Save(capPath, cap); err != nil {
		t.Fatalf("failed saving retries vector: %v", err)
	}
	saveExpectedJSON(t, vDir, cap)
}
