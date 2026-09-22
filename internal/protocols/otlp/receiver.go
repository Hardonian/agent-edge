package otlp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/agentpcap/agentpcap/internal/cost"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// OTLPTracesData models standard OpenTelemetry JSON trace export.
type OTLPTracesData struct {
	ResourceSpans []ResourceSpan `json:"resourceSpans"`
}

type ResourceSpan struct {
	Resource   *Resource   `json:"resource,omitempty"`
	ScopeSpans []ScopeSpan `json:"scopeSpans"`
}

type Resource struct {
	Attributes []KeyValue `json:"attributes,omitempty"`
}

type ScopeSpan struct {
	Spans []Span `json:"spans"`
}

type Span struct {
	TraceID           string      `json:"traceId"`
	SpanID            string      `json:"spanId"`
	ParentSpanID      string      `json:"parentSpanId,omitempty"`
	Name              string      `json:"name"`
	Kind              int         `json:"kind"`
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	EndTimeUnixNano   string      `json:"endTimeUnixNano"`
	Attributes        []KeyValue  `json:"attributes,omitempty"`
	Status            *SpanStatus `json:"status,omitempty"`
}

type SpanStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type KeyValue struct {
	Key   string   `json:"key"`
	Value AnyValue `json:"value"`
}

type AnyValue struct {
	StringValue string  `json:"stringValue,omitempty"`
	IntValue    string  `json:"intValue,omitempty"`
	DoubleValue float64 `json:"doubleValue,omitempty"`
	BoolValue   bool    `json:"boolValue,omitempty"`
}

// Receiver ingests OTLP traces and normalizes them into APCAP events.
type Receiver struct {
	costEngine *cost.Engine
}

// NewReceiver creates an OTLP trace receiver.
func NewReceiver(ce *cost.Engine) *Receiver {
	if ce == nil {
		ce = cost.NewEngine()
	}
	return &Receiver{costEngine: ce}
}

// ParseTracesJSON parses standard OTLP/HTTP JSON body into a list of APCAP events.
func (r *Receiver) ParseTracesJSON(body []byte) ([]apcap.Event, error) {
	var data OTLPTracesData
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("invalid otlp json: %w", err)
	}

	var events []apcap.Event

	for _, rs := range data.ResourceSpans {
		serviceName := "agent"
		if rs.Resource != nil {
			for _, attr := range rs.Resource.Attributes {
				if attr.Key == "service.name" && attr.Value.StringValue != "" {
					serviceName = attr.Value.StringValue
				}
			}
		}

		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				ev := r.spanToEvent(span, serviceName)
				events = append(events, ev)
			}
		}
	}

	return events, nil
}

func (r *Receiver) spanToEvent(span Span, serviceName string) apcap.Event {
	startNano, _ := strconv.ParseInt(span.StartTimeUnixNano, 10, 64)
	endNano, _ := strconv.ParseInt(span.EndTimeUnixNano, 10, 64)

	var durationMs float64
	if endNano > startNano && startNano > 0 {
		durationMs = float64(endNano-startNano) / 1e6
	}

	startTime := time.Unix(0, startNano).UTC()
	if startNano == 0 {
		startTime = time.Now().UTC()
	}

	status := apcap.StatusOK
	if span.Status != nil && span.Status.Code == 2 { // 2 = STATUS_CODE_ERROR
		status = apcap.StatusError
	}

	attrsMap := make(map[string]any)
	for _, kv := range span.Attributes {
		if kv.Value.StringValue != "" {
			attrsMap[kv.Key] = kv.Value.StringValue
		} else if kv.Value.IntValue != "" {
			i, _ := strconv.ParseInt(kv.Value.IntValue, 10, 64)
			attrsMap[kv.Key] = i
		} else if kv.Value.DoubleValue != 0 {
			attrsMap[kv.Key] = kv.Value.DoubleValue
		} else {
			attrsMap[kv.Key] = kv.Value.BoolValue
		}
	}

	// Classify protocol and event type using GenAI semantic conventions
	proto := apcap.ProtocolOTLP
	evType := apcap.EventCustom
	destName := span.Name
	destKind := "service"

	genAISystem, _ := attrsMap["gen_ai.system"].(string)
	modelName, _ := attrsMap["gen_ai.request.model"].(string)
	if modelName == "" {
		modelName, _ = attrsMap["gen_ai.response.model"].(string)
	}

	var tokens *apcap.TokenUsage
	inTok, hasIn := getInt64(attrsMap, "gen_ai.usage.input_tokens")
	outTok, hasOut := getInt64(attrsMap, "gen_ai.usage.output_tokens")
	if hasIn || hasOut {
		tokens = &apcap.TokenUsage{
			InputTokens:  inTok,
			OutputTokens: outTok,
			TotalTokens:  inTok + outTok,
		}
	}

	if genAISystem != "" || modelName != "" {
		proto = apcap.ProtocolModel
		evType = apcap.EventModelResponse
		if modelName != "" {
			destName = modelName
		} else {
			destName = genAISystem
		}
		destKind = "model"
	} else if strings.Contains(strings.ToLower(span.Name), "mcp") {
		proto = apcap.ProtocolMCP
		evType = apcap.EventMCPToolCall
		destKind = "mcp_server"
	} else if strings.Contains(strings.ToLower(span.Name), "agent") {
		proto = apcap.ProtocolA2A
		evType = apcap.EventA2ARequest
		destKind = "agent"
	}

	var costVal *apcap.Money
	if tokens != nil && modelName != "" {
		costVal = r.costEngine.Calculate(modelName, tokens)
	}

	traceID := span.TraceID
	if len(traceID) == 32 {
		// Valid hex
	} else if traceID == "" {
		traceID = fmt.Sprintf("tr_%d", time.Now().UnixNano())
	}

	spanID := span.SpanID
	if spanID == "" {
		spanID = fmt.Sprintf("sp_%d", time.Now().UnixNano())
	}

	return apcap.Event{
		ID:         spanID,
		TraceID:    traceID,
		ParentID:   span.ParentSpanID,
		Timestamp:  startTime,
		DurationMs: durationMs,
		Type:       evType,
		Protocol:   proto,
		Operation:  span.Name,
		Source: apcap.Endpoint{
			Name: serviceName,
			Kind: "agent",
		},
		Destination: apcap.Endpoint{
			Name: destName,
			Kind: destKind,
		},
		Status:     status,
		Attributes: attrsMap,
		Tokens:     tokens,
		Cost:       costVal,
		Provenance: apcap.ProvenanceOTel,
	}
}

func getInt64(m map[string]any, k string) (int64, bool) {
	v, ok := m[k]
	if !ok {
		return 0, false
	}
	switch val := v.(type) {
	case int64:
		return val, true
	case int:
		return int64(val), true
	case float64:
		return int64(val), true
	case string:
		i, err := strconv.ParseInt(val, 10, 64)
		return i, err == nil
	}
	return 0, false
}

// Dummy helper
var _ = hex.EncodeToString
