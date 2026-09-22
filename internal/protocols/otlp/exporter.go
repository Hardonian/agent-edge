package otlp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// ExportCaptureToOTLP converts a Capture into standard OTLP JSON format.
func ExportCaptureToOTLP(cap *apcap.Capture) ([]byte, error) {
	var spans []Span

	for _, ev := range cap.Events {
		startNano := ev.Timestamp.UnixNano()
		endNano := ev.Timestamp.Add(time.Duration(ev.DurationMs * float64(time.Millisecond))).UnixNano()

		statusCode := 1 // STATUS_CODE_OK
		if ev.Status == apcap.StatusError {
			statusCode = 2 // STATUS_CODE_ERROR
		}

		var attrs []KeyValue
		attrs = append(attrs, KeyValue{
			Key:   "protocol",
			Value: AnyValue{StringValue: string(ev.Protocol)},
		})
		attrs = append(attrs, KeyValue{
			Key:   "operation",
			Value: AnyValue{StringValue: ev.Operation},
		})
		attrs = append(attrs, KeyValue{
			Key:   "provenance",
			Value: AnyValue{StringValue: string(ev.Provenance)},
		})

		if ev.Tokens != nil {
			attrs = append(attrs, KeyValue{
				Key:   "gen_ai.usage.input_tokens",
				Value: AnyValue{IntValue: fmt.Sprintf("%d", ev.Tokens.InputTokens)},
			})
			attrs = append(attrs, KeyValue{
				Key:   "gen_ai.usage.output_tokens",
				Value: AnyValue{IntValue: fmt.Sprintf("%d", ev.Tokens.OutputTokens)},
			})
		}

		spans = append(spans, Span{
			TraceID:           ev.TraceID,
			SpanID:            ev.ID,
			ParentSpanID:      ev.ParentID,
			Name:              ev.Operation,
			Kind:              1, // SPAN_KIND_INTERNAL
			StartTimeUnixNano: fmt.Sprintf("%d", startNano),
			EndTimeUnixNano:   fmt.Sprintf("%d", endNano),
			Attributes:        attrs,
			Status:            &SpanStatus{Code: statusCode},
		})
	}

	tracesData := OTLPTracesData{
		ResourceSpans: []ResourceSpan{
			{
				Resource: &Resource{
					Attributes: []KeyValue{
						{
							Key:   "service.name",
							Value: AnyValue{StringValue: "agentpcap-export"},
						},
					},
				},
				ScopeSpans: []ScopeSpan{
					{Spans: spans},
				},
			},
		},
	}

	return json.MarshalIndent(tracesData, "", "  ")
}
