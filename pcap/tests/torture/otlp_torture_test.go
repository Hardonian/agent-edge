package torture_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/internal/protocols/otlp"
)

func TestOTLPTorture_Corpus(t *testing.T) {
	rec := otlp.NewReceiver(nil)

	cases := []struct {
		name     string
		body     []byte
		mustFail bool
	}{
		// 1. Corrupt payloads
		{"null byte stream", []byte("\x00\x00\x00\x00"), true},
		{"unclosed JSON", []byte(`{"resourceSpans": [{"scopeSpans": [`), true},
		{"malformed int in stringValue", []byte(`{
			"resourceSpans": [{
				"scopeSpans": [{
					"spans": [{
						"name": "call",
						"attributes": [{"key": "gen_ai.usage.input_tokens", "value": {"intValue": "NOT_AN_INT"}}]
					}]
				}]
			}]
		}`), false},

		// 2. Clock skew and abnormal timestamps
		{"start time is 0", []byte(`{
			"resourceSpans": [{
				"scopeSpans": [{
					"spans": [{"name": "zero_time", "startTimeUnixNano": "0", "endTimeUnixNano": "0"}]
				}]
			}]
		}`), false},
		{"negative timestamps", []byte(`{
			"resourceSpans": [{
				"scopeSpans": [{
					"spans": [{"name": "neg_time", "startTimeUnixNano": "-1000", "endTimeUnixNano": "-500"}]
				}]
			}]
		}`), false},

		// 3. Huge attribute count
		{"5000 attributes in single span", func() []byte {
			var b strings.Builder
			b.WriteString(`{"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "dense", "attributes": [`)
			for i := 0; i < 5000; i++ {
				if i > 0 {
					b.WriteString(",")
				}
				b.WriteString(fmt.Sprintf(`{"key": "attr_%d", "value": {"stringValue": "val_%d"}}`, i, i))
			}
			b.WriteString(`]}]}]}]}`)
			return []byte(b.String())
		}(), false},

		// 4. TraceID with non-standard lengths
		{"empty traceID and spanID", []byte(`{
			"resourceSpans": [{
				"scopeSpans": [{
					"spans": [{"name": "no_ids"}]
				}]
			}]
		}`), false},
		{"huge string in span name", fmt.Appendf(nil, `{
			"resourceSpans": [{
				"scopeSpans": [{
					"spans": [{"name": "%s"}]
				}]
			}]
		}`, strings.Repeat("SPAN_", 10000)), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC TRIGGERED on OTLP input %q: %v", tc.name, r)
				}
			}()

			events, err := rec.ParseTracesJSON(tc.body)
			if tc.mustFail && err == nil {
				t.Errorf("expected rejection for %q, but parser succeeded", tc.name)
			}
			if !tc.mustFail && err != nil {
				t.Errorf("expected success for %q, got err: %v", tc.name, err)
			}
			if !tc.mustFail && events == nil {
				t.Errorf("expected events slice for %q", tc.name)
			}
		})
	}
}
