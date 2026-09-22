package torture_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/internal/protocols/a2a"
)

func TestA2ATorture_Corpus(t *testing.T) {
	p := a2a.NewParser()

	cases := []struct {
		name       string
		raw        []byte
		isResponse bool
		mustFail   bool
	}{
		// 1. Corrupt payloads
		{"null bytes", []byte("\x00\x00\x00"), false, true},
		{"malformed JSON syntax", []byte(`{"taskId": "t1", "instruction": `), false, true},
		{"empty string", []byte(""), false, true},
		{"primitive bool", []byte("true"), false, true},

		// 2. Oversized fields
		{"100KB task instruction", fmt.Appendf(nil, `{"taskId": "t-big", "instruction": "%s"}`, strings.Repeat("I", 100000)), false, false},
		{"50 level circular delegation chain", func() []byte {
			chain := make([]string, 50)
			for i := range chain {
				chain[i] = fmt.Sprintf("agent_%d", i%3) // agent_0 -> agent_1 -> agent_2 -> agent_0 ...
			}
			return fmt.Appendf(nil, `{
				"taskId": "t-cycle",
				"sourceAgent": "agent_0",
				"targetAgent": "agent_1",
				"delegation": {
					"depth": 50,
					"initiator": "agent_0",
					"chain": ["%s"]
				}
			}`, strings.Join(chain, `","`))
		}(), false, false},

		// 3. Status responses
		{"response with unknown status", []byte(`{"taskId": "t1", "status": "MY_WEIRD_STATUS_UNKNOWN"}`), true, false},
		{"response with massive error payload", fmt.Appendf(nil, `{"taskId": "t1", "status": "failed", "error": "%s"}`, strings.Repeat("ERR_", 10000)), true, false},
		{"response with zero artifact count", []byte(`{"taskId": "t1", "status": "completed", "artifactsCount": 0}`), true, false},
		{"response with negative artifact count", []byte(`{"taskId": "t1", "status": "completed", "artifactsCount": -99}`), true, false},

		// 4. Unicode, control characters & XSS
		{"RTL unicode in instruction", []byte(`{"taskId": "t-rtl", "instruction": "مرحبا بالعالم \u202E reversed"}`), false, false},
		{"XSS payload in agent name", []byte(`{"taskId": "t-xss", "sourceAgent": "<img src=x onerror=alert(1)>"}`), false, false},
		{"Control characters in taskId", []byte(`{"taskId": "t\r\n\t\b\f", "instruction": "clean"}`), false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC TRIGGERED on A2A input %q: %v", tc.name, r)
				}
			}()

			var err error
			if tc.isResponse {
				_, err = p.ParseTaskResponse(tc.raw, "agent-src", "agent-dst", 10.0)
			} else {
				_, err = p.ParseTaskRequest(tc.raw, "agent-src", "agent-dst", 10.0)
			}

			if tc.mustFail && err == nil {
				t.Errorf("expected rejection for %q, but parser succeeded", tc.name)
			}
			if !tc.mustFail && err != nil {
				t.Errorf("expected graceful acceptance for %q, got error: %v", tc.name, err)
			}
		})
	}
}
