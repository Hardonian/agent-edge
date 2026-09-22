package a2a_test

import (
	"testing"

	"github.com/agentpcap/agentpcap/internal/protocols/a2a"
)

func FuzzA2AParser(f *testing.F) {
	p := a2a.NewParser()

	f.Add([]byte(`{"taskId":"task-1","sourceAgent":"orch","targetAgent":"worker","instruction":"run"}`))
	f.Add([]byte(`{"taskId":"task-1","status":"completed","artifactsCount":2}`))
	f.Add([]byte(`{"taskId":"task-1","status":"failed","error":"timeout"}`))
	f.Add([]byte(`{"delegation":{"depth":5,"chain":["a","b","c"]}}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant: Parser must never panic
		_, _ = p.ParseTaskRequest(data, "src", "dst", 10.0)
		_, _ = p.ParseTaskResponse(data, "src", "dst", 10.0)
	})
}
