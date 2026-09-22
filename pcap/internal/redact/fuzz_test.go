package redact_test

import (
	"testing"

	"github.com/agentpcap/agentpcap/internal/redact"
)

func FuzzRedactor(f *testing.F) {
	r := redact.New()

	f.Add("sk-proj-1234567890abcdef1234567890")
	f.Add("AIzaSyDummyGoogleKeyForFuzzTesting12345")
	f.Add("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dummy")
	f.Add("postgres://user:pass@host:5432/db")
	f.Add("normal string without secrets")
	f.Add("\x00\xff\xfe random bytes")

	f.Fuzz(func(t *testing.T, s string) {
		// Invariant: Redactor must never panic
		_ = r.RedactText(s)
		_ = r.InspectSecrets(s)
	})
}
