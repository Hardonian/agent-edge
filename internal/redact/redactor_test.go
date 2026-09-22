package redact_test

import (
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/internal/redact"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestRedactor(t *testing.T) {
	r := redact.New()

	// Synthetic mock tokens used exclusively for testing regex scrubbing
	mockGoogleKey := "AI" + "za" + "MockTestTokenScrubbingUnitTest12345"
	mockOpenAIKey := "sk-" + "MockOpenAITestKey1234567890abcdef"
	mockAnthropicKey := "sk-ant-api03-" + "MockAnthropicTestKey1234567890abcdef"
	mockAWSKey := "AKIA" + "IOSFODNN7EXAMPLE"
	mockGitHubToken := "ghp_" + "123456789012345678901234567890123456"
	mockPrivateKey := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "OpenAI Key",
			input:    "client using " + mockOpenAIKey + " for auth",
			expected: "client using [REDACTED_OPENAI_KEY] for auth",
		},
		{
			name:     "Google Key",
			input:    "gemini key " + mockGoogleKey,
			expected: "gemini key [REDACTED_GOOGLE_KEY]",
		},
		{
			name:     "Anthropic Key",
			input:    "anthropic secret " + mockAnthropicKey,
			expected: "anthropic secret [REDACTED_ANTHROPIC_KEY]",
		},
		{
			name:     "AWS Access Key",
			input:    "AWS creds: " + mockAWSKey,
			expected: "AWS creds: [REDACTED_AWS_KEY]",
		},
		{
			name:     "GitHub Token",
			input:    "github token " + mockGitHubToken,
			expected: "github token [REDACTED_GITHUB_TOKEN]",
		},
		{
			name:     "Bearer Token",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef",
			expected: "Authorization: Bearer [REDACTED_TOKEN]",
		},
		{
			name:     "Database URI",
			input:    "connecting to postgres://admin:supersecretpassword@db.internal:5432/agents",
			expected: "connecting to postgres://[USER]:[REDACTED_PASS]@db.internal:5432/agents",
		},
		{
			name:     "Private Key PEM Block",
			input:    "key data:\n" + mockPrivateKey + "\nend",
			expected: "key data:\n[REDACTED_PRIVATE_KEY]\nend",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := r.RedactText(tc.input)
			if got != tc.expected {
				t.Errorf("got %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestRedactMapAndSlice(t *testing.T) {
	r := redact.New()
	mockKey := "sk-" + "MockKey1234567890abcdef12345678"

	input := map[string]any{
		"safe_field": "hello world",
		"auth_token": "secret_token_val", // matches sensitive key "token"
		"nested": map[string]any{
			"url": "https://api.openai.com?key=" + mockKey,
		},
		"list": []any{
			"item with " + mockKey,
			map[string]any{"api_key": "val"},
		},
	}

	cleaned := r.RedactMap(input)

	if cleaned["auth_token"] != "[REDACTED_SENSITIVE_FIELD]" {
		t.Errorf("auth_token not scrubbed: %v", cleaned["auth_token"])
	}

	nested, ok := cleaned["nested"].(map[string]any)
	if !ok || strings.Contains(nested["url"].(string), mockKey) {
		t.Errorf("nested map not scrubbed: %+v", nested)
	}

	list, ok := cleaned["list"].([]any)
	if !ok || strings.Contains(list[0].(string), mockKey) {
		t.Errorf("list item not scrubbed: %+v", list)
	}
}

func TestRedactEventAndCapture(t *testing.T) {
	r := redact.New()
	mockGoogleKey := "AI" + "za" + "MockTestTokenScrubbingUnitTest12345"
	mockOpenAIKey := "sk-" + "MockOpenAITestKey1234567890abcdef"

	ev := &apcap.Event{
		ID:        "ev-1",
		Operation: "POST /v1/chat with key " + mockOpenAIKey,
		Attributes: map[string]any{
			"authorization": "Bearer secret-token-123",
			"safe_field":    "model-gemini",
		},
		Payload: &apcap.PayloadRef{
			Preview: "my api key is " + mockGoogleKey + " in body",
		},
	}

	redacted := r.RedactEvent(ev)
	if redacted.Operation != "POST /v1/chat with key [REDACTED_OPENAI_KEY]" {
		t.Errorf("operation not redacted: %s", redacted.Operation)
	}
	if redacted.Attributes["authorization"] != "[REDACTED_SENSITIVE_FIELD]" {
		t.Errorf("sensitive attribute not scrubbed: %v", redacted.Attributes["authorization"])
	}
	if redacted.Payload.Preview != "my api key is [REDACTED_GOOGLE_KEY] in body" {
		t.Errorf("payload preview not scrubbed: %s", redacted.Payload.Preview)
	}

	// Full capture redaction
	cap := &apcap.Capture{
		Manifest: apcap.Manifest{
			CaptureID:     "cap_test",
			RedactionMode: "full_content",
		},
		Events: []apcap.Event{*ev},
	}
	cleanCap := r.RedactCapture(cap)
	if cleanCap.Manifest.RedactionMode != "sanitized_content" {
		t.Errorf("expected sanitized_content mode, got %s", cleanCap.Manifest.RedactionMode)
	}
	if len(cleanCap.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(cleanCap.Events))
	}
}

func TestInspectSecrets(t *testing.T) {
	r := redact.New()
	text := "Found key sk-1234567890abcdef1234567890 in log"
	findings := r.InspectSecrets(text)
	if len(findings) == 0 {
		t.Fatal("expected secret finding, got none")
	}
	if findings[0].PatternName != "OpenAI API Key" {
		t.Errorf("unexpected pattern: %s", findings[0].PatternName)
	}
	if !strings.Contains(findings[0].Sample, "...") {
		t.Errorf("expected masked sample, got %s", findings[0].Sample)
	}
}
