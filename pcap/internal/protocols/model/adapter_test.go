package model_test

import (
	"testing"

	"github.com/agentpcap/agentpcap/internal/cost"
	"github.com/agentpcap/agentpcap/internal/protocols/model"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestModelAdapter_IsModelRequest(t *testing.T) {
	a := model.NewAdapter(nil)

	tests := []struct {
		host     string
		path     string
		expected bool
	}{
		{"generativelanguage.googleapis.com", "/v1beta/models/gemini-1.5-pro:generateContent", true},
		{"api.openai.com", "/v1/chat/completions", true},
		{"api.anthropic.com", "/v1/messages", true},
		{"custom-gateway.internal", "/v1/chat/completions", true},
		{"example.com", "/api/v1/users", false},
	}

	for _, tc := range tests {
		got := a.IsModelRequest(tc.host, tc.path)
		if got != tc.expected {
			t.Errorf("IsModelRequest(%q, %q) = %v, expected %v", tc.host, tc.path, got, tc.expected)
		}
	}
}

func TestModelAdapter_GeminiExchange(t *testing.T) {
	ce := cost.NewEngine()
	a := model.NewAdapter(ce)

	body := []byte(`{
		"usageMetadata": {
			"promptTokenCount": 800,
			"candidatesTokenCount": 200,
			"totalTokenCount": 1000,
			"cachedContentTokenCount": 100
		}
	}`)

	ev := a.ParseExchange(
		"POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
		"generativelanguage.googleapis.com", "/v1beta/models/gemini-1.5-pro:generateContent",
		200, body, "research-agent", 450.0,
	)

	if ev.Protocol != apcap.ProtocolModel {
		t.Errorf("expected ProtocolModel, got %v", ev.Protocol)
	}
	if ev.Destination.Name != "gemini-1.5-pro" {
		t.Errorf("expected destination gemini-1.5-pro, got %s", ev.Destination.Name)
	}
	if ev.Tokens == nil || ev.Tokens.TotalTokens != 1000 {
		t.Errorf("expected 1000 tokens, got %+v", ev.Tokens)
	}
	if ev.Cost == nil || ev.Cost.Amount <= 0 {
		t.Errorf("expected non-zero cost, got %+v", ev.Cost)
	}
}

func TestModelAdapter_OpenAIExchange(t *testing.T) {
	ce := cost.NewEngine()
	a := model.NewAdapter(ce)

	body := []byte(`{
		"model": "gpt-4o",
		"usage": {
			"prompt_tokens": 500,
			"completion_tokens": 150,
			"total_tokens": 650
		}
	}`)

	ev := a.ParseExchange(
		"POST", "https://api.openai.com/v1/chat/completions",
		"api.openai.com", "/v1/chat/completions",
		200, body, "analyst-agent", 300.0,
	)

	if ev.Destination.Name != "gpt-4o" {
		t.Errorf("expected destination gpt-4o, got %s", ev.Destination.Name)
	}
	if ev.Tokens == nil || ev.Tokens.TotalTokens != 650 {
		t.Errorf("expected 650 tokens, got %+v", ev.Tokens)
	}
}

func TestModelAdapter_AnthropicExchange(t *testing.T) {
	ce := cost.NewEngine()
	a := model.NewAdapter(ce)

	body := []byte(`{
		"model": "claude-3-5-sonnet-20241022",
		"usage": {
			"input_tokens": 1200,
			"output_tokens": 300
		}
	}`)

	ev := a.ParseExchange(
		"POST", "https://api.anthropic.com/v1/messages",
		"api.anthropic.com", "/v1/messages",
		200, body, "writer-agent", 500.0,
	)

	if ev.Destination.Name != "claude-3-5-sonnet-20241022" {
		t.Errorf("expected claude-3-5-sonnet-20241022, got %s", ev.Destination.Name)
	}
	if ev.Tokens == nil || ev.Tokens.TotalTokens != 1500 {
		t.Errorf("expected 1500 total tokens, got %+v", ev.Tokens)
	}
}

func TestModelAdapter_ErrorStatus(t *testing.T) {
	a := model.NewAdapter(nil)

	ev := a.ParseExchange(
		"POST", "https://api.openai.com/v1/chat/completions",
		"api.openai.com", "/v1/chat/completions",
		429, []byte(`{"error": {"message": "Rate limit exceeded"}}`), "agent", 100.0,
	)

	if ev.Status != apcap.StatusError {
		t.Errorf("expected StatusError for 429, got %v", ev.Status)
	}
	if ev.Type != apcap.EventModelError {
		t.Errorf("expected EventModelError, got %v", ev.Type)
	}
}
