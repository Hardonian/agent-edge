package model

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/agentpcap/agentpcap/internal/cost"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

var (
	geminiPathRegex    = regexp.MustCompile(`/(?:v1|v1beta)/models/([^:]+):(?:streamGenerateContent|generateContent)`)
	openaiPathRegex    = regexp.MustCompile(`/v1/(chat/completions|embeddings|completions)`)
	anthropicPathRegex = regexp.MustCompile(`/v1/messages`)
)

// GeminiUsageMetadata matches Google GenAI token response.
type GeminiUsageMetadata struct {
	PromptTokenCount        int64 `json:"promptTokenCount"`
	CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
	TotalTokenCount         int64 `json:"totalTokenCount"`
	CachedContentTokenCount int64 `json:"cachedContentTokenCount,omitempty"`
}

// GeminiResponse represents a Gemini API JSON response.
type GeminiResponse struct {
	UsageMetadata *GeminiUsageMetadata `json:"usageMetadata,omitempty"`
}

// OpenAIUsage matches OpenAI / compatible token usage.
type OpenAIUsage struct {
	PromptTokens        int64 `json:"prompt_tokens"`
	CompletionTokens    int64 `json:"completion_tokens"`
	TotalTokens         int64 `json:"total_tokens"`
	PromptTokensDetails struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details,omitempty"`
}

// OpenAIResponse represents an OpenAI chat completions response.
type OpenAIResponse struct {
	Model string       `json:"model"`
	Usage *OpenAIUsage `json:"usage,omitempty"`
}

// AnthropicUsage matches Anthropic Messages API usage.
type AnthropicUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens,omitempty"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens,omitempty"`
}

// AnthropicResponse represents an Anthropic Messages API response.
type AnthropicResponse struct {
	Model string          `json:"model"`
	Usage *AnthropicUsage `json:"usage,omitempty"`
}

// Adapter normalizes model provider requests and responses.
type Adapter struct {
	costEngine *cost.Engine
}

// NewAdapter creates a model protocol adapter.
func NewAdapter(ce *cost.Engine) *Adapter {
	if ce == nil {
		ce = cost.NewEngine()
	}
	return &Adapter{costEngine: ce}
}

// IsModelRequest inspects URL path and headers to determine if an HTTP call is targeting an LLM.
func (a *Adapter) IsModelRequest(host, path string) bool {
	lowerHost := strings.ToLower(host)
	if strings.Contains(lowerHost, "googleapis.com") ||
		strings.Contains(lowerHost, "openai.com") ||
		strings.Contains(lowerHost, "anthropic.com") {
		return true
	}
	return geminiPathRegex.MatchString(path) ||
		openaiPathRegex.MatchString(path) ||
		anthropicPathRegex.MatchString(path)
}

// ParseExchange converts an HTTP request/response exchange with an LLM into an APCAP Event.
func (a *Adapter) ParseExchange(
	reqMethod, reqURL, host, path string,
	statusCode int,
	respBody []byte,
	callerName string,
	durationMs float64,
) *apcap.Event {
	ev := &apcap.Event{
		ID:         fmt.Sprintf("model_%d", time.Now().UnixNano()),
		Timestamp:  time.Now().UTC(),
		DurationMs: durationMs,
		Type:       apcap.EventModelResponse,
		Protocol:   apcap.ProtocolModel,
		Source: apcap.Endpoint{
			Name: callerName,
			Kind: "agent",
		},
		Status:     apcap.StatusOK,
		Attributes: make(map[string]any),
		Provenance: apcap.ProvenanceProtocolParsed,
	}

	if statusCode >= 400 {
		ev.Status = apcap.StatusError
		ev.Type = apcap.EventModelError
		ev.Attributes["http.status_code"] = statusCode
	}

	// 1. Check Gemini
	if m := geminiPathRegex.FindStringSubmatch(path); len(m) > 1 || strings.Contains(host, "googleapis.com") {
		modelName := "gemini"
		if len(m) > 1 {
			modelName = m[1]
		}
		ev.Destination = apcap.Endpoint{
			Name: modelName,
			Kind: "model",
			Host: host,
		}
		ev.Operation = fmt.Sprintf("gemini:%s", modelName)
		ev.Attributes["model.provider"] = "google"
		ev.Attributes["model.name"] = modelName

		var gemResp GeminiResponse
		if err := json.Unmarshal(respBody, &gemResp); err == nil && gemResp.UsageMetadata != nil {
			ev.Tokens = &apcap.TokenUsage{
				InputTokens:  gemResp.UsageMetadata.PromptTokenCount,
				OutputTokens: gemResp.UsageMetadata.CandidatesTokenCount,
				CachedTokens: gemResp.UsageMetadata.CachedContentTokenCount,
				TotalTokens:  gemResp.UsageMetadata.TotalTokenCount,
			}
			ev.Cost = a.costEngine.Calculate(modelName, ev.Tokens)
		}
		return ev
	}

	// 2. Check OpenAI
	if m := openaiPathRegex.FindStringSubmatch(path); len(m) > 1 || strings.Contains(host, "openai.com") {
		op := "chat/completions"
		if len(m) > 1 {
			op = m[1]
		}
		ev.Operation = fmt.Sprintf("openai:%s", op)
		ev.Attributes["model.provider"] = "openai"

		var oaiResp OpenAIResponse
		if err := json.Unmarshal(respBody, &oaiResp); err == nil {
			modelName := oaiResp.Model
			if modelName == "" {
				modelName = "openai-model"
			}
			ev.Destination = apcap.Endpoint{
				Name: modelName,
				Kind: "model",
				Host: host,
			}
			ev.Attributes["model.name"] = modelName

			if oaiResp.Usage != nil {
				ev.Tokens = &apcap.TokenUsage{
					InputTokens:  oaiResp.Usage.PromptTokens,
					OutputTokens: oaiResp.Usage.CompletionTokens,
					CachedTokens: oaiResp.Usage.PromptTokensDetails.CachedTokens,
					TotalTokens:  oaiResp.Usage.TotalTokens,
				}
				ev.Cost = a.costEngine.Calculate(modelName, ev.Tokens)
			}
		}
		return ev
	}

	// 3. Check Anthropic
	if anthropicPathRegex.MatchString(path) || strings.Contains(host, "anthropic.com") {
		ev.Operation = "anthropic:messages"
		ev.Attributes["model.provider"] = "anthropic"

		var antResp AnthropicResponse
		if err := json.Unmarshal(respBody, &antResp); err == nil {
			modelName := antResp.Model
			if modelName == "" {
				modelName = "claude"
			}
			ev.Destination = apcap.Endpoint{
				Name: modelName,
				Kind: "model",
				Host: host,
			}
			ev.Attributes["model.name"] = modelName

			if antResp.Usage != nil {
				ev.Tokens = &apcap.TokenUsage{
					InputTokens:  antResp.Usage.InputTokens,
					OutputTokens: antResp.Usage.OutputTokens,
					CachedTokens: antResp.Usage.CacheReadInputTokens,
					TotalTokens:  antResp.Usage.InputTokens + antResp.Usage.OutputTokens,
				}
				ev.Cost = a.costEngine.Calculate(modelName, ev.Tokens)
			}
		}
		return ev
	}

	// Generic HTTP fallback
	ev.Destination = apcap.Endpoint{
		Name: host,
		Kind: "service",
		Host: host,
	}
	ev.Protocol = apcap.ProtocolHTTP
	ev.Type = apcap.EventHTTPResponse
	ev.Operation = fmt.Sprintf("%s %s", reqMethod, path)
	ev.Attributes["http.status_code"] = statusCode

	return ev
}

// Dummy helper to satisfy http import if not used directly
var _ = http.StatusOK
