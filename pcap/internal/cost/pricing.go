package cost

import (
	"strings"
	"sync"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// ModelRate defines price per million tokens in USD.
type ModelRate struct {
	InputPerMillion  float64 `json:"input_per_million"`
	OutputPerMillion float64 `json:"output_per_million"`
	CachedPerMillion float64 `json:"cached_per_million"`
	Currency         string  `json:"currency"`
}

var defaultRates = map[string]ModelRate{
	// Google Gemini
	"gemini-1.5-pro":   {InputPerMillion: 1.25, OutputPerMillion: 5.00, CachedPerMillion: 0.3125, Currency: "USD"},
	"gemini-1.5-flash": {InputPerMillion: 0.075, OutputPerMillion: 0.30, CachedPerMillion: 0.01875, Currency: "USD"},
	"gemini-2.0-flash": {InputPerMillion: 0.10, OutputPerMillion: 0.40, CachedPerMillion: 0.025, Currency: "USD"},
	"gemini-1.0-pro":   {InputPerMillion: 0.50, OutputPerMillion: 1.50, CachedPerMillion: 0.0, Currency: "USD"},

	// OpenAI
	"gpt-4o":      {InputPerMillion: 2.50, OutputPerMillion: 10.00, CachedPerMillion: 1.25, Currency: "USD"},
	"gpt-4o-mini": {InputPerMillion: 0.15, OutputPerMillion: 0.60, CachedPerMillion: 0.075, Currency: "USD"},
	"o1":          {InputPerMillion: 15.00, OutputPerMillion: 60.00, CachedPerMillion: 7.50, Currency: "USD"},
	"o3-mini":     {InputPerMillion: 1.10, OutputPerMillion: 4.40, CachedPerMillion: 0.55, Currency: "USD"},
	"gpt-4-turbo": {InputPerMillion: 10.00, OutputPerMillion: 30.00, CachedPerMillion: 0.0, Currency: "USD"},

	// Anthropic
	"claude-3-5-sonnet": {InputPerMillion: 3.00, OutputPerMillion: 15.00, CachedPerMillion: 0.30, Currency: "USD"},
	"claude-3-5-haiku":  {InputPerMillion: 0.80, OutputPerMillion: 4.00, CachedPerMillion: 0.08, Currency: "USD"},
	"claude-3-opus":     {InputPerMillion: 15.00, OutputPerMillion: 75.00, CachedPerMillion: 1.50, Currency: "USD"},

	// Local & Simulated
	"simulated-gemini": {InputPerMillion: 0.075, OutputPerMillion: 0.30, CachedPerMillion: 0.0, Currency: "USD"},
	"simulated-local":  {InputPerMillion: 0.0, OutputPerMillion: 0.0, CachedPerMillion: 0.0, Currency: "USD"},
	"ollama":           {InputPerMillion: 0.0, OutputPerMillion: 0.0, CachedPerMillion: 0.0, Currency: "USD"},
}

// Engine calculates monetary costs for token usage.
type Engine struct {
	mu          sync.RWMutex
	customRates map[string]ModelRate
	sourceName  string
}

// NewEngine initializes the cost calculation engine.
func NewEngine() *Engine {
	return &Engine{
		customRates: make(map[string]ModelRate),
		sourceName:  "pricing-snapshot-v1",
	}
}

// SetCustomRate registers or overrides pricing for a model.
func (e *Engine) SetCustomRate(model string, rate ModelRate) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rate.Currency == "" {
		rate.Currency = "USD"
	}
	e.customRates[normalizeModel(model)] = rate
}

// Calculate returns the calculated cost for given model and tokens.
func (e *Engine) Calculate(modelName string, tokens *apcap.TokenUsage) *apcap.Money {
	if tokens == nil {
		return nil
	}

	norm := normalizeModel(modelName)

	e.mu.RLock()
	rate, ok := e.customRates[norm]
	e.mu.RUnlock()

	if !ok {
		rate, ok = findDefaultRate(norm)
	}

	if !ok {
		return &apcap.Money{
			Amount:   0,
			Currency: "USD",
			Status:   apcap.CostStatusUnknown,
			Source:   e.sourceName,
		}
	}

	inputCost := (float64(tokens.InputTokens) / 1_000_000.0) * rate.InputPerMillion
	outputCost := (float64(tokens.OutputTokens) / 1_000_000.0) * rate.OutputPerMillion
	cachedCost := (float64(tokens.CachedTokens) / 1_000_000.0) * rate.CachedPerMillion

	totalCost := inputCost + outputCost + cachedCost

	return &apcap.Money{
		Amount:   totalCost,
		Currency: rate.Currency,
		Status:   apcap.CostStatusEstimated,
		Source:   e.sourceName,
	}
}

func normalizeModel(m string) string {
	s := strings.ToLower(strings.TrimSpace(m))
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

func findDefaultRate(norm string) (ModelRate, bool) {
	// Exact match
	if rate, ok := defaultRates[norm]; ok {
		return rate, true
	}

	// Substring / prefix match
	for k, rate := range defaultRates {
		if strings.Contains(norm, k) {
			return rate, true
		}
	}

	// Local heuristic
	if strings.HasPrefix(norm, "local-") || strings.HasPrefix(norm, "llama") || strings.HasPrefix(norm, "mistral-local") {
		return ModelRate{Currency: "USD"}, true
	}

	return ModelRate{}, false
}
