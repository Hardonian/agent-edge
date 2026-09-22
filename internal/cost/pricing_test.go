package cost_test

import (
	"testing"

	"github.com/agentpcap/agentpcap/internal/cost"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestCostEngine(t *testing.T) {
	eng := cost.NewEngine()

	tokens := &apcap.TokenUsage{
		InputTokens:  1_000_000,
		OutputTokens: 1_000_000,
		CachedTokens: 0,
		TotalTokens:  2_000_000,
	}

	// Test Gemini 1.5 Flash: $0.075 input, $0.30 output -> total $0.375
	money := eng.Calculate("gemini-1.5-flash", tokens)
	if money == nil {
		t.Fatal("expected money, got nil")
	}
	if money.Status != apcap.CostStatusEstimated {
		t.Errorf("expected status ESTIMATED, got %s", money.Status)
	}
	expected := 0.375
	if money.Amount != expected {
		t.Errorf("expected amount %f, got %f", expected, money.Amount)
	}

	// Test GPT-4o: $2.50 input, $10.00 output -> $12.50
	money4o := eng.Calculate("gpt-4o-2024-08-06", tokens)
	if money4o == nil || money4o.Amount != 12.50 {
		t.Errorf("expected amount 12.50, got %+v", money4o)
	}

	// Test Unknown model
	moneyUnknown := eng.Calculate("custom-proprietary-model-x", tokens)
	if moneyUnknown.Status != apcap.CostStatusUnknown {
		t.Errorf("expected UNKNOWN status, got %s", moneyUnknown.Status)
	}

	// Test Custom override
	eng.SetCustomRate("custom-proprietary-model-x", cost.ModelRate{
		InputPerMillion:  5.0,
		OutputPerMillion: 20.0,
		Currency:         "USD",
	})
	moneyCustom := eng.Calculate("custom-proprietary-model-x", tokens)
	if moneyCustom.Amount != 25.0 {
		t.Errorf("expected 25.0, got %f", moneyCustom.Amount)
	}
}
