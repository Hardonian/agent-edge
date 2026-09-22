package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/agentpcap/agentpcap/internal/pathology"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// ChecksConfig defines CI assertion thresholds.
type ChecksConfig struct {
	FailOn       []string `json:"fail_on"`
	MaxCost      float64  `json:"max_cost"`
	MaxLatencyMs float64  `json:"max_latency_ms"`
}

// Config represents .agentpcap.yml configuration.
type Config struct {
	Version int          `json:"version"`
	Checks  ChecksConfig `json:"checks"`
}

// DefaultConfig returns baseline configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Checks: ChecksConfig{
			FailOn: []string{"RETRY_STORM", "LOOP"},
		},
	}
}

// Load reads and parses an .agentpcap.yml file.
func Load(filePath string) (*Config, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := DefaultConfig()
	scanner := bufio.NewScanner(f)
	currentSection := ""
	seenFailOn := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasSuffix(line, ":") {
			currentSection = strings.TrimSuffix(line, ":")
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])

			switch k {
			case "max_cost", "cost":
				if val, err := strconv.ParseFloat(v, 64); err == nil {
					cfg.Checks.MaxCost = val
				}
			case "max_latency_ms", "latency":
				if val, err := strconv.ParseFloat(v, 64); err == nil {
					cfg.Checks.MaxLatencyMs = val
				}
			}
		}

		// Handle list items like: - retry_storm
		if strings.HasPrefix(line, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			itemUpper := strings.ToUpper(strings.ReplaceAll(item, "-", "_"))
			if currentSection == "fail_on" || strings.Contains(line, "fail") {
				if !seenFailOn {
					cfg.Checks.FailOn = nil
					seenFailOn = true
				}
				cfg.Checks.FailOn = append(cfg.Checks.FailOn, itemUpper)
			}
		}
	}

	return cfg, nil
}

// CheckCapture evaluates assertions on a capture. Returns list of violations.
func (c *Config) CheckCapture(cap *apcap.Capture) []string {
	var violations []string

	pEng := pathology.NewEngine()
	findings := pEng.Analyze(cap.Events)

	for _, f := range findings {
		for _, failType := range c.Checks.FailOn {
			if strings.EqualFold(f.Type, failType) {
				violations = append(violations, fmt.Sprintf("Pathology violation [%s]: %s", f.Type, f.Title))
			}
		}
	}

	if c.Checks.MaxCost > 0 && cap.Metadata.TotalCost > c.Checks.MaxCost {
		violations = append(violations, fmt.Sprintf("Cost violation: Total cost $%.4f exceeds configured max $%.4f", cap.Metadata.TotalCost, c.Checks.MaxCost))
	}

	if c.Checks.MaxLatencyMs > 0 && cap.Metadata.TotalDurationMs > c.Checks.MaxLatencyMs {
		violations = append(violations, fmt.Sprintf("Latency violation: Duration %.1fms exceeds configured max %.1fms", cap.Metadata.TotalDurationMs, c.Checks.MaxLatencyMs))
	}

	return violations
}
