package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/internal/demo"
)

func TestGenerateFixtures(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")
	_ = os.MkdirAll(examplesDir, 0755)

	// 1. examples/demo.apcap
	demoPath := filepath.Join(examplesDir, "demo.apcap")
	session := capture.NewSession(capture.SessionConfig{
		CaptureID:   "cap_demo_simulation",
		Title:       "Quarterly Market Research Flow",
		Description: "Multi-agent research simulation with A2A delegation, MCP tool calls, and retry storm.",
		CaptureMode: "simulation",
		OutputPath:  demoPath,
	})
	demo.RunDemo(session)
	_ = session.Close()

	// 2. examples/demo_optimized.apcap
	optPath := filepath.Join(examplesDir, "demo_optimized.apcap")
	if err := createOptimizedCapture(optPath); err != nil {
		t.Fatalf("failed generating optimized fixture: %v", err)
	}
}
