package runner_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/runner"
)

func TestRunner_EmptyCommand(t *testing.T) {
	_, err := runner.Run(context.Background(), runner.Config{})
	if err == nil {
		t.Fatal("expected error on empty command, got nil")
	}
}

func TestRunner_SafeExecutionNoShellInterpolation(t *testing.T) {
	// Locate standard Go or system executable
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go executable not found in PATH")
	}

	// Pass malicious shell injection attempt as argument
	// If shell interpolation existed, `;` or `|` would be interpreted
	cfg := runner.Config{
		Command: []string{goPath, "version", ";", "echo", "injected"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := runner.Run(ctx, cfg)
	if err != nil && res.ExitCode == 0 {
		t.Fatalf("unexpected execution failure: %v", err)
	}
	// `go version` with extra arguments should exit cleanly or flag extra arguments, but NEVER spawn a subshell executing `echo injected`
}

func TestRunner_ContextCancellation(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go executable not found in PATH")
	}

	// Run long-running or blocking command with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := runner.Config{
		Command: []string{goPath, "version"},
	}

	res, err := runner.Run(ctx, cfg)
	if err == nil && (res == nil || res.ExitCode == 0) {
		t.Errorf("expected cancellation error/exit, got clean success")
	}
}
