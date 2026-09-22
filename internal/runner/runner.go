package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Config configures child process execution.
type Config struct {
	Command      []string
	ProxyURL     string
	OTLPEndpoint string
	CaptureID    string
}

// Result contains the outcome of the child process run.
type Result struct {
	ExitCode int
	Error    error
}

// Run executes the child command safely, injecting proxy and OTel environment variables.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if len(cfg.Command) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Inherit existing environment and inject AgentPCAP capture targets
	env := os.Environ()
	if cfg.ProxyURL != "" {
		env = append(env,
			fmt.Sprintf("HTTP_PROXY=%s", cfg.ProxyURL),
			fmt.Sprintf("http_proxy=%s", cfg.ProxyURL),
			fmt.Sprintf("HTTPS_PROXY=%s", cfg.ProxyURL),
			fmt.Sprintf("https_proxy=%s", cfg.ProxyURL),
		)
	}
	if cfg.OTLPEndpoint != "" {
		env = append(env,
			fmt.Sprintf("OTEL_EXPORTER_OTLP_ENDPOINT=%s", cfg.OTLPEndpoint),
			"OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf",
		)
	}
	if cfg.CaptureID != "" {
		env = append(env,
			"AGENTPCAP_ACTIVE=1",
			fmt.Sprintf("AGENTPCAP_CAPTURE_ID=%s", cfg.CaptureID),
		)
	}
	cmd.Env = env

	// Setup signal trapping so Ctrl+C gracefully interrupts child
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return &Result{ExitCode: 1, Error: err}, fmt.Errorf("failed to start command: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case sig := <-sigCh:
		// Forward signal to child process
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
		// Wait for termination
		err := <-done
		exitCode := extractExitCode(err)
		return &Result{ExitCode: exitCode, Error: err}, nil

	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return &Result{ExitCode: 1, Error: ctx.Err()}, nil

	case err := <-done:
		exitCode := extractExitCode(err)
		return &Result{ExitCode: exitCode, Error: err}, nil
	}
}

func extractExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}
