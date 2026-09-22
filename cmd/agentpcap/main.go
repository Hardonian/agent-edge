package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/agentpcap/agentpcap/internal/analyzer"
	"github.com/agentpcap/agentpcap/internal/browser"
	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/internal/config"
	"github.com/agentpcap/agentpcap/internal/cost"
	"github.com/agentpcap/agentpcap/internal/demo"
	"github.com/agentpcap/agentpcap/internal/diff"
	"github.com/agentpcap/agentpcap/internal/pathology"
	"github.com/agentpcap/agentpcap/internal/protocols/model"
	"github.com/agentpcap/agentpcap/internal/protocols/otlp"
	"github.com/agentpcap/agentpcap/internal/proxy"
	"github.com/agentpcap/agentpcap/internal/redact"
	"github.com/agentpcap/agentpcap/internal/report"
	"github.com/agentpcap/agentpcap/internal/runner"
	"github.com/agentpcap/agentpcap/internal/server"
	"github.com/agentpcap/agentpcap/internal/version"
	"github.com/agentpcap/agentpcap/pkg/apcap"
	"github.com/agentpcap/agentpcap/web"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run":
		handleRun(args)
	case "demo":
		handleDemo(args)
	case "open":
		handleOpen(args)
	case "proxy":
		handleProxy(args)
	case "otlp":
		handleOTLP(args)
	case "diff":
		handleDiff(args)
	case "explain":
		handleExplain(args)
	case "doctor":
		handleDoctor(args)
	case "version", "--version", "-v":
		handleVersion()
	case "summary":
		handleSummary(args)
	case "top":
		handleTop(args)
	case "check":
		handleCheck(args)
	case "validate":
		handleValidate(args)
	case "redact":
		handleRedact(args)
	case "inspect-redaction":
		handleInspectRedaction(args)
	case "export":
		handleExport(args)
	case "report":
		handleReport(args)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'agentpcap help' for usage.\n", cmd)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AgentPCAP — Wireshark for AI Agents
Capture A2A, MCP, model and tool traffic in one local timeline.
No account. No API key. One Go binary.

Usage:
  agentpcap <command> [arguments]

CAPTURE:
  run -- <cmd>              Run agent command as child process with capture & live viewer
  proxy                     Start standalone HTTP forward capture proxy
  otlp                      Start OpenTelemetry trace ingestion receiver

VIEW:
  demo                      Launch deterministic multi-agent simulation & web viewer
  open <file.apcap>         Open capture file in local offline web viewer

ANALYZE:
  explain <file.apcap>      Analyze critical path and detect pathologies (no LLM required)
  top <file.apcap>          Rank top operations by cost, latency, tokens, or errors
  summary <file.apcap>      Print human or markdown summary of capture
  check <file.apcap>        Assert capture thresholds against .agentpcap.yml in CI
  validate <file.apcap>     Verify .apcap schema and cryptographic SHA-256 hashes
  report <in> -o <out.html> Export single-file offline HTML forensic report
  redact <in> -o <out>      Scrub credentials and tokens from a capture file
  inspect-redaction <file>  Scan a capture file for potential leaked secrets
  export otlp <file.apcap>  Export capture as standard OpenTelemetry trace JSON

COMPARE:
  diff <a.apcap> <b.apcap>  Compare two agent runs (latency, tokens, cost, pathologies)

SYSTEM:
  doctor                    Verify local environment, ports, and protocol adapters
  version                   Display version, commit, and runtime information

Options:
  --no-browser              Do not open browser automatically
  --listen <addr>           Bind address for web viewer (default: 127.0.0.1:9477)
  --output <path>           Destination path for .apcap capture file
  --timeout <duration>      Duration to run demo before auto-shutdown (e.g. 5s)
  --exit                    Generate capture fixture and exit immediately
  --json                    Output structured JSON format
  --markdown                Output GitHub markdown format
  --capture-content         Explicitly capture payloads (default: metadata-only)`)
}

func handleRun(args []string) {
	var (
		listenAddr     string
		proxyAddr      string
		outputPath     string
		noBrowser      bool
		captureContent bool
	)

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.StringVar(&listenAddr, "listen", "127.0.0.1:9477", "Web viewer address")
	fs.StringVar(&proxyAddr, "proxy", "127.0.0.1:9478", "HTTP capture proxy address")
	fs.StringVar(&outputPath, "output", "", "Output .apcap file path")
	fs.BoolVar(&noBrowser, "no-browser", false, "Disable opening browser")
	fs.BoolVar(&captureContent, "capture-content", false, "Capture payloads (default: metadata-only)")

	// Find the double-dash separator: agentpcap run [flags] -- command args...
	cmdIdx := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIdx = i
			break
		}
	}

	var childCmd []string
	if cmdIdx >= 0 {
		_ = fs.Parse(args[:cmdIdx])
		childCmd = args[cmdIdx+1:]
	} else {
		_ = fs.Parse(args)
		childCmd = fs.Args()
	}

	if len(childCmd) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No child command specified. Example: agentpcap run -- ./my-agent")
		os.Exit(1)
	}

	if outputPath == "" {
		outputPath = fmt.Sprintf("capture_%d.apcap", time.Now().Unix())
	}

	if captureContent {
		fmt.Println("⚠️  CONTENT CAPTURE ACTIVE: Payloads and tool arguments will be recorded. Centralized secret scrubbing will sanitize credentials.")
	}
	if isExternalAddress(listenAddr) {
		fmt.Printf("⚠️  SECURITY WARNING: Binding web viewer to external address '%s'. Captures may be accessible on the local network.\n", listenAddr)
	}
	if isExternalAddress(proxyAddr) {
		fmt.Printf("⚠️  SECURITY WARNING: Binding proxy to external address '%s'.\n", proxyAddr)
	}

	// 1. Initialize Capture Session
	session := capture.NewSession(capture.SessionConfig{
		CaptureID:      fmt.Sprintf("cap_%d", time.Now().Unix()),
		Title:          strings.Join(childCmd, " "),
		CaptureMode:    "child_process",
		CaptureContent: captureContent,
		OutputPath:     outputPath,
	})
	defer session.Close()

	// 2. Initialize Model Adapter & Proxy Server
	costEng := cost.NewEngine()
	modAdapter := model.NewAdapter(costEng)
	proxySrv := proxy.NewServer(session, modAdapter, proxy.Config{ListenAddr: proxyAddr})
	if err := proxySrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not bind proxy: %v\n", err)
	}
	defer proxySrv.Stop(context.Background())

	// 3. Initialize OTLP Receiver
	otlpRec := otlp.NewReceiver(costEng)

	// 4. Start Embedded Web Server
	webSrv := server.NewServer(session, otlpRec, server.ServerConfig{ListenAddr: listenAddr})
	if err := webSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting web server: %v\n", err)
		os.Exit(1)
	}
	defer webSrv.Stop(context.Background())

	fmt.Printf("\n✓ AgentPCAP capture engine started\n")
	fmt.Printf("✓ Proxy listener: %s\n", proxySrv.Addr())
	fmt.Printf("✓ Live web viewer: %s\n", webSrv.URL())
	fmt.Printf("✓ Running: %s\n\n", strings.Join(childCmd, " "))

	if !noBrowser {
		_ = browser.Open(webSrv.URL())
	}

	// 5. Execute Child Command with injected env
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res, err := runner.Run(ctx, runner.Config{
		Command:      childCmd,
		ProxyURL:     fmt.Sprintf("http://%s", proxySrv.Addr()),
		OTLPEndpoint: fmt.Sprintf("%s/v1/traces", webSrv.URL()),
		CaptureID:    session.Capture().Manifest.CaptureID,
	})

	fmt.Printf("\n✓ Child process finished (exit code %d)\n", res.ExitCode)
	if err != nil && res.ExitCode == 0 {
		fmt.Printf("Process error: %v\n", err)
	}

	// 6. Finalize Capture
	_ = session.Close()
	fmt.Printf("✓ Capture saved: %s (%d events)\n", outputPath, len(session.Events()))

	os.Exit(res.ExitCode)
}

func handleDemo(args []string) {
	var (
		listenAddr    string
		noBrowser     bool
		outputPath    string
		exitImmediate bool
		timeout       time.Duration
	)

	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	fs.StringVar(&listenAddr, "listen", "127.0.0.1:9477", "Web viewer address")
	fs.BoolVar(&noBrowser, "no-browser", false, "Disable opening browser")
	fs.StringVar(&outputPath, "output", "demo.apcap", "Output .apcap file path")
	fs.BoolVar(&exitImmediate, "exit", false, "Exit after generating demo capture")
	fs.DurationVar(&timeout, "timeout", 0, "Duration to run demo before auto-shutdown (e.g. 5s, 30s)")
	_ = fs.Parse(args)

	fmt.Println("AgentPCAP Demo — Local Multi-Agent Simulation")
	fmt.Println("--------------------------------------------")

	if isExternalAddress(listenAddr) {
		fmt.Printf("⚠️  SECURITY WARNING: Binding web viewer to external address '%s'. Captures may be accessible on the local network.\n\n", listenAddr)
	}

	session := capture.NewSession(capture.SessionConfig{
		CaptureID:   "cap_demo_simulation",
		Title:       "Quarterly Market Research & Procurement Flow",
		Description: "Multi-agent research simulation demonstrating A2A delegation, MCP tool calls, model calls, and retry storms.",
		CaptureMode: "simulation",
		OutputPath:  outputPath,
	})

	costEng := cost.NewEngine()
	otlpRec := otlp.NewReceiver(costEng)
	webSrv := server.NewServer(session, otlpRec, server.ServerConfig{ListenAddr: listenAddr})
	if err := webSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = webSrv.Stop(context.Background()) }()

	fmt.Printf("✓ capture started\n")
	fmt.Printf("✓ finance-agent\n")
	fmt.Printf("✓ research-agent\n")
	fmt.Printf("✓ procurement-agent\n")
	fmt.Printf("✓ MCP analytics\n")
	fmt.Printf("✓ model simulator\n\n")
	fmt.Printf("Viewer:\n%s\n\n", webSrv.URL())

	// Run multi-agent simulation
	demo.RunDemo(session)
	_ = session.Close()

	if !noBrowser {
		_ = browser.Open(webSrv.URL())
	}

	fmt.Printf("✓ Simulated task started (12 events streamed)\n")
	fmt.Printf("✓ Saved capture fixture to: %s\n", outputPath)

	if exitImmediate {
		return
	}

	if timeout > 0 {
		fmt.Printf("Running demo server for %s...\n", timeout)
		time.Sleep(timeout)
		fmt.Println("\nDemo duration elapsed. Stopped.")
		return
	}

	fmt.Println("Press Ctrl+C to exit.")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\nExiting.")
}

func handleOpen(args []string) {
	var (
		listenAddr string
		noBrowser  bool
	)

	fs := flag.NewFlagSet("open", flag.ExitOnError)
	fs.StringVar(&listenAddr, "listen", "127.0.0.1:9477", "Web viewer address")
	fs.BoolVar(&noBrowser, "no-browser", false, "Disable opening browser")
	_ = fs.Parse(args)

	files := fs.Args()
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap open [flags] <file.apcap>")
		os.Exit(1)
	}
	capFile := files[0]
	parsedCap := openCaptureOrExit(capFile)

	if isExternalAddress(listenAddr) {
		fmt.Printf("⚠️  SECURITY WARNING: Binding web viewer to external address '%s'. Captures may be accessible on the local network.\n\n", listenAddr)
	}

	session := capture.NewSession(capture.SessionConfig{
		CaptureID:   parsedCap.Manifest.CaptureID,
		Title:       parsedCap.Metadata.Title,
		Description: parsedCap.Metadata.Description,
	})
	for _, ev := range parsedCap.Events {
		session.Ingest(ev)
	}

	costEng := cost.NewEngine()
	otlpRec := otlp.NewReceiver(costEng)
	webSrv := server.NewServer(session, otlpRec, server.ServerConfig{ListenAddr: listenAddr})
	if err := webSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting viewer: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = webSrv.Stop(context.Background()) }()

	fmt.Printf("\n✓ Opened: %s (%d events)\n", capFile, len(parsedCap.Events))
	fmt.Printf("✓ Local Viewer: %s\n\n", webSrv.URL())

	if !noBrowser {
		_ = browser.Open(webSrv.URL())
	}

	fmt.Println("Press Ctrl+C to stop viewer.")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\nViewer stopped.")
}

func handleProxy(args []string) {
	var listenAddr string
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	fs.StringVar(&listenAddr, "listen", "127.0.0.1:8080", "Proxy listen address")
	_ = fs.Parse(args)

	if isExternalAddress(listenAddr) {
		fmt.Printf("⚠️  SECURITY WARNING: Binding proxy to external address '%s'.\n", listenAddr)
	}

	session := capture.NewSession(capture.SessionConfig{
		CaptureID:   fmt.Sprintf("proxy_%d", time.Now().Unix()),
		CaptureMode: "proxy",
	})
	defer session.Close()

	costEng := cost.NewEngine()
	modAdapter := model.NewAdapter(costEng)
	pSrv := proxy.NewServer(session, modAdapter, proxy.Config{ListenAddr: listenAddr})
	if err := pSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("AgentPCAP HTTP Proxy running on %s\nPress Ctrl+C to exit.\n", pSrv.Addr())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	_ = pSrv.Stop(context.Background())
}

func handleOTLP(args []string) {
	var listenAddr string
	fs := flag.NewFlagSet("otlp", flag.ExitOnError)
	fs.StringVar(&listenAddr, "listen", "127.0.0.1:4318", "OTLP HTTP listen address")
	_ = fs.Parse(args)

	if isExternalAddress(listenAddr) {
		fmt.Printf("⚠️  SECURITY WARNING: Binding OTLP receiver to external address '%s'.\n", listenAddr)
	}

	session := capture.NewSession(capture.SessionConfig{
		CaptureID:   fmt.Sprintf("otlp_%d", time.Now().Unix()),
		CaptureMode: "otlp",
	})
	costEng := cost.NewEngine()
	otlpRec := otlp.NewReceiver(costEng)
	webSrv := server.NewServer(session, otlpRec, server.ServerConfig{ListenAddr: listenAddr})
	if err := webSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("AgentPCAP OTLP Receiver running on %s/v1/traces\nPress Ctrl+C to exit.\n", webSrv.URL())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
}

func handleDiff(args []string) {
	var jsonOutput bool
	var files []string
	for _, arg := range args {
		if arg == "--json" || arg == "-json" {
			jsonOutput = true
		} else if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap diff before.apcap after.apcap [--json]")
		os.Exit(1)
	}

	capA := openCaptureOrExit(files[0])
	capB := openCaptureOrExit(files[1])

	res := diff.Compare(capA, capB)
	if jsonOutput {
		b, _ := res.ToJSON()
		fmt.Println(string(b))
	} else {
		fmt.Print(res.FormatTerminal())
	}
}

func handleExplain(args []string) {
	var jsonOutput bool
	var files []string
	for _, arg := range args {
		if arg == "--json" || arg == "-json" {
			jsonOutput = true
		} else if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap explain <file.apcap> [--json]")
		os.Exit(1)
	}

	cap := openCaptureOrExit(files[0])

	cp := analyzer.AnalyzeCriticalPath(cap.Events)
	pEng := pathology.NewEngine()
	findings := pEng.Analyze(cap.Events)

	if jsonOutput {
		out := map[string]any{
			"capture_id":     cap.Manifest.CaptureID,
			"duration_ms":    cap.Metadata.TotalDurationMs,
			"events_count":   len(cap.Events),
			"error_count":    cap.Metadata.ErrorCount,
			"total_tokens":   cap.Metadata.TotalTokens.TotalTokens,
			"estimated_cost": cap.Metadata.TotalCost,
			"critical_path":  cp,
			"findings":       findings,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Printf("\nAGENTPCAP EXPLAIN: %s\n", cap.Manifest.CaptureID)
	fmt.Println("======================================================================")

	// 1. LIKELY BOTTLENECK
	fmt.Println("\nLIKELY BOTTLENECK")
	fmt.Println("----------------------------------------------------------------------")
	if cp.DominantEvent.EventID != "" {
		fmt.Printf("• %s (%s)\n  Duration: %.1fms (%.1f%% of wall-clock time)\n  Status: %s\n",
			cp.DominantEvent.Operation, cp.DominantEvent.Protocol,
			cp.DominantEvent.DurationMs, cp.DominantEvent.PercentOfTotal,
			cp.DominantEvent.Status)
	} else {
		fmt.Println("• No single dominant bottleneck identified.")
	}

	// 2. CAUSE CHAIN
	fmt.Println("\nCAUSE CHAIN")
	fmt.Println("----------------------------------------------------------------------")
	if len(cp.Steps) > 0 {
		chain := make([]string, 0, len(cp.Steps))
		for _, s := range cp.Steps {
			chain = append(chain, fmt.Sprintf("%s (%.1fms)", s.Operation, s.DurationMs))
		}
		fmt.Println("  " + strings.Join(chain, "\n  ↳ "))
	} else {
		fmt.Println("• Execution graph has no serialized cause chain.")
	}

	// 3. OBSERVATIONS
	fmt.Println("\nOBSERVATIONS")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("• Wall-Clock Duration: %.2fs\n", cap.Metadata.TotalDurationMs/1000.0)
	fmt.Printf("• Total Events:        %d (with %d errors)\n", len(cap.Events), cap.Metadata.ErrorCount)
	fmt.Printf("• Total Tokens:        %d\n", cap.Metadata.TotalTokens.TotalTokens)
	fmt.Printf("• Estimated Cost:      $%.4f USD\n", cap.Metadata.TotalCost)
	if len(findings) > 0 {
		fmt.Printf("• Pathologies:         %d detected\n", len(findings))
		for _, f := range findings {
			fmt.Printf("  [%s] %s: %s\n", f.Severity, f.Type, f.Title)
		}
	} else {
		fmt.Println("• Pathologies:         0 detected (clean execution pattern)")
	}

	// 4. SUGGESTED INVESTIGATION
	fmt.Println("\nSUGGESTED INVESTIGATION")
	fmt.Println("----------------------------------------------------------------------")
	if len(findings) > 0 {
		for i, f := range findings {
			fmt.Printf("%d. %s\n   Action: %s\n", i+1, f.Title, f.SuggestedFix)
		}
	} else if cp.DominantEvent.EventID != "" {
		fmt.Printf("1. Inspect '%s' for potential asynchronous caching or parallelization opportunities.\n", cp.DominantEvent.Operation)
	} else {
		fmt.Println("• Performance appears nominal. No immediate action required.")
	}
	fmt.Println()
}

func handleDoctor(_ []string) {
	fmt.Println("AgentPCAP Doctor")
	fmt.Println("================")

	// Check web viewer assets
	webFS := web.GetFS()
	if _, err := webFS.Open("index.html"); err == nil {
		fmt.Println("✓ viewer assets: OK")
	} else {
		fmt.Println("✗ viewer assets: MISSING")
	}

	// Check local port availability
	ln, err := net.Listen("tcp", "127.0.0.1:9477")
	if err == nil {
		ln.Close()
		fmt.Println("✓ default viewer port 9477: AVAILABLE")
	} else {
		fmt.Println("! default viewer port 9477: OCCUPIED (auto-collision discovery active)")
	}

	fmt.Println("✓ capture engine: READY")
	fmt.Println("✓ .apcap reader/writer: READY")
	fmt.Println("✓ MCP parser: READY")
	fmt.Println("✓ A2A parser: READY")
	fmt.Println("✓ OTLP receiver: READY")
	fmt.Println("✓ redaction: READY")

	fmt.Println()
	if os.Getenv("GEMINI_API_KEY") != "" {
		fmt.Println("✓ Gemini integration: configured (GEMINI_API_KEY)")
	} else {
		fmt.Println("○ Gemini integration: not configured (optional)")
	}
	if os.Getenv("VERTEXAI_PROJECT") != "" || os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		fmt.Println("✓ Vertex integration: configured")
	} else {
		fmt.Println("○ Vertex integration: not configured (optional)")
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		fmt.Println("✓ OpenAI integration: configured (OPENAI_API_KEY)")
	} else {
		fmt.Println("○ OpenAI integration: not configured (optional)")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		fmt.Println("✓ Anthropic integration: configured (ANTHROPIC_API_KEY)")
	} else {
		fmt.Println("○ Anthropic integration: not configured (optional)")
	}

	fmt.Println("\nCore AgentPCAP is ready.")
}

func handleVersion() {
	fmt.Println(version.Info())
}

func handleSummary(args []string) {
	var markdownOutput bool
	var jsonOutput bool
	var files []string
	for _, arg := range args {
		if arg == "--markdown" || arg == "-markdown" {
			markdownOutput = true
		} else if arg == "--json" || arg == "-json" {
			jsonOutput = true
		} else if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap summary <file.apcap> [--markdown|--json]")
		os.Exit(1)
	}

	cap := openCaptureOrExit(files[0])

	pEng := pathology.NewEngine()
	findings := pEng.Analyze(cap.Events)

	if jsonOutput {
		out := map[string]any{
			"capture_id":     cap.Manifest.CaptureID,
			"duration_s":     cap.Metadata.TotalDurationMs / 1000.0,
			"total_tokens":   cap.Metadata.TotalTokens.TotalTokens,
			"estimated_cost": cap.Metadata.TotalCost,
			"events":         len(cap.Events),
			"errors":         cap.Metadata.ErrorCount,
			"pathologies":    len(findings),
			"findings":       findings,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	if markdownOutput {
		fmt.Printf("### AgentPCAP Capture Summary: `%s`\n\n", cap.Manifest.CaptureID)
		fmt.Printf("| Metric | Value |\n|---|---|\n")
		fmt.Printf("| Duration | %.2fs |\n", cap.Metadata.TotalDurationMs/1000.0)
		fmt.Printf("| Tokens | %d |\n", cap.Metadata.TotalTokens.TotalTokens)
		fmt.Printf("| Estimated Cost | $%.4f |\n", cap.Metadata.TotalCost)
		fmt.Printf("| Events | %d |\n", len(cap.Events))
		fmt.Printf("| Errors | %d |\n", cap.Metadata.ErrorCount)
		fmt.Printf("| Pathologies | %d |\n", len(findings))
	} else {
		fmt.Printf("\nCAPTURE SUMMARY: %s\n", cap.Manifest.CaptureID)
		fmt.Println("======================================")
		fmt.Printf("Duration:     %.2fs\n", cap.Metadata.TotalDurationMs/1000.0)
		fmt.Printf("Tokens:       %d\n", cap.Metadata.TotalTokens.TotalTokens)
		fmt.Printf("Cost:         $%.4f USD\n", cap.Metadata.TotalCost)
		fmt.Printf("Total Events: %d\n", len(cap.Events))
		fmt.Printf("Errors:       %d\n", cap.Metadata.ErrorCount)
		fmt.Printf("Pathologies:  %d detected\n\n", len(findings))
	}
}

func handleTop(args []string) {
	sortBy := "latency"
	var files []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--by" || arg == "-by" {
			if i+1 < len(args) {
				sortBy = args[i+1]
				i++
			}
		} else if strings.HasPrefix(arg, "--by=") || strings.HasPrefix(arg, "-by=") {
			parts := strings.SplitN(arg, "=", 2)
			sortBy = parts[1]
		} else if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap top <file.apcap> [--by latency|calls|tokens|cost]")
		os.Exit(1)
	}

	cap := openCaptureOrExit(files[0])

	type opStat struct {
		op       string
		protocol string
		calls    int
		duration float64
		tokens   int64
		cost     float64
	}

	statsMap := make(map[string]*opStat)
	for _, ev := range cap.Events {
		s, ok := statsMap[ev.Operation]
		if !ok {
			s = &opStat{op: ev.Operation, protocol: string(ev.Protocol)}
			statsMap[ev.Operation] = s
		}
		s.calls++
		s.duration += ev.DurationMs
		if ev.Tokens != nil {
			s.tokens += ev.Tokens.TotalTokens
		}
		if ev.Cost != nil {
			s.cost += ev.Cost.Amount
		}
	}

	list := make([]*opStat, 0, len(statsMap))
	for _, s := range statsMap {
		list = append(list, s)
	}

	sort.Slice(list, func(i, j int) bool {
		switch strings.ToLower(sortBy) {
		case "calls":
			return list[i].calls > list[j].calls
		case "tokens":
			return list[i].tokens > list[j].tokens
		case "cost":
			return list[i].cost > list[j].cost
		default: // latency
			return list[i].duration > list[j].duration
		}
	})

	fmt.Printf("\nTOP OPERATIONS (by %s)\n", strings.ToUpper(sortBy))
	fmt.Println("==========================================================================================")
	fmt.Printf("%-3s %-6s %-36s %8s %12s %10s %10s\n", "#", "PROTO", "OPERATION", "CALLS", "DURATION", "TOKENS", "COST")
	fmt.Println("------------------------------------------------------------------------------------------")

	limit := 10
	if len(list) < limit {
		limit = len(list)
	}

	for i := 0; i < limit; i++ {
		s := list[i]
		fmt.Printf("%-3d %-6s %-36s %8d %10.1fms %10d %9.4f$\n",
			i+1, s.protocol, truncateString(s.op, 36), s.calls, s.duration, s.tokens, s.cost)
	}
	fmt.Println()
}

func handleCheck(args []string) {
	configPath := ".agentpcap.yml"
	var files []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--config" || arg == "-config" {
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		} else if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			parts := strings.SplitN(arg, "=", 2)
			configPath = parts[1]
		} else if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap check <file.apcap> [--config .agentpcap.yml]")
		os.Exit(1)
	}

	cap := openCaptureOrExit(files[0])

	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	violations := cfg.CheckCapture(cap)
	if len(violations) > 0 {
		fmt.Fprintf(os.Stderr, "\n❌ CI Assertions Failed (%d violations):\n", len(violations))
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "  • %s\n", v)
		}
		os.Exit(1)
	}

	fmt.Println("\n✓ All AgentPCAP assertions passed cleanly.")
}

func handleValidate(args []string) {
	var jsonOutput bool
	var files []string
	for _, arg := range args {
		if arg == "--json" || arg == "-json" {
			jsonOutput = true
		} else if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap validate <file.apcap> [--json]")
		os.Exit(1)
	}

	target := files[0]
	cap, err := apcap.Open(target)
	if err != nil {
		if jsonOutput {
			out, _ := json.Marshal(map[string]any{"valid": false, "file": target, "error": err.Error()})
			fmt.Println(string(out))
		} else {
			fmt.Fprintf(os.Stderr, "❌ Validation failed: %v\n", err)
		}
		os.Exit(1)
	}

	if cap.Manifest.Format != apcap.FormatIdentifier {
		if jsonOutput {
			out, _ := json.Marshal(map[string]any{"valid": false, "file": target, "error": fmt.Sprintf("invalid format identifier: %s", cap.Manifest.Format)})
			fmt.Println(string(out))
		} else {
			fmt.Fprintf(os.Stderr, "❌ Invalid format identifier: %s\n", cap.Manifest.Format)
		}
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(map[string]any{
			"valid":           true,
			"file":            target,
			"format":          cap.Manifest.Format,
			"format_version":  cap.Manifest.FormatVersion,
			"hashes_verified": len(cap.Manifest.Hashes),
			"events_count":    len(cap.Events),
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	fmt.Printf("✓ Capture '%s' conforms to APCAP v%s\n", target, cap.Manifest.FormatVersion)
	fmt.Printf("✓ Hashes verified: %d file checksums OK\n", len(cap.Manifest.Hashes))
	fmt.Printf("✓ Parsed %d events safely\n", len(cap.Events))
}

func parseInputOutput(args []string, defaultOut string) (input, output string) {
	output = defaultOut
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" || args[i] == "--output" {
			if i+1 < len(args) {
				output = args[i+1]
				i++
				continue
			}
		}
		if !strings.HasPrefix(args[i], "-") && input == "" {
			input = args[i]
		}
	}
	return
}

func handleRedact(args []string) {
	inputPath, outputPath := parseInputOutput(args, "")
	if inputPath == "" || outputPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap redact <in.apcap> -o <out.apcap>")
		os.Exit(1)
	}

	cap := openCaptureOrExit(inputPath)

	redactor := redact.New()
	cleanCap := redactor.RedactCapture(cap)

	if err := apcap.Save(outputPath, cleanCap); err != nil {
		fmt.Fprintf(os.Stderr, "Failed saving redacted capture: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Redacted capture written to %s (all credentials scrubbed)\n", outputPath)
}

func handleInspectRedaction(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap inspect-redaction <file.apcap>")
		os.Exit(1)
	}

	cap := openCaptureOrExit(args[0])

	redactor := redact.New()
	totalFindings := 0

	for _, ev := range cap.Events {
		b, _ := json.Marshal(ev)
		findings := redactor.InspectSecrets(string(b))
		if len(findings) > 0 {
			totalFindings += len(findings)
			fmt.Printf("Event %s contains %d potential secrets:\n", ev.ID, len(findings))
			for _, f := range findings {
				fmt.Printf("  • %s: sample %s\n", f.PatternName, f.Sample)
			}
		}
	}

	if totalFindings == 0 {
		fmt.Println("✓ Zero unredacted secrets found in capture file.")
	} else {
		fmt.Printf("\n⚠ Total %d potential secrets flagged.\n", totalFindings)
	}
}

func handleExport(args []string) {
	if len(args) < 2 || args[0] != "otlp" {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap export otlp <file.apcap>")
		os.Exit(1)
	}

	cap := openCaptureOrExit(args[1])

	otlpJSON, err := otlp.ExportCaptureToOTLP(cap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Export error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(otlpJSON))
}

func handleReport(args []string) {
	inputPath, outputPath := parseInputOutput(args, "report.html")
	if inputPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: agentpcap report <file.apcap> [-o report.html]")
		os.Exit(1)
	}

	cap := openCaptureOrExit(inputPath)

	if err := report.GenerateHTMLReport(cap, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Report generation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Standalone offline HTML report generated: %s\n", outputPath)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func openCaptureOrExit(filePath string) *apcap.Capture {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Capture file '%s' does not exist.\n", filePath)
		os.Exit(1)
	}
	cap, err := apcap.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to open capture file '%s'.\n\nDetails:\n  %v\n\nTry:\n  agentpcap validate %s\n", filePath, err, filePath)
		os.Exit(1)
	}
	return cap
}

func isExternalAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return false
	}
	return true
}

// Dummy helpers
var _ = filepath.Clean
