package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentpcap/agentpcap/internal/analyzer"
	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/internal/demo"
	"github.com/agentpcap/agentpcap/internal/pathology"
	"github.com/agentpcap/agentpcap/internal/protocols/otlp"
	"github.com/agentpcap/agentpcap/pkg/apcap"
	"github.com/agentpcap/agentpcap/web"
)

// ServerConfig configures the embedded web viewer server.
type ServerConfig struct {
	ListenAddr string // default "127.0.0.1:9477"
}

// Server serves the embedded React viewer and AgentPCAP REST APIs.
type Server struct {
	session         *capture.Session
	otlpReceiver    *otlp.Receiver
	pathologyEngine *pathology.Engine
	httpServer      *http.Server
	listener        net.Listener
	listenAddr      string
	actualURL       string
	wg              sync.WaitGroup
}

// NewServer initializes the AgentPCAP web server.
func NewServer(session *capture.Session, otlpRec *otlp.Receiver, cfg ServerConfig) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:9477"
	}

	return &Server{
		session:         session,
		otlpReceiver:    otlpRec,
		pathologyEngine: pathology.NewEngine(),
		listenAddr:      cfg.ListenAddr,
	}
}

// SetSession allows switching the active viewing session (e.g. after loading an .apcap file).
func (s *Server) SetSession(session *capture.Session) {
	s.session = session
}

// Start binds to the listener and starts the HTTP server asynchronously.
func (s *Server) Start() error {
	var ln net.Listener
	var err error

	// Try specified address or increment port on collision
	host, portStr, _ := net.SplitHostPort(s.listenAddr)
	if host == "" {
		host = "127.0.0.1"
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	if port == 0 {
		port = 9477
	}

	for i := 0; i < 10; i++ {
		addr := fmt.Sprintf("%s:%d", host, port+i)
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			s.listenAddr = addr
			s.actualURL = fmt.Sprintf("http://%s:%d", host, port+i)
			break
		}
	}

	if ln == nil {
		return fmt.Errorf("failed to bind server: %w", err)
	}
	s.listener = ln

	mux := http.NewServeMux()

	// REST Endpoints
	mux.HandleFunc("/api/session", s.handleGetSession)
	mux.HandleFunc("/api/events", s.handleGetEvents)
	mux.HandleFunc("/api/findings", s.handleGetFindings)
	mux.HandleFunc("/api/critical-path", s.handleGetCriticalPath)
	mux.HandleFunc("/api/flamegraph", s.handleGetFlamegraph)
	mux.HandleFunc("/api/stream", s.handleSSEStream)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/simulate", s.handleSimulate)
	mux.HandleFunc("/api/load-demo", s.handleLoadDemo)
	mux.HandleFunc("/v1/traces", s.handleOTLPTraces)

	// Static Web Assets with SPA Fallback
	webFS := web.GetFS()
	fileServer := http.FileServer(webFS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set Security Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:;")

		// Check if file exists in webFS
		f, err := webFS.Open(r.URL.Path)
		if err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// Fallback to index.html for client-side routing
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // Keep open for SSE
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("web server error", "err", err)
		}
	}()

	return nil
}

// URL returns the full HTTP address the server is listening on.
func (s *Server) URL() string {
	return s.actualURL
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	err := s.httpServer.Shutdown(ctx)
	s.wg.Wait()
	return err
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	cap := s.session.Capture()
	_ = json.NewEncoder(w).Encode(cap)
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	events := s.session.Events()
	_ = json.NewEncoder(w).Encode(events)
}

func (s *Server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	events := s.session.Events()
	findings := s.pathologyEngine.Analyze(events)
	_ = json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleGetCriticalPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	events := s.session.Events()
	report := analyzer.AnalyzeCriticalPath(events)
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Server) handleGetFlamegraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	modeStr := strings.ToUpper(r.URL.Query().Get("mode"))
	mode := analyzer.FlameModeCost
	switch modeStr {
	case "TOKENS":
		mode = analyzer.FlameModeTokens
	case "TIME":
		mode = analyzer.FlameModeTime
	case "CALLS":
		mode = analyzer.FlameModeCalls
	}

	w.Header().Set("Content-Type", "application/json")
	events := s.session.Events()
	flame := analyzer.BuildFlamegraph(events, mode)
	_ = json.NewEncoder(w).Encode(flame)
}

func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsubscribe := s.session.Subscribe()
	defer unsubscribe()

	// Flush connected event
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(b))
				flusher.Flush()
			}
		}
	}
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(50 * 1024 * 1024) // 50 MB limit
	if err != nil {
		http.Error(w, "failed to parse multipart form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file in form", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tempFile, err := os.CreateTemp("", "upload_*.apcap")
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, file); err != nil {
		http.Error(w, "failed writing temp capture", http.StatusInternalServerError)
		return
	}

	parsedCap, err := apcap.Open(tempFile.Name())
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid apcap capture: %v", err), http.StatusBadRequest)
		return
	}

	// Create new session from uploaded capture
	newSession := capture.NewSession(capture.SessionConfig{
		CaptureID:   parsedCap.Manifest.CaptureID,
		Title:       parsedCap.Metadata.Title,
		Description: parsedCap.Metadata.Description,
	})
	for _, ev := range parsedCap.Events {
		newSession.Ingest(ev)
	}

	s.SetSession(newSession)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"capture_id":  parsedCap.Manifest.CaptureID,
		"event_count": len(parsedCap.Events),
	})
}

func (s *Server) handleOTLPTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed reading body", http.StatusBadRequest)
		return
	}

	events, err := s.otlpReceiver.ParseTracesJSON(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid otlp payload: %v", err), http.StatusBadRequest)
		return
	}

	for _, ev := range events {
		s.session.Ingest(ev)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	go demo.RunDemoLive(s.session)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "simulating"})
}

func (s *Server) handleLoadDemo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.session.Reset()
	demo.RunDemo(s.session)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "loaded"})
}

// Dummy helper
var _ = filepath.Clean
