package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/internal/protocols/model"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// Server is a local HTTP forward proxy capturing agent traffic.
type Server struct {
	session      *capture.Session
	modelAdapter *model.Adapter
	listener     net.Listener
	httpServer   *http.Server
	client       *http.Client
	listenAddr   string
	wg           sync.WaitGroup
}

// Config configures proxy listener.
type Config struct {
	ListenAddr string // default "127.0.0.1:9478"
}

// NewServer creates a proxy server instance.
func NewServer(session *capture.Session, modelAdapter *model.Adapter, cfg Config) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:9478"
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &Server{
		session:      session,
		modelAdapter: modelAdapter,
		listenAddr:   cfg.ListenAddr,
		client:       &http.Client{Transport: transport},
	}
}

// Start binds to the configured port and serves proxy requests asynchronously.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("proxy failed to bind %s: %w", s.listenAddr, err)
	}
	s.listener = ln
	s.listenAddr = ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleProxyRequest)

	s.httpServer = &http.Server{
		Handler: mux,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("proxy server error", "err", err)
		}
	}()

	return nil
}

// Addr returns the actual bound network address.
func (s *Server) Addr() string {
	return s.listenAddr
}

// Stop shuts down the proxy server gracefully.
func (s *Server) Stop(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	err := s.httpServer.Shutdown(ctx)
	s.wg.Wait()
	return err
}

func (s *Server) handleProxyRequest(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		s.handleConnect(w, req)
		return
	}

	start := time.Now()

	// Capture incoming request body if needed
	var reqBodyBytes []byte
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil {
			reqBodyBytes = body
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	// Prepare outbound request
	outReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.RequestURI, bytes.NewReader(reqBodyBytes))
	if err != nil {
		// Try resolving URL from Host if RequestURI is relative
		targetURL := req.URL.String()
		if !strings.HasPrefix(targetURL, "http") {
			targetURL = fmt.Sprintf("http://%s%s", req.Host, req.RequestURI)
		}
		outReq, err = http.NewRequestWithContext(req.Context(), req.Method, targetURL, bytes.NewReader(reqBodyBytes))
		if err != nil {
			http.Error(w, "invalid proxy destination", http.StatusBadRequest)
			return
		}
	}

	// Copy headers
	for k, vv := range req.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Del("Proxy-Connection")

	// Execute upstream call
	resp, err := s.client.Do(outReq)
	duration := time.Since(start)
	durationMs := float64(duration.Microseconds()) / 1000.0

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		// Record failed HTTP event
		s.session.Ingest(apcap.Event{
			ID:          fmt.Sprintf("http_err_%d", time.Now().UnixNano()),
			Timestamp:   start.UTC(),
			DurationMs:  durationMs,
			Type:        apcap.EventError,
			Protocol:    apcap.ProtocolHTTP,
			Operation:   fmt.Sprintf("%s %s", req.Method, req.URL.Path),
			Source:      apcap.Endpoint{Name: "client", Kind: "agent"},
			Destination: apcap.Endpoint{Name: req.Host, Kind: "service", Host: req.Host},
			Status:      apcap.StatusError,
			Attributes:  map[string]any{"error": err.Error()},
			Provenance:  apcap.ProvenanceObserved,
		})
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBodyBytes, _ := io.ReadAll(resp.Body)

	// Copy response headers to client
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBodyBytes)

	// Parse exchange
	caller := req.Header.Get("X-Agent-Name")
	if caller == "" {
		caller = "client-agent"
	}

	parsedEv := s.modelAdapter.ParseExchange(
		req.Method,
		req.URL.String(),
		req.Host,
		req.URL.Path,
		resp.StatusCode,
		respBodyBytes,
		caller,
		durationMs,
	)

	s.session.Ingest(*parsedEv)
}

// handleConnect handles transparent TCP tunneling (e.g. CONNECT host:443)
func (s *Server) handleConnect(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	targetConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Pipe bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
	}

	go pipe(targetConn, clientConn)
	go pipe(clientConn, targetConn)

	go func() {
		wg.Wait()
		durationMs := float64(time.Since(start).Microseconds()) / 1000.0

		// Log TLS tunnel connection event without intercepting payload
		host, _, _ := net.SplitHostPort(req.Host)
		if host == "" {
			host = req.Host
		}

		s.session.Ingest(apcap.Event{
			ID:          fmt.Sprintf("conn_%d", time.Now().UnixNano()),
			Timestamp:   start.UTC(),
			DurationMs:  durationMs,
			Type:        apcap.EventHTTPRequest,
			Protocol:    apcap.ProtocolHTTP,
			Operation:   fmt.Sprintf("CONNECT %s", req.Host),
			Source:      apcap.Endpoint{Name: "client", Kind: "agent"},
			Destination: apcap.Endpoint{Name: host, Kind: "service", Host: host},
			Status:      apcap.StatusOK,
			Attributes:  map[string]any{"tunnel": "tls_passthrough"},
			Provenance:  apcap.ProvenanceObserved,
		})
	}()
}

// Dummy helper
var _ = url.Parse
