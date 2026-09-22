package capture

import (
	"fmt"
	"sync"
	"time"

	"github.com/agentpcap/agentpcap/internal/redact"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// SessionConfig configures capture behavior and bounds.
type SessionConfig struct {
	CaptureID      string
	Title          string
	Description    string
	CaptureMode    string
	CaptureContent bool // false = metadata_only, true = sanitized_content
	MaxEvents      int  // default 100,000
	OutputPath     string
}

// Session coordinates active capture ingestion, live subscribers, and persistence.
type Session struct {
	mu          sync.RWMutex
	cfg         SessionConfig
	manifest    apcap.Manifest
	metadata    apcap.CaptureMetadata
	events      []apcap.Event
	subscribers map[chan apcap.Event]struct{}
	redactor    *redact.Redactor
	closed      bool
}

// NewSession creates an active capture session.
func NewSession(cfg SessionConfig) *Session {
	if cfg.CaptureID == "" {
		cfg.CaptureID = fmt.Sprintf("cap_%d", time.Now().Unix())
	}
	if cfg.CaptureMode == "" {
		cfg.CaptureMode = "proxy"
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 100000
	}

	redactionMode := "metadata_only"
	if cfg.CaptureContent {
		redactionMode = "sanitized_content"
	}

	return &Session{
		cfg: cfg,
		manifest: apcap.Manifest{
			Format:           apcap.FormatIdentifier,
			FormatVersion:    apcap.CurrentFormatVersion,
			CaptureID:        cfg.CaptureID,
			CreatedAt:        time.Now().UTC(),
			AgentpcapVersion: "1.0.0",
			CaptureMode:      cfg.CaptureMode,
			RedactionMode:    redactionMode,
			ProtocolsSeen:    make([]apcap.Protocol, 0),
			Hashes:           make(map[string]string),
		},
		metadata: apcap.CaptureMetadata{
			Title:        cfg.Title,
			Description:  cfg.Description,
			Currency:     "USD",
			CustomLabels: make(map[string]string),
		},
		events:      make([]apcap.Event, 0, 1024),
		subscribers: make(map[chan apcap.Event]struct{}),
		redactor:    redact.New(),
	}
}

// Ingest sanitizes and adds an event, then notifies all live stream subscribers.
func (s *Session) Ingest(ev apcap.Event) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}

	// Enforce max event limits
	if len(s.events) >= s.cfg.MaxEvents {
		s.mu.Unlock()
		return
	}

	// Redact secrets
	cleanEv := *s.redactor.RedactEvent(&ev)

	// If metadata-only mode, strip payload preview
	if !s.cfg.CaptureContent && cleanEv.Payload != nil {
		cleanEv.Payload.Preview = ""
	}

	s.events = append(s.events, cleanEv)
	s.recordProtocolLocked(cleanEv.Protocol)
	s.updateMetadataLocked(cleanEv)

	// Broadcast to active subscribers
	for ch := range s.subscribers {
		select {
		case ch <- cleanEv:
		default:
			// Non-blocking drop if subscriber buffer is full
		}
	}
	s.mu.Unlock()
}

func (s *Session) recordProtocolLocked(p apcap.Protocol) {
	for _, seen := range s.manifest.ProtocolsSeen {
		if seen == p {
			return
		}
	}
	s.manifest.ProtocolsSeen = append(s.manifest.ProtocolsSeen, p)
}

func (s *Session) updateMetadataLocked(ev apcap.Event) {
	if ev.Tokens != nil {
		s.metadata.TotalTokens.InputTokens += ev.Tokens.InputTokens
		s.metadata.TotalTokens.OutputTokens += ev.Tokens.OutputTokens
		s.metadata.TotalTokens.CachedTokens += ev.Tokens.CachedTokens
		s.metadata.TotalTokens.TotalTokens += ev.Tokens.TotalTokens
	}
	if ev.Cost != nil {
		s.metadata.TotalCost += ev.Cost.Amount
	}
	if ev.Status == apcap.StatusError || ev.Status == apcap.StatusTimeout {
		s.metadata.ErrorCount++
	}
}

// Subscribe returns a channel receiving newly ingested events in real-time.
func (s *Session) Subscribe() (chan apcap.Event, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan apcap.Event, 256)
	s.subscribers[ch] = struct{}{}

	unsubscribe := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, exists := s.subscribers[ch]; exists {
			delete(s.subscribers, ch)
			close(ch)
		}
	}

	return ch, unsubscribe
}

// Events returns a snapshot of all events captured so far.
func (s *Session) Events() []apcap.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]apcap.Event, len(s.events))
	copy(copied, s.events)
	return copied
}

// Capture produces a finished *apcap.Capture struct.
func (s *Session) Capture() *apcap.Capture {
	s.mu.RLock()
	defer s.mu.RUnlock()

	manifest := s.manifest
	manifest.CompletedAt = time.Now().UTC()
	manifest.EventCount = len(s.events)

	metadata := s.metadata
	copiedEvents := make([]apcap.Event, len(s.events))
	copy(copiedEvents, s.events)

	return &apcap.Capture{
		Manifest: manifest,
		Metadata: metadata,
		Events:   copiedEvents,
	}
}

// Close finalizes the session and saves to OutputPath if specified.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.manifest.CompletedAt = time.Now().UTC()
	s.manifest.EventCount = len(s.events)
	for ch := range s.subscribers {
		delete(s.subscribers, ch)
		close(ch)
	}
	s.mu.Unlock()

	if s.cfg.OutputPath != "" {
		return apcap.Save(s.cfg.OutputPath, s.Capture())
	}
	return nil
}

// Reset clears existing events and reinitializes metadata for a fresh run.
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make([]apcap.Event, 0, 1024)
	s.manifest.CreatedAt = time.Now().UTC()
	s.manifest.CompletedAt = time.Time{}
	s.manifest.ProtocolsSeen = make([]apcap.Protocol, 0)
	s.manifest.EventCount = 0
	s.metadata.TotalDurationMs = 0
	s.metadata.TotalTokens = apcap.TokenUsage{}
	s.metadata.TotalCost = 0
	s.metadata.ErrorCount = 0
	s.metadata.AgentCount = 0
	s.metadata.ToolCount = 0
	s.metadata.ModelCount = 0
	s.closed = false
}
