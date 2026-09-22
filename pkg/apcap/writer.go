package apcap

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Writer creates a valid .apcap zip bundle.
type Writer struct {
	targetPath string
	file       *os.File
	zipWriter  *zip.Writer

	manifest Manifest
	metadata CaptureMetadata
	events   []Event

	eventHash  hashWriter
	eventCount int
	closed     bool
}

type hashWriter struct {
	hasher io.Writer
	h      [32]byte
}

// WriterOptions provides configuration when creating a new capture file.
type WriterOptions struct {
	CaptureID     string
	CaptureMode   string // e.g. "proxy", "otlp", "sdk", "simulation"
	RedactionMode string // "metadata_only", "sanitized_content"
	Title         string
	Description   string
	Extensions    map[string]any
}

// NewWriter initializes a writer for creating an .apcap file at targetPath.
func NewWriter(targetPath string, opts WriterOptions) (*Writer, error) {
	if opts.CaptureID == "" {
		opts.CaptureID = fmt.Sprintf("cap_%d", time.Now().UnixNano())
	}
	if opts.CaptureMode == "" {
		opts.CaptureMode = "proxy"
	}
	if opts.RedactionMode == "" {
		opts.RedactionMode = "metadata_only"
	}

	dir := filepath.Dir(targetPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create target directory: %w", err)
		}
	}

	f, err := os.Create(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create capture file: %w", err)
	}

	zw := zip.NewWriter(f)

	w := &Writer{
		targetPath: targetPath,
		file:       f,
		zipWriter:  zw,
		manifest: Manifest{
			Format:           FormatIdentifier,
			FormatVersion:    CurrentFormatVersion,
			CaptureID:        opts.CaptureID,
			CreatedAt:        time.Now().UTC(),
			AgentpcapVersion: "1.0.0",
			HostMetadata: HostMetadata{
				OS:        runtime.GOOS,
				Arch:      runtime.GOARCH,
				GoVersion: runtime.Version(),
			},
			CaptureMode:   opts.CaptureMode,
			RedactionMode: opts.RedactionMode,
			ProtocolsSeen: make([]Protocol, 0),
			Hashes:        make(map[string]string),
			Extensions:    opts.Extensions,
		},
		metadata: CaptureMetadata{
			Title:        opts.Title,
			Description:  opts.Description,
			Currency:     "USD",
			CustomLabels: make(map[string]string),
		},
	}

	return w, nil
}

// WriteEvent buffers an event and adds its protocol to seen list.
func (w *Writer) WriteEvent(event Event) {
	w.events = append(w.events, event)
	w.recordProtocol(event.Protocol)
}

func (w *Writer) recordProtocol(proto Protocol) {
	for _, p := range w.manifest.ProtocolsSeen {
		if p == proto {
			return
		}
	}
	w.manifest.ProtocolsSeen = append(w.manifest.ProtocolsSeen, proto)
}

// Close finalizes all entries, computes SHA-256 hashes, writes manifest, and closes archive.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.file.Close()

	w.manifest.CompletedAt = time.Now().UTC()
	w.manifest.EventCount = len(w.events)

	// 1. Write events.jsonl
	eventsHash := sha256.New()
	eventsEntry, err := w.zipWriter.Create("events.jsonl")
	if err != nil {
		_ = w.zipWriter.Close()
		return fmt.Errorf("failed to create events entry: %w", err)
	}

	eventsTee := io.MultiWriter(eventsEntry, eventsHash)
	enc := json.NewEncoder(eventsTee)

	var (
		totalTokens TokenUsage
		totalCost   float64
		errorCount  int
		agents      = make(map[string]bool)
		models      = make(map[string]bool)
		tools       = make(map[string]bool)
		minTime     time.Time
		maxTime     time.Time
	)

	for i, ev := range w.events {
		if i == 0 || ev.Timestamp.Before(minTime) {
			minTime = ev.Timestamp
		}
		end := ev.Timestamp.Add(time.Duration(ev.DurationMs * float64(time.Millisecond)))
		if maxTime.IsZero() || end.After(maxTime) {
			maxTime = end
		}

		if ev.Tokens != nil {
			totalTokens.InputTokens += ev.Tokens.InputTokens
			totalTokens.OutputTokens += ev.Tokens.OutputTokens
			totalTokens.CachedTokens += ev.Tokens.CachedTokens
			totalTokens.TotalTokens += ev.Tokens.TotalTokens
		}
		if ev.Cost != nil {
			totalCost += ev.Cost.Amount
		}
		if ev.Status == StatusError || ev.Status == StatusTimeout {
			errorCount++
		}

		if ev.Source.Kind == "agent" && ev.Source.Name != "" {
			agents[ev.Source.Name] = true
		}
		if ev.Destination.Kind == "agent" && ev.Destination.Name != "" {
			agents[ev.Destination.Name] = true
		}
		if ev.Destination.Kind == "model" && ev.Destination.Name != "" {
			models[ev.Destination.Name] = true
		}
		if ev.Destination.Kind == "tool" && ev.Destination.Name != "" {
			tools[ev.Destination.Name] = true
		}

		if err := enc.Encode(ev); err != nil {
			_ = w.zipWriter.Close()
			return fmt.Errorf("failed encoding event to bundle: %w", err)
		}
	}

	w.manifest.Hashes["events.jsonl"] = hex.EncodeToString(eventsHash.Sum(nil))

	// 2. Compute metadata
	if !maxTime.IsZero() && !minTime.IsZero() {
		w.metadata.TotalDurationMs = float64(maxTime.Sub(minTime).Milliseconds())
	}
	w.metadata.TotalTokens = totalTokens
	w.metadata.TotalCost = totalCost
	w.metadata.AgentCount = len(agents)
	w.metadata.ModelCount = len(models)
	w.metadata.ToolCount = len(tools)
	w.metadata.ErrorCount = errorCount

	// 3. Write metadata.json
	metaHash := sha256.New()
	metaEntry, err := w.zipWriter.Create("metadata.json")
	if err != nil {
		_ = w.zipWriter.Close()
		return fmt.Errorf("failed to create metadata entry: %w", err)
	}
	metaTee := io.MultiWriter(metaEntry, metaHash)
	metaBytes, err := json.MarshalIndent(w.metadata, "", "  ")
	if err != nil {
		_ = w.zipWriter.Close()
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	if _, err := metaTee.Write(metaBytes); err != nil {
		_ = w.zipWriter.Close()
		return fmt.Errorf("failed to write metadata: %w", err)
	}
	w.manifest.Hashes["metadata.json"] = hex.EncodeToString(metaHash.Sum(nil))

	// 4. Write manifest.json
	manifestEntry, err := w.zipWriter.Create("manifest.json")
	if err != nil {
		_ = w.zipWriter.Close()
		return fmt.Errorf("failed to create manifest entry: %w", err)
	}
	manifestBytes, err := json.MarshalIndent(w.manifest, "", "  ")
	if err != nil {
		_ = w.zipWriter.Close()
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	if _, err := manifestEntry.Write(manifestBytes); err != nil {
		_ = w.zipWriter.Close()
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return w.zipWriter.Close()
}

// Save is a convenience function to write a complete Capture struct to disk.
func Save(path string, cap *Capture) error {
	w, err := NewWriter(path, WriterOptions{
		CaptureID:     cap.Manifest.CaptureID,
		CaptureMode:   cap.Manifest.CaptureMode,
		RedactionMode: cap.Manifest.RedactionMode,
		Title:         cap.Metadata.Title,
		Description:   cap.Metadata.Description,
		Extensions:    cap.Manifest.Extensions,
	})
	if err != nil {
		return err
	}

	for _, ev := range cap.Events {
		w.WriteEvent(ev)
	}

	if cap.Metadata.CustomLabels != nil {
		w.metadata.CustomLabels = cap.Metadata.CustomLabels
	}

	return w.Close()
}
