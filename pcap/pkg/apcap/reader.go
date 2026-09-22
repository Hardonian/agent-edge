package apcap

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Safety thresholds to prevent resource exhaustion and decompression bombs.
const (
	MaxArchiveEntries    = 5000
	MaxUncompressedBytes = 256 * 1024 * 1024 // 256 MB total uncompressed limit
	MaxEntrySizeBytes    = 128 * 1024 * 1024 // 128 MB max single entry
	MaxEventLineBytes    = 10 * 1024 * 1024  // 10 MB per JSONL line
)

// Capture represents a fully parsed APCAP capture file.
type Capture struct {
	Manifest Manifest        `json:"manifest"`
	Metadata CaptureMetadata `json:"metadata"`
	Events   []Event         `json:"events"`
}

// Reader provides safe inspection of an .apcap file.
type Reader struct {
	zipReader *zip.ReadCloser
	totalRead int64
}

// Open opens and parses an .apcap capture file from disk with strict security boundaries.
func Open(filePath string) (*Capture, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat capture file: %w", err)
	}
	if fileInfo.Size() == 0 {
		return nil, ErrInvalidCapture
	}

	zr, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCapture, err)
	}
	defer zr.Close()

	if len(zr.File) > MaxArchiveEntries {
		return nil, fmt.Errorf("%w: archive contains %d entries (limit %d)", ErrCaptureLimit, len(zr.File), MaxArchiveEntries)
	}

	var (
		manifestFile   *zip.File
		metadataFile   *zip.File
		eventsFile     *zip.File
		totalReadBytes int64
	)

	// Validate entries for Zip-slip and excessive declared sizes
	for _, f := range zr.File {
		if err := validateSafePath(f.Name); err != nil {
			return nil, err
		}
		if f.UncompressedSize64 > MaxEntrySizeBytes {
			return nil, fmt.Errorf("%w: entry %s exceeds max size (%d > %d)", ErrDecompressionBomb, f.Name, f.UncompressedSize64, MaxEntrySizeBytes)
		}
		cleanName := path.Clean(f.Name)
		switch cleanName {
		case "manifest.json":
			manifestFile = f
		case "metadata.json":
			metadataFile = f
		case "events.jsonl":
			eventsFile = f
		}
	}

	if manifestFile == nil {
		return nil, fmt.Errorf("%w: missing manifest.json", ErrInvalidCapture)
	}
	if eventsFile == nil {
		return nil, fmt.Errorf("%w: missing events.jsonl", ErrInvalidCapture)
	}

	// 1. Read and parse manifest
	manifestBytes, err := readBoundedEntry(manifestFile, &totalReadBytes)
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("%w: invalid manifest JSON: %v", ErrInvalidCapture, err)
	}

	if manifest.Format != FormatIdentifier {
		return nil, fmt.Errorf("%w: unrecognized format '%s'", ErrInvalidCapture, manifest.Format)
	}

	// Check major version compatibility
	majorVersion := strings.Split(manifest.FormatVersion, ".")[0]
	if majorVersion != "1" {
		return nil, fmt.Errorf("%w: capture version %s incompatible with current 1.x", ErrUnsupportedVersion, manifest.FormatVersion)
	}

	// 2. Read metadata.json if present
	var metadata CaptureMetadata
	if metadataFile != nil {
		metadataBytes, err := readBoundedEntry(metadataFile, &totalReadBytes)
		if err == nil {
			_ = json.Unmarshal(metadataBytes, &metadata)
		}
	}

	// 3. Stream events.jsonl with streaming byte counter and calculate SHA-256
	eventsRc, err := eventsFile.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open events.jsonl: %w", err)
	}
	defer eventsRc.Close()

	eventsHasher := sha256.New()
	counter := &countingReader{
		r:         eventsRc,
		totalRead: &totalReadBytes,
		maxBytes:  MaxUncompressedBytes,
	}
	teeReader := io.TeeReader(counter, eventsHasher)

	eventsScanner := bufio.NewScanner(teeReader)
	buf := make([]byte, 64*1024)
	eventsScanner.Buffer(buf, MaxEventLineBytes)

	var events []Event
	lineNum := 0
	for eventsScanner.Scan() {
		lineNum++
		line := bytes.TrimSpace(eventsScanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			// Gracefully stop on trailing truncated line
			break
		}
		events = append(events, ev)
	}

	if err := eventsScanner.Err(); err != nil {
		if errors.Is(err, ErrDecompressionBomb) {
			return nil, ErrDecompressionBomb
		}
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("%w: single line exceeded %d bytes", ErrDecompressionBomb, MaxEventLineBytes)
		}
	}

	// 4. Verify integrity hash if manifest has events.jsonl hash
	calculatedHash := hex.EncodeToString(eventsHasher.Sum(nil))
	if expectedHash, ok := manifest.Hashes["events.jsonl"]; ok && expectedHash != "" {
		if !strings.EqualFold(calculatedHash, expectedHash) {
			return nil, fmt.Errorf("%w: events.jsonl SHA256 mismatch (expected %s, got %s)", ErrCorruptBundle, expectedHash, calculatedHash)
		}
	}

	return &Capture{
		Manifest: manifest,
		Metadata: metadata,
		Events:   events,
	}, nil
}

type countingReader struct {
	r         io.Reader
	totalRead *int64
	maxBytes  int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		*cr.totalRead += int64(n)
		if *cr.totalRead > cr.maxBytes {
			return n, ErrDecompressionBomb
		}
	}
	return n, err
}

// validateSafePath ensures the archive entry does not escape destination directory.
func validateSafePath(entryName string) error {
	cleaned := path.Clean(filepath.ToSlash(entryName))
	if strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, `\`) || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return fmt.Errorf("%w: %s", ErrPathTraversal, entryName)
	}
	// Also prevent Windows absolute drive paths (e.g. C:)
	if len(cleaned) > 1 && cleaned[1] == ':' {
		return fmt.Errorf("%w: %s", ErrPathTraversal, entryName)
	}
	return nil
}

// readBoundedEntry reads a zip file entry up to safety limits.
func readBoundedEntry(f *zip.File, totalRead *int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	remainingTotal := MaxUncompressedBytes - *totalRead
	if remainingTotal <= 0 {
		return nil, ErrDecompressionBomb
	}

	limit := int64(MaxEntrySizeBytes)
	if remainingTotal < limit {
		limit = remainingTotal
	}

	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return nil, fmt.Errorf("error reading entry %s: %w", f.Name, err)
	}
	*totalRead += int64(len(data))
	if *totalRead > MaxUncompressedBytes {
		return nil, ErrDecompressionBomb
	}

	return data, nil
}
