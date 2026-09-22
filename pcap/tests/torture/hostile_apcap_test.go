package torture_test

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestHostileApcap_CorruptAndMaliciousFiles(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		generator func(path string) error
		mustFail  bool
	}{
		{
			name: "zero-byte file",
			generator: func(path string) error {
				return os.WriteFile(path, []byte{}, 0644)
			},
			mustFail: true,
		},
		{
			name: "truncated zip header",
			generator: func(path string) error {
				return os.WriteFile(path, []byte("PK\x03\x04truncated"), 0644)
			},
			mustFail: true,
		},
		{
			name: "missing manifest.json",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				ew, _ := zw.Create("events.jsonl")
				_, _ = ew.Write([]byte("{}\n"))
				return zw.Close()
			},
			mustFail: true,
		},
		{
			name: "missing events.jsonl",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"1.0.0","capture_id":"c1"}`))
				return zw.Close()
			},
			mustFail: true,
		},
		{
			name: "zip slip with backslashes and relative parents",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"1.0.0","capture_id":"c1"}`))
				bad, _ := zw.Create(`..\..\..\..\..\..\evil.txt`)
				_, _ = bad.Write([]byte("malicious content"))
				return zw.Close()
			},
			mustFail: true,
		},
		{
			name: "drive letter traversal C:evil.bat",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"1.0.0","capture_id":"c1"}`))
				bad, _ := zw.Create(`C:\Temp\evil.bat`)
				_, _ = bad.Write([]byte("format C:"))
				return zw.Close()
			},
			mustFail: true,
		},
		{
			name: "corrupted SHA-256 hash in manifest",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{
					"format":"apcap",
					"format_version":"1.0.0",
					"capture_id":"c1",
					"hashes": {"events.jsonl": "0000000000000000000000000000000000000000000000000000000000000000"}
				}`))
				ew, _ := zw.Create("events.jsonl")
				_, _ = ew.Write([]byte(`{"id":"e1","trace_id":"t1","timestamp":"2026-09-04T12:00:00Z","operation":"op"}` + "\n"))
				return zw.Close()
			},
			mustFail: true,
		},
		{
			name: "future major version 4.0.0",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"4.0.0","capture_id":"c1"}`))
				ew, _ := zw.Create("events.jsonl")
				_, _ = ew.Write([]byte("{}\n"))
				return zw.Close()
			},
			mustFail: true,
		},
		{
			name: "too many entries in archive (>5000 entries)",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"1.0.0","capture_id":"c1"}`))
				ew, _ := zw.Create("events.jsonl")
				_, _ = ew.Write([]byte("{}\n"))
				for i := 0; i < 5005; i++ {
					w, _ := zw.Create(fmt.Sprintf("attachments/att_%d.txt", i))
					_, _ = w.Write([]byte("x"))
				}
				return zw.Close()
			},
			mustFail: true,
		},
		{
			name: "truncated trailing event line (crash recovery)",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"1.0.0","capture_id":"c1"}`))
				ew, _ := zw.Create("events.jsonl")
				// Line 1 is valid, Line 2 is half-written mid-flush
				_, _ = ew.Write([]byte(`{"id":"e1","trace_id":"t1","timestamp":"2026-09-04T12:00:00Z","operation":"op"}` + "\n" + `{"id":"e2","trace_id":`))
				return zw.Close()
			},
			mustFail: false, // Incomplete lines are tolerated gracefully, reading all preceding valid events
		},
		{
			name: "malformed UTF-8 in events",
			generator: func(path string) error {
				f, err := os.Create(path)
				if err != nil {
					return err
				}
				defer f.Close()
				zw := zip.NewWriter(f)
				mw, _ := zw.Create("manifest.json")
				_, _ = mw.Write([]byte(`{"format":"apcap","format_version":"1.0.0","capture_id":"c1"}`))
				ew, _ := zw.Create("events.jsonl")
				// Invalid UTF-8 sequence
				_, _ = ew.Write([]byte("{\"id\":\"e1\",\"operation\":\"\xff\xfe\xfd\"}\n"))
				return zw.Close()
			},
			mustFail: false, // JSON parser accepts or escapes invalid bytes without panic
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC TRIGGERED on hostile archive %q: %v", tc.name, r)
				}
			}()

			safeName := strings.NewReplacer(" ", "_", ">", "gt", "<", "lt", ":", "_", "/", "_", "\\", "_", "|", "_", "?", "_", "*", "_").Replace(tc.name)
			filePath := filepath.Join(tempDir, safeName+".apcap")
			if err := tc.generator(filePath); err != nil {
				t.Fatalf("failed generating test file: %v", err)
			}

			cap, err := apcap.Open(filePath)
			if tc.mustFail && err == nil {
				t.Errorf("expected archive to be rejected, but Open succeeded")
			}
			if !tc.mustFail && err != nil {
				t.Errorf("expected archive to be tolerated, got error: %v", err)
			}
			if !tc.mustFail && cap == nil {
				t.Errorf("expected non-nil capture for %q", tc.name)
			}
		})
	}
}
