# The Open .APCAP Format

## Specification Version: 1.0.0

`.apcap` (Agent Packet Capture) is an open, portable, and versioned container format for multi-agent traces, model calls, and protocol packets.

## Container Structure

An `.apcap` file is an unencrypted standard ZIP container containing:

```text
capture.apcap
├── manifest.json       # Top-level capture metadata and SHA-256 hashes
├── metadata.json       # Aggregate metrics (duration, tokens, cost, errors)
├── events.jsonl        # Line-delimited canonical event stream
└── attachments/        # Optional sanitized payload previews and logs
```

---

## 1. `manifest.json` Schema

```json
{
  "format": "apcap",
  "format_version": "1.0.0",
  "capture_id": "cap_1725450000",
  "created_at": "2026-09-04T15:00:00Z",
  "completed_at": "2026-09-04T15:00:05Z",
  "agentpcap_version": "1.0.0",
  "host_metadata": {
    "os": "windows",
    "arch": "amd64",
    "go_version": "go1.26.3"
  },
  "capture_mode": "child_process",
  "redaction_mode": "metadata_only",
  "protocols_seen": ["A2A", "MCP", "MODEL", "TOOL"],
  "event_count": 12,
  "attachment_count": 0,
  "hashes": {
    "events.jsonl": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "metadata.json": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
  }
}
```

---

## 2. `events.jsonl` Schema

Each line in `events.jsonl` contains a single JSON-encoded `apcap.Event`:

```json
{
  "id": "ev_demo_05",
  "trace_id": "trace_demo_simulation_001",
  "parent_id": "ev_demo_02",
  "timestamp": "2026-09-04T15:00:01.090Z",
  "duration_ms": 820.0,
  "type": "MODEL_RESPONSE",
  "protocol": "MODEL",
  "operation": "gemini:gemini-1.5-pro",
  "source": { "name": "research-agent", "kind": "agent" },
  "destination": { "name": "gemini-1.5-pro", "kind": "model" },
  "status": "OK",
  "attributes": {
    "model.provider": "google",
    "model.name": "gemini-1.5-pro"
  },
  "tokens": {
    "input_tokens": 1850,
    "output_tokens": 640,
    "cached_tokens": 256,
    "total_tokens": 2490
  },
  "cost": {
    "amount": 0.0055,
    "currency": "USD",
    "status": "ESTIMATED",
    "source": "pricing-snapshot-v1"
  },
  "provenance": "PROTOCOL_PARSED"
}
```

---

## 3. Go Library (`pkg/apcap`)

Third-party Go applications can read and write `.apcap` files directly:

```go
import "github.com/agentpcap/agentpcap/pkg/apcap"

// Open and parse an archive safely
cap, err := apcap.Open("run.apcap")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Parsed %d events from capture %s\n", len(cap.Events), cap.Manifest.CaptureID)
```
