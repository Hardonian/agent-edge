# AgentPCAP v1.0 — Release Blockers Log

**Status:** ALL BLOCKERS RESOLVED — ZERO REMAINING  
**Target Version:** v1.0.0  
**Audit Date:** 2026-09-04  
**Verdict:** **READY FOR RELEASE**

---

## 1. Open Release Blockers

| ID | Category | Severity | Summary | Status |
| :--- | :--- | :--- | :--- | :--- |
| — | — | — | **NO OPEN BLOCKERS** | **CLEARED** |

*There are currently zero open blockers preventing the v1.0.0 release of AgentPCAP.*

---

## 2. Resolved Blockers Prior to Certification

All identified pre-release issues, edge cases, and safety risks were systematically addressed and verified via regression tests:

### BLK-01: Session Subscriber Channel Panics on Concurrent / Duplicate Unsubscribe

- **Severity:** High (Crash / Denial of Service)
- **Subsystem:** `internal/capture/session.go`
- **Root Cause:** Closing an already-closed or un-tracked subscriber channel when consumers disconnected simultaneously or during session shutdown.
- **Resolution:** Introduced atomic existence verification `if _, exists := s.subscribers[ch]; exists` with mutex protection, plus safe drainage and cleanup on `Session.Close()`.
- **Verification:** Verified via `internal/capture/session_test.go` and fast-producer backpressure torture tests under `go test -race`.

### BLK-02: Nil Pointer Dereference in Runner on Immediate Context Cancellation

- **Severity:** High (Crash)
- **Subsystem:** `internal/runner/runner.go`
- **Root Cause:** If a context was canceled before or during `cmd.Start()`, `res` returned as `nil`, causing downstream callers to panic when inspecting exit status.
- **Resolution:** Guaranteed that `runner.Run` always returns a valid, non-nil `*Result{ExitCode: 1, Error: err}` even on early failure or cancellation.
- **Verification:** Verified in `internal/runner/runner_test.go` across multiple cancellation and signal propagation test cases.

### BLK-03: Windows Filename Sanitization in Hostile Archive Test Fixtures

- **Severity:** Medium (Test suite portability)
- **Subsystem:** `tests/torture/hostile_apcap_test.go`
- **Root Cause:** Test names containing `<` and `>` characters failed file creation on Windows NTFS filesystems.
- **Resolution:** Sanitized temporary fixture paths using `strings.NewReplacer("<", "_", ">", "_")`.
- **Verification:** Verified across all platforms (Windows, Linux, macOS).

### BLK-04: Strict Path Traversal & Zip-Slip Invariants on Archive Ingestion

- **Severity:** Critical (Security / Arbitrary File Overwrite)
- **Subsystem:** `pkg/apcap/reader.go`
- **Root Cause:** Archive readers must defensively reject relative paths, absolute paths, and Windows drive specifications (`C:\...`).
- **Resolution:** Hardened `validateSafePath()` to reject entries starting with `/`, `\`, `..`, or drive letters like `C:`.
- **Verification:** Verified via `tests/torture/hostile_apcap_test.go` and `pkg/apcap/fuzz_test.go`.

### BLK-05: Decompression Bomb Defenses

- **Severity:** High (Resource Exhaustion / OOM)
- **Subsystem:** `pkg/apcap/reader.go`
- **Root Cause:** Maliciously crafted gzip/zip archives could consume excessive memory.
- **Resolution:** Enforced `MaxEntrySizeBytes` (128 MB) and `MaxUncompressedBytes` (256 MB) total archive bounds.
- **Verification:** Verified via hostile archive torture tests.

### BLK-06: Zero Shell Interpolation Guarantee

- **Severity:** Critical (Command Injection)
- **Subsystem:** `internal/runner/runner.go`
- **Root Cause:** Executing commands with shell wrappers (`sh -c` or `cmd.exe /c`) allows argument injection.
- **Resolution:** All execution uses direct `exec.CommandContext(ctx, cmd[0], cmd[1:]...)` slices with zero shell wrapper invocation.
- **Verification:** Verified via `internal/runner/runner_test.go` testing malicious argument characters (`|`, `;`, `&&`, `$()`).

### BLK-07: External Binding Security Warnings

- **Severity:** Medium (Network Security)
- **Subsystem:** `cmd/agentpcap/main.go`
- **Root Cause:** Defaulting or inadvertently binding to `0.0.0.0` could expose unauthenticated trace viewers or proxy listeners to local networks.
- **Resolution:** All servers bind strictly to `127.0.0.1` by default. Binding to external interfaces prints high-visibility console security alerts.
- **Verification:** Verified in CLI tests and manual clean-room verification.

---

## 3. Certification Sign-Off

- **Auditor / Sign-Off:** AgentPCAP Core Team
- **Release Ready:** YES
- **Open Blockers:** 0
