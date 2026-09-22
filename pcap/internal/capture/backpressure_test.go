package capture_test

import (
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestSession_BackpressureSlowSubscriber(t *testing.T) {
	sess := capture.NewSession(capture.SessionConfig{
		CaptureID: "backpressure_test",
		MaxEvents: 20000,
	})

	// Create subscriber channel with standard buffer (256) but do NOT read from it
	_, unsubscribe := sess.Subscribe()
	defer unsubscribe()

	// Ingest 5000 events rapidly (far exceeding the 256 buffer)
	// Must not deadlock or hang
	done := make(chan bool)
	go func() {
		for i := 0; i < 5000; i++ {
			sess.Ingest(apcap.Event{
				ID:         "ev_bulk",
				Timestamp:  time.Now().UTC(),
				DurationMs: 0.5,
				Protocol:   apcap.ProtocolA2A,
				Operation:  "task/ping",
				Status:     apcap.StatusOK,
			})
		}
		done <- true
	}()

	select {
	case <-done:
		// Succeeded in non-blocking broadcast
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK / BLOCKING DETECTED: fast producer hung on slow subscriber")
	}

	// Invariant: Canonical storage preserved 100% of the 5000 events without loss
	events := sess.Events()
	if len(events) != 5000 {
		t.Errorf("expected 5000 canonically preserved events, got %d", len(events))
	}
}

func TestSession_EventLossDefense(t *testing.T) {
	sess := capture.NewSession(capture.SessionConfig{
		CaptureID: "event_loss_test",
		MaxEvents: 10000,
	})

	expectedCount := 1000
	for i := 0; i < expectedCount; i++ {
		sess.Ingest(apcap.Event{
			ID:         "ev",
			Timestamp:  time.Now().UTC(),
			DurationMs: 1.0,
			Protocol:   apcap.ProtocolModel,
			Operation:  "generate",
			Status:     apcap.StatusOK,
			Tokens: &apcap.TokenUsage{
				InputTokens:  10,
				OutputTokens: 20,
				TotalTokens:  30,
			},
			Cost: &apcap.Money{
				Amount: 0.0001,
			},
		})
	}

	cap := sess.Capture()
	if len(cap.Events) != expectedCount {
		t.Errorf("expected %d events in capture, got %d", expectedCount, len(cap.Events))
	}
	if cap.Manifest.EventCount != expectedCount {
		t.Errorf("expected manifest event count %d, got %d", expectedCount, cap.Manifest.EventCount)
	}
	if cap.Metadata.TotalTokens.TotalTokens != int64(expectedCount*30) {
		t.Errorf("expected total tokens %d, got %d", expectedCount*30, cap.Metadata.TotalTokens.TotalTokens)
	}
}
