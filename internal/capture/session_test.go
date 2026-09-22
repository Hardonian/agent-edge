package capture_test

import (
	"sync"
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestSession_ConcurrencyAndRace(t *testing.T) {
	sess := capture.NewSession(capture.SessionConfig{
		CaptureID: "race_test_session",
		MaxEvents: 50000,
	})

	var wg sync.WaitGroup

	// Subscriber 1
	ch1, unsub1 := sess.Subscribe()
	defer unsub1()

	// Subscriber 2
	ch2, unsub2 := sess.Subscribe()
	defer unsub2()

	// Consumer routine 1
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range ch1 {
			// consume
		}
	}()

	// Consumer routine 2
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range ch2 {
			// consume
		}
	}()

	// Concurrent producers
	numProducers := 5
	eventsPerProducer := 200

	var producerWg sync.WaitGroup
	for p := 0; p < numProducers; p++ {
		producerWg.Add(1)
		go func(pID int) {
			defer producerWg.Done()
			for i := 0; i < eventsPerProducer; i++ {
				sess.Ingest(apcap.Event{
					ID:         "ev",
					Timestamp:  time.Now().UTC(),
					DurationMs: 1.0,
					Protocol:   apcap.ProtocolMCP,
					Operation:  "tools/call",
					Status:     apcap.StatusOK,
				})
			}
		}(p)
	}

	// Concurrent reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_ = sess.Events()
			_ = sess.Capture()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Wait for all producers to finish (reliable barrier instead of sleep)
	producerWg.Wait()

	// Close session & subscribers
	unsub1()
	unsub2()
	_ = sess.Close()
	wg.Wait()

	events := sess.Events()
	expectedTotal := numProducers * eventsPerProducer
	if len(events) != expectedTotal {
		t.Errorf("expected %d events, got %d", expectedTotal, len(events))
	}
}

func TestSession_MetadataOnlyMode(t *testing.T) {
	sess := capture.NewSession(capture.SessionConfig{
		CaptureContent: false, // metadata only
	})

	sess.Ingest(apcap.Event{
		ID:        "ev_meta",
		Operation: "chat",
		Payload: &apcap.PayloadRef{
			Preview: "this raw prompt preview must be stripped",
			Length:  100,
		},
	})

	evs := sess.Events()
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Payload != nil && evs[0].Payload.Preview != "" {
		t.Errorf("expected empty payload preview in metadata-only mode, got %q", evs[0].Payload.Preview)
	}
}
