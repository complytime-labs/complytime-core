package locker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/events"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/ingest"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

const (
	// retryDelay is the delay before retrying a transient failure
	retryDelay = 5 * time.Second
)

// Worker is the async JetStream consumer that seals receipts into the locker.
type Worker struct {
	js     jetstream.JetStream
	locker *Locker
	events *eventspkg.EventPublisher

	// Shutdown coordination
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewWorker creates a new ingest worker.
func NewWorker(
	js jetstream.JetStream,
	locker *Locker,
	events *eventspkg.EventPublisher,
) *Worker {
	return &Worker{
		js:     js,
		locker: locker,
		events: events,
		stopCh: make(chan struct{}),
	}
}

// Start creates the durable consumer and begins processing messages.
// Blocks until ctx is cancelled.
func (w *Worker) Start(ctx context.Context) error {
	// Create or get the durable consumer
	consumer, err := w.js.CreateOrUpdateConsumer(ctx, natsinfra.StreamIngest, natsinfra.IngestConsumerConfig())
	if err != nil {
		return fmt.Errorf("creating ingest consumer: %w", err)
	}

	slog.Info("locker ingest worker started", "consumer", natsinfra.ConsumerIngestWorker)

	// Start message processing goroutine
	w.wg.Add(1)
	go w.processMessages(ctx, consumer)

	// Wait for shutdown
	<-ctx.Done()
	return w.Stop()
}

// Stop signals the worker to stop and waits for it to drain.
// Idempotent - safe to call multiple times.
func (w *Worker) Stop() error {
	w.stopOnce.Do(func() {
		close(w.stopCh)
	})
	w.wg.Wait()
	slog.Info("locker ingest worker stopped")
	return nil
}

// processMessages is the main message processing loop.
func (w *Worker) processMessages(ctx context.Context, consumer jetstream.Consumer) {
	defer w.wg.Done()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ctx.Done():
			return
		default:
			// Fetch next message with timeout
			msgs, err := consumer.Fetch(1, jetstream.FetchMaxWait(5*time.Second))

			if err != nil {
				// Check if context was cancelled
				select {
				case <-ctx.Done():
					return
				default:
					// Log error and continue
					if err != context.DeadlineExceeded {
						slog.Warn("failed to fetch message", "error", err)
					}
					continue
				}
			}

			// Process each message
			for msg := range msgs.Messages() {
				w.handleMessage(ctx, msg)
			}

			// Check if msgs channel closed due to error
			if msgs.Error() != nil {
				slog.Warn("fetch messages error", "error", msgs.Error())
			}
		}
	}
}

// handleMessage processes a single IngestRef message.
func (w *Worker) handleMessage(ctx context.Context, msg jetstream.Msg) {
	// Deserialize IngestRef
	var ref ingest.IngestRef
	if err := json.Unmarshal(msg.Data(), &ref); err != nil {
		slog.Error("failed to unmarshal IngestRef", "error", err)
		_ = msg.Term()
		return
	}

	slog.Info("processing ingest job", "jobId", ref.JobID, "subjectId", ref.SubjectID)

	processErr := w.processReceipt(ctx, &ref)
	if processErr != nil {
		// Determine if error is transient or permanent
		if isPermanent(processErr) {
			slog.Error("permanent failure, terminating message", "error", processErr, "jobId", ref.JobID)
			_ = msg.Term()
		} else {
			slog.Warn("transient failure, will retry", "error", processErr, "jobId", ref.JobID)
			_ = msg.NakWithDelay(retryDelay)
		}
		return
	}

	// Success - ack the message
	slog.Info("receipt sealed successfully", "jobId", ref.JobID)
	if err := msg.Ack(); err != nil {
		slog.Error("failed to ack message", "error", err, "jobId", ref.JobID)
	}
}

// processReceipt handles receipt sealing: seal receipt → publish event → update status.
func (w *Worker) processReceipt(ctx context.Context, ref *ingest.IngestRef) error {
	// Get the ledger
	ledger, ok := w.locker.GetLedger(ref.SubjectID)
	if !ok {
		return &LedgerNotFoundError{SubjectID: ref.SubjectID}
	}

	// Check for duplicate (NATS retry) before sealing
	digest := SHA256Hex(ref.ReceiptBytes)
	if _, found := ledger.VerifyDigest(digest); found {
		// Already sealed (NATS retry) — skip
		slog.Info("receipt already sealed, skipping", "jobId", ref.JobID, "digest", digest)
		return nil
	}

	// Seal receipt to locker
	index, err := ledger.Seal(ctx, ref.ReceiptBytes)
	if err != nil {
		return fmt.Errorf("sealing receipt: %w", err)
	}

	// Publish sealed event
	storageRef := fmt.Sprintf("locker://%s/entry/%d", ref.SubjectID, index)
	// #nosec G115 -- Tessera index is uint64, CloudEvents schema uses int64. Overflow at 2^63 entries is not a practical concern.
	logIndex := int64(index)
	if err := w.events.PublishEvidenceSealed(ctx, events.EvidenceSealedData{
		ContentDigest: ref.ContentDigest,
		LogIndex:      logIndex,
		ReceiptDigest: digest,
		ReceiptType:   "gemara-receipt/v1",
		StorageRef:    storageRef,
		SubjectID:     ref.SubjectID,
	}); err != nil {
		slog.Warn("failed to publish CloudEvent", "error", err, "jobId", ref.JobID)
		// Continue - don't fail the job just because event publishing failed
	}

	slog.Info("receipt sealed", "jobId", ref.JobID, "index", index, "digest", digest)
	return nil
}

// LedgerNotFoundError is returned when a ledger for a subject doesn't exist.
type LedgerNotFoundError struct {
	SubjectID string
}

func (e *LedgerNotFoundError) Error() string {
	return fmt.Sprintf("ledger not found for subject: %s", e.SubjectID)
}

// isPermanent determines if an error should terminate the message vs. retry.
func isPermanent(err error) bool {
	// LedgerNotFoundError is permanent — the subject hasn't been registered
	if _, ok := err.(*LedgerNotFoundError); ok {
		return true
	}

	// Context cancellation is permanent
	if err == context.Canceled {
		return true
	}

	// All other errors are transient (Tessera write failures, etc.)
	return false
}
