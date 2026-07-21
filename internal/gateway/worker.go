package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/events"
	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

const (
	// retryDelay is the delay before retrying a transient failure
	retryDelay = 5 * time.Second
)

// Worker is the async JetStream consumer that seals receipts into the locker.
type Worker struct {
	js         jetstream.JetStream
	lockerURL  string
	events     *EventPublisher
	jobs       *sync.Map // map[string]*JobInfo
	httpClient *http.Client

	// Shutdown coordination
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewWorker creates a new ingest worker.
func NewWorker(
	js jetstream.JetStream,
	lockerURL string,
	lockerClient *http.Client,
	events *EventPublisher,
	jobs *sync.Map,
) *Worker {
	return &Worker{
		js:         js,
		lockerURL:  lockerURL,
		events:     events,
		jobs:       jobs,
		httpClient: lockerClient,
		stopCh:     make(chan struct{}),
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

	slog.Info("ingest worker started", "consumer", natsinfra.ConsumerIngestWorker)

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
	slog.Info("ingest worker stopped")
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
	var ref IngestRef
	if err := json.Unmarshal(msg.Data(), &ref); err != nil {
		slog.Error("failed to unmarshal IngestRef", "error", err)
		_ = msg.Term()
		return
	}

	slog.Info("processing ingest job", "jobId", ref.JobID, "subjectId", ref.SubjectID, "isDSSE", ref.IsDSSE)

	var processErr error
	if ref.IsDSSE {
		processErr = w.processDSSE(ctx, &ref)
	} else {
		processErr = w.processReceipt(ctx, &ref)
	}

	if processErr != nil {
		// Determine if error is transient or permanent
		if isPermanent(processErr) {
			slog.Error("permanent failure, terminating message", "error", processErr, "jobId", ref.JobID)
			w.updateJobStatus(ref.JobID, Failed, nil, nil)
			_ = msg.Term()
		} else {
			slog.Warn("transient failure, will retry", "error", processErr, "jobId", ref.JobID)
			_ = msg.NakWithDelay(retryDelay)
		}
		return
	}

	// Success - ack the message
	if err := msg.Ack(); err != nil {
		slog.Error("failed to ack message", "error", err, "jobId", ref.JobID)
	}
}

// processReceipt handles the non-DSSE path: seal receipt → publish event.
func (w *Worker) processReceipt(ctx context.Context, ref *IngestRef) error {
	// Seal receipt to locker
	sealResp, err := w.sealToLocker(ctx, ref.SubjectID, ref.ReceiptBytes)
	if err != nil {
		return fmt.Errorf("sealing receipt: %w", err)
	}

	// Publish sealed event
	storageRef := fmt.Sprintf("locker://%s/entry/%d", ref.SubjectID, sealResp.Index)
	if err := w.events.PublishEvidenceSealed(ctx, events.EvidenceSealedData{
		ContentDigest: ref.ContentDigest,
		LogIndex:      sealResp.Index,
		ReceiptDigest: sealResp.Digest,
		ReceiptType:   "gemara-receipt/v1",
		StorageRef:    storageRef,
		SubjectID:     ref.SubjectID,
	}); err != nil {
		slog.Warn("failed to publish CloudEvent", "error", err, "jobId", ref.JobID)
		// Continue - don't fail the job just because event publishing failed
	}

	// Update job status
	digest := sealResp.Digest
	w.updateJobStatus(ref.JobID, Sealed, &digest, &sealResp.Index)

	slog.Info("receipt sealed", "jobId", ref.JobID, "index", sealResp.Index, "digest", sealResp.Digest)
	return nil
}

// processDSSE handles the DSSE path: verify → seal DSSE (if needed) → rebuild DSSE channel receipt → seal → publish event.
func (w *Worker) processDSSE(ctx context.Context, ref *IngestRef) error {
	// Compute DSSE digest
	dsseDigest := computeDigest(ref.DSSEBytes)

	// Check if DSSE already sealed (idempotent retry)
	var dsseIndex int64
	verifyResp, err := w.verifyDigest(ctx, ref.SubjectID, dsseDigest)
	if err != nil {
		return fmt.Errorf("verifying DSSE digest: %w", err)
	}

	if verifyResp.Found {
		// DSSE already sealed, reuse its index
		dsseIndex = verifyResp.Index
		slog.Info("DSSE already sealed", "jobId", ref.JobID, "index", dsseIndex)
	} else {
		// Seal DSSE
		sealResp, err := w.sealToLocker(ctx, ref.SubjectID, ref.DSSEBytes)
		if err != nil {
			return fmt.Errorf("sealing DSSE: %w", err)
		}
		dsseIndex = sealResp.Index
		slog.Info("DSSE sealed", "jobId", ref.JobID, "index", dsseIndex)
	}

	// Rebuild DSSE channel receipt with actual index
	// The handler created a placeholder with index -1; we need to rebuild it with the real index.
	// Parse the placeholder to extract the publisher and payload type.
	var placeholderReceipt map[string]interface{}
	if err := json.Unmarshal(ref.DSSEChannelReceiptBytes, &placeholderReceipt); err != nil {
		return fmt.Errorf("parsing placeholder attestation: %w", err)
	}

	// Extract predicate
	predicate, ok := placeholderReceipt["predicate"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid attestation: missing predicate")
	}

	// Extract publisher
	publisherMap, ok := predicate["publisher"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid attestation: missing publisher")
	}
	publisher := receipt.Publisher{
		Issuer: publisherMap["issuer"].(string),
		Sub:    publisherMap["sub"].(string),
	}

	// Extract payload type
	contentEnvelope, ok := predicate["contentEnvelope"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid attestation: missing contentEnvelope")
	}
	payloadType, ok := contentEnvelope["payloadType"].(string)
	if !ok {
		return fmt.Errorf("invalid attestation: missing payloadType")
	}

	// Rebuild DSSE channel receipt with actual DSSE index
	dsseChannelReceiptBytes, err := receipt.BuildDSSEChannelReceipt(dsseDigest, dsseIndex, publisher, ref.SubjectID, payloadType)
	if err != nil {
		return fmt.Errorf("building DSSE channel receipt: %w", err)
	}

	// Seal DSSE channel receipt
	receiptSealResp, err := w.sealToLocker(ctx, ref.SubjectID, dsseChannelReceiptBytes)
	if err != nil {
		return fmt.Errorf("sealing DSSE channel receipt: %w", err)
	}

	slog.Info("DSSE channel receipt sealed", "jobId", ref.JobID, "index", receiptSealResp.Index)

	// Publish sealed event
	storageRef := fmt.Sprintf("locker://%s/entry/%d", ref.SubjectID, receiptSealResp.Index)
	if err := w.events.PublishEvidenceSealed(ctx, events.EvidenceSealedData{
		ContentDigest: ref.ContentDigest,
		LogIndex:      receiptSealResp.Index,
		ReceiptDigest: receiptSealResp.Digest,
		ReceiptType:   "gemara-dsse-channel-receipt/v1",
		StorageRef:    storageRef,
		SubjectID:     ref.SubjectID,
	}); err != nil {
		slog.Warn("failed to publish CloudEvent", "error", err, "jobId", ref.JobID)
		// Continue
	}

	// Update job status (use DSSE channel receipt digest/index as the primary result)
	digest := receiptSealResp.Digest
	w.updateJobStatus(ref.JobID, Sealed, &digest, &receiptSealResp.Index)

	return nil
}

// sealToLocker sends bytes to the locker seal endpoint.
func (w *Worker) sealToLocker(ctx context.Context, subjectID string, data []byte) (*SealResponse, error) {
	url := fmt.Sprintf("%s/ledgers/%s/seal", w.lockerURL, subjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, &LockerError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	var sealResp SealResponse
	if err := json.NewDecoder(resp.Body).Decode(&sealResp); err != nil {
		return nil, fmt.Errorf("decoding seal response: %w", err)
	}

	return &sealResp, nil
}

// verifyDigest checks if a digest is already sealed in the locker.
func (w *Worker) verifyDigest(ctx context.Context, subjectID, digest string) (*VerifyResponse, error) {
	url := fmt.Sprintf("%s/ledgers/%s/verify/%s", w.lockerURL, subjectID, digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &LockerError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	var verifyResp VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		return nil, fmt.Errorf("decoding verify response: %w", err)
	}

	return &verifyResp, nil
}

// updateJobStatus updates the job status in the shared jobs map.
func (w *Worker) updateJobStatus(jobID string, status JobStatusStatus, digest *string, logIndex *int64) {
	value, ok := w.jobs.Load(jobID)
	if !ok {
		slog.Warn("job not found in tracker", "jobId", jobID)
		return
	}

	jobInfo := value.(*JobInfo)
	jobInfo.Status = status
	jobInfo.Digest = digest
	jobInfo.LogIndex = logIndex
	w.jobs.Store(jobID, jobInfo)
}

// computeDigest computes SHA-256 digest in the format expected by locker (hex-encoded).
func computeDigest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// LockerError represents an error from the locker API.
type LockerError struct {
	StatusCode int
	Message    string
}

func (e *LockerError) Error() string {
	return fmt.Sprintf("locker error (status %d): %s", e.StatusCode, e.Message)
}

// SealResponse is the locker's response to a seal request.
type SealResponse struct {
	Index  int64  `json:"index"`
	Digest string `json:"digest"`
}

// VerifyResponse is the locker's response to a verify request.
type VerifyResponse struct {
	Found bool  `json:"found"`
	Index int64 `json:"index,omitempty"`
}

// isPermanent determines if an error should terminate the message vs. retry.
// Checks if the error is a LockerError (potentially wrapped) with a permanent status code.
func isPermanent(err error) bool {
	// Check for LockerError in error chain
	for e := err; e != nil; {
		if lockerErr, ok := e.(*LockerError); ok {
			// Permanent errors: client errors that won't be fixed by retrying
			switch lockerErr.StatusCode {
			case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict:
				return true
			default:
				// 5xx errors are transient
				return false
			}
		}
		// Try unwrapping
		unwrapped, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = unwrapped.Unwrap()
	}

	// Non-locker errors are considered transient (network, timeout, etc.)
	return false
}
