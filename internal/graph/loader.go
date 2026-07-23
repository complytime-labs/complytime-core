package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/events"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

const (
	fetchBatchSize = 10
	fetchTimeout   = 5 * time.Second
	retryDelay     = 5 * time.Second
)

// Loader consumes CloudEvents from the EVIDENCE stream and materializes
// the knowledge graph in Memgraph.
type Loader struct {
	js         jetstream.JetStream
	writer     *Writer
	lockerURL  string
	httpClient *http.Client

	// Shutdown coordination
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewLoader creates a new graph loader.
func NewLoader(
	js jetstream.JetStream,
	writer *Writer,
	lockerURL string,
	httpClient *http.Client,
) *Loader {
	return &Loader{
		js:         js,
		writer:     writer,
		lockerURL:  lockerURL,
		httpClient: httpClient,
		stopCh:     make(chan struct{}),
	}
}

// Start creates the durable consumer and begins processing CloudEvents.
// Blocks until ctx is cancelled.
func (l *Loader) Start(ctx context.Context) error {
	consumer, err := l.js.CreateOrUpdateConsumer(ctx, natsinfra.StreamEvidence, natsinfra.GraphLoaderConsumerConfig())
	if err != nil {
		return fmt.Errorf("creating graph loader consumer: %w", err)
	}

	slog.Info("graph loader started", "consumer", natsinfra.ConsumerGraphLoader)

	l.wg.Add(1)
	go l.consume(ctx, consumer)

	<-ctx.Done()
	return l.Stop()
}

// Stop signals the loader to stop and waits for it to drain.
func (l *Loader) Stop() error {
	l.stopOnce.Do(func() {
		close(l.stopCh)
	})
	l.wg.Wait()
	slog.Info("graph loader stopped")
	return nil
}

// consume is the main message processing loop.
func (l *Loader) consume(ctx context.Context, consumer jetstream.Consumer) {
	defer l.wg.Done()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ctx.Done():
			return
		default:
			msgs, err := consumer.Fetch(fetchBatchSize, jetstream.FetchMaxWait(fetchTimeout))
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					if err != context.DeadlineExceeded {
						slog.Warn("failed to fetch messages", "error", err)
					}
					continue
				}
			}

			for msg := range msgs.Messages() {
				l.handleMessage(ctx, msg)
			}

			if msgs.Error() != nil {
				slog.Warn("fetch messages error", "error", msgs.Error())
			}
		}
	}
}

// handleMessage processes a single CloudEvent message.
func (l *Loader) handleMessage(ctx context.Context, msg jetstream.Msg) {
	event, err := parseCloudEvent(msg.Data())
	if err != nil {
		slog.Error("failed to parse CloudEvent", "error", err)
		_ = msg.Term()
		return
	}

	slog.Info("processing event", "type", event.Type(), "subject", event.Subject())

	var processErr error
	switch event.Type() {
	case events.TypeEvidenceIngested:
		processErr = l.handleIngested(ctx, event)
	case events.TypeEvidenceSealed:
		processErr = l.handleSealed(ctx, event)
	case events.TypeSubjectRegistered:
		processErr = l.handleSubjectRegistered(ctx, event)
	default:
		slog.Warn("unknown event type", "type", event.Type())
		_ = msg.Ack()
		return
	}

	if processErr != nil {
		if isPermanentError(processErr) {
			slog.Error("permanent failure, terminating message", "error", processErr, "type", event.Type())
			_ = msg.Term()
		} else {
			slog.Warn("transient failure, will retry", "error", processErr, "type", event.Type())
			_ = msg.NakWithDelay(retryDelay)
		}
		return
	}

	if err := msg.Ack(); err != nil {
		slog.Error("failed to ack message", "error", err)
	}
}

// parseCloudEvent unmarshals a CloudEvent from JSON.
func parseCloudEvent(data []byte) (*cloudevents.Event, error) {
	var event cloudevents.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("unmarshaling CloudEvent: %w", err)
	}
	return &event, nil
}

// handleIngested processes an evidence.ingested event.
func (l *Loader) handleIngested(ctx context.Context, event *cloudevents.Event) error {
	var data events.EvidenceIngestedData
	if err := event.DataAs(&data); err != nil {
		return fmt.Errorf("extracting ingested data: %w", err)
	}

	// Upsert subject
	if err := l.writer.UpsertSubject(ctx, data.SubjectID); err != nil {
		return fmt.Errorf("upserting subject: %w", err)
	}

	// Upsert publisher
	if err := l.writer.UpsertPublisher(ctx, data.Publisher.Issuer, data.Publisher.Sub); err != nil {
		return fmt.Errorf("upserting publisher: %w", err)
	}

	// Note: Evidence node creation is deferred until sealed event when we have a logIndex.
	// For now, just ensure subject and publisher exist.

	slog.Info("evidence ingested", "digest", data.ContentDigest, "artifactType", data.ArtifactType)
	return nil
}

// handleSealed processes an evidence.sealed event.
func (l *Loader) handleSealed(ctx context.Context, event *cloudevents.Event) error {
	var data events.EvidenceSealedData
	if err := event.DataAs(&data); err != nil {
		return fmt.Errorf("extracting sealed data: %w", err)
	}

	// Fetch artifact from locker
	artifactData, err := l.fetchArtifact(ctx, data.StorageRef)
	if err != nil {
		return fmt.Errorf("fetching artifact: %w", err)
	}

	// Upsert subject (idempotent)
	if err := l.writer.UpsertSubject(ctx, data.SubjectID); err != nil {
		return fmt.Errorf("upserting subject: %w", err)
	}

	// We don't have publisher info in sealed event — assume it was set in ingested event.
	// For now, create a placeholder publisher if needed. In production, this would be
	// resolved by correlating with the ingested event or fetching from the receipt.
	// For the MVP, we'll use a service account placeholder.
	publisherIssuer := "locker-service"
	publisherSub := "locker"
	if err := l.writer.UpsertPublisher(ctx, publisherIssuer, publisherSub); err != nil {
		return fmt.Errorf("upserting publisher: %w", err)
	}

	// Upsert evidence node with sealed status
	evidenceRecord := EvidenceRecord{
		LogIndex:        data.LogIndex,
		Digest:          data.ContentDigest,
		ReceiptDigest:   data.ReceiptDigest,
		ArtifactType:    inferArtifactType(artifactData),
		Status:          "sealed",
		SubjectID:       data.SubjectID,
		PublisherIssuer: publisherIssuer,
		PublisherSub:    publisherSub,
		Sealed:          time.Now(),
	}

	if err := l.writer.UpsertEvidence(ctx, evidenceRecord); err != nil {
		return fmt.Errorf("upserting evidence: %w", err)
	}

	// Parse artifact and upsert entities and edges
	if err := l.processArtifact(ctx, evidenceRecord.ArtifactType, artifactData, data.LogIndex); err != nil {
		return fmt.Errorf("processing artifact: %w", err)
	}

	slog.Info("evidence sealed and processed", "logIndex", data.LogIndex, "digest", data.ContentDigest)
	return nil
}

// handleSubjectRegistered processes a subject.registered event.
func (l *Loader) handleSubjectRegistered(ctx context.Context, event *cloudevents.Event) error {
	var data events.SubjectRegisteredData
	if err := event.DataAs(&data); err != nil {
		return fmt.Errorf("extracting subject data: %w", err)
	}

	if err := l.writer.UpsertSubject(ctx, data.SubjectID); err != nil {
		return fmt.Errorf("upserting subject: %w", err)
	}

	slog.Info("subject registered", "subjectId", data.SubjectID)
	return nil
}

// fetchArtifact fetches an artifact from the locker via HTTP GET.
func (l *Loader) fetchArtifact(ctx context.Context, storageRef string) ([]byte, error) {
	// Parse storage ref: locker://subject-id/entry/N
	// For MVP, assume storageRef is a full URL to the locker HTTP endpoint
	url := l.lockerURL + "/" + storageRef[len("locker://"):]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching from locker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("locker returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return data, nil
}

// processArtifact parses a Gemara artifact and writes entities and edges to Memgraph.
func (l *Loader) processArtifact(ctx context.Context, artifactType string, data []byte, logIndex int64) error {
	parsed, err := ParseArtifact(artifactType, data, logIndex)
	if err != nil {
		return fmt.Errorf("parsing artifact: %w", err)
	}

	// Upsert all entities
	for _, entity := range parsed.Entities {
		if err := l.writer.UpsertEntity(ctx, entity); err != nil {
			return fmt.Errorf("upserting entity %s: %w", entity.ID, err)
		}
	}

	// Upsert all edges
	for _, edge := range parsed.Edges {
		// Create stub nodes for referenced entities that don't exist yet
		// This handles cross-catalog references
		if err := l.writer.UpsertEntity(ctx, EntityRecord{
			ID:               edge.ToID,
			Label:            edge.ToLabel,
			Properties:       map[string]any{"stub": true},
			EvidenceLogIndex: logIndex,
		}); err != nil {
			return fmt.Errorf("upserting stub entity %s: %w", edge.ToID, err)
		}

		if err := l.writer.UpsertEdge(ctx, edge); err != nil {
			return fmt.Errorf("upserting edge %s->%s: %w", edge.FromID, edge.ToID, err)
		}
	}

	slog.Info("artifact processed", "artifactType", artifactType, "entities", len(parsed.Entities), "edges", len(parsed.Edges))
	return nil
}

// inferArtifactType infers the artifact type from the JSON metadata field.
func inferArtifactType(data []byte) string {
	var meta struct {
		Metadata struct {
			Type string `json:"type"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "unknown"
	}
	if meta.Metadata.Type == "" {
		return "unknown"
	}
	return meta.Metadata.Type
}

// isPermanentError determines if an error should terminate the message vs. retry.
func isPermanentError(err error) bool {
	// JSON unmarshal errors are permanent
	if _, ok := err.(*json.UnmarshalTypeError); ok {
		return true
	}
	if _, ok := err.(*json.SyntaxError); ok {
		return true
	}
	// Context cancellation is permanent
	if err == context.Canceled {
		return true
	}
	// All other errors (network, DB writes) are transient
	return false
}
