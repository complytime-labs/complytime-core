// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const defaultJobTTL = 30 * time.Minute

// IngestJobStatus tracks the lifecycle of an async ingest request.
// Stored in-memory only -- lost on restart (accepted trade-off for POC).
type IngestJobStatus struct {
	JobID        string    `json:"job_id"`
	Status       string    `json:"status"`
	Inserted     int       `json:"inserted,omitempty"`
	PolicyID     string    `json:"policy_id,omitempty"`
	ArtifactID   string    `json:"artifact_id,omitempty"`
	ArtifactType string    `json:"artifact_type,omitempty"`
	Error        string    `json:"error,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// IngestTracker provides in-memory job status tracking for async ingest.
// Terminal jobs (completed/failed) are evicted after a TTL to prevent
// unbounded memory growth.
type IngestTracker struct {
	mu     sync.RWMutex
	jobs   map[string]*IngestJobStatus
	ttl    time.Duration
	cancel context.CancelFunc
}

// NewIngestTracker creates a tracker and starts a background eviction loop.
func NewIngestTracker() *IngestTracker {
	ctx, cancel := context.WithCancel(context.Background())
	t := &IngestTracker{
		jobs:   make(map[string]*IngestJobStatus),
		ttl:    defaultJobTTL,
		cancel: cancel,
	}
	go t.evictLoop(ctx)
	return t
}

// Stop terminates the background eviction goroutine.
func (t *IngestTracker) Stop() {
	t.cancel()
}

func (t *IngestTracker) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(t.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.evict()
		}
	}
}

func (t *IngestTracker) evict() {
	cutoff := time.Now().UTC().Add(-t.ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	evicted := 0
	for id, j := range t.jobs {
		if (j.Status == "completed" || j.Status == "failed") && j.UpdatedAt.Before(cutoff) {
			delete(t.jobs, id)
			evicted++
		}
	}
	if evicted > 0 {
		slog.Debug("ingest tracker evicted stale jobs", "count", evicted)
	}
}

// Create registers a new pending ingest job.
func (t *IngestTracker) Create(jobID string) {
	now := time.Now().UTC()
	t.mu.Lock()
	t.jobs[jobID] = &IngestJobStatus{
		JobID:     jobID,
		Status:    "pending",
		CreatedAt: now,
		UpdatedAt: now,
	}
	t.mu.Unlock()
}

// Complete marks a job as completed with results.
func (t *IngestTracker) Complete(jobID string, inserted int, policyID string) {
	t.mu.Lock()
	if j, ok := t.jobs[jobID]; ok {
		j.Status = "completed"
		j.Inserted = inserted
		j.PolicyID = policyID
		j.UpdatedAt = time.Now().UTC()
	}
	t.mu.Unlock()
}

func (t *IngestTracker) CompleteArtifact(jobID, artifactID, artifactType string) {
	t.mu.Lock()
	if j, ok := t.jobs[jobID]; ok {
		j.Status = "completed"
		j.ArtifactID = artifactID
		j.ArtifactType = artifactType
		j.UpdatedAt = time.Now().UTC()
	}
	t.mu.Unlock()
}

// Fail marks a job as failed with an error reason.
func (t *IngestTracker) Fail(jobID string, reason string) {
	t.mu.Lock()
	if j, ok := t.jobs[jobID]; ok {
		j.Status = "failed"
		j.Error = reason
		j.UpdatedAt = time.Now().UTC()
	}
	t.mu.Unlock()
}

// Get returns the current status of a job, or nil if not found.
func (t *IngestTracker) Get(jobID string) *IngestJobStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	j, ok := t.jobs[jobID]
	if !ok {
		return nil
	}
	cp := *j
	return &cp
}
