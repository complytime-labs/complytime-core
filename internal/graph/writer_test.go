//go:build integration

package graph

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDriver(t *testing.T) neo4j.DriverWithContext {
	t.Helper()
	url := os.Getenv("MEMGRAPH_URL")
	if url == "" {
		url = "bolt://localhost:7687"
	}
	driver, err := neo4j.NewDriverWithContext(url, neo4j.NoAuth())
	require.NoError(t, err)
	t.Cleanup(func() { driver.Close(context.Background()) })
	return driver
}

func clearGraph(t *testing.T, driver neo4j.DriverWithContext) {
	t.Helper()
	ctx := context.Background()
	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)
	result, err := session.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
	require.NoError(t, err)
	_, err = result.Consume(ctx)
	require.NoError(t, err)
}

func TestWriter_UpsertSubject(t *testing.T) {
	driver := testDriver(t)
	clearGraph(t, driver)
	w := NewWriter(driver)

	ctx := context.Background()
	err := w.UpsertSubject(ctx, "my-app-v1")
	require.NoError(t, err)

	// Upsert again — idempotent
	err = w.UpsertSubject(ctx, "my-app-v1")
	require.NoError(t, err)
}

func TestWriter_UpsertEvidence(t *testing.T) {
	driver := testDriver(t)
	clearGraph(t, driver)
	w := NewWriter(driver)

	ctx := context.Background()

	err := w.UpsertSubject(ctx, "my-app-v1")
	require.NoError(t, err)

	err = w.UpsertPublisher(ctx, "https://idp.example.com", "ci-pipeline")
	require.NoError(t, err)

	err = w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex:        1,
		Digest:          "sha256:abc123",
		ArtifactType:    "ControlCatalog",
		Status:          "sealed",
		SubjectID:       "my-app-v1",
		PublisherIssuer: "https://idp.example.com",
		PublisherSub:    "ci-pipeline",
		Sealed:          time.Now(),
	})
	require.NoError(t, err)

	subjects, err := w.ListSubjects(ctx)
	require.NoError(t, err)
	require.Len(t, subjects, 1)
	assert.Equal(t, "my-app-v1", subjects[0].SubjectID)
}

func TestWriter_UpsertEntity_And_Edge(t *testing.T) {
	driver := testDriver(t)
	clearGraph(t, driver)
	w := NewWriter(driver)

	ctx := context.Background()

	err := w.UpsertSubject(ctx, "my-app-v1")
	require.NoError(t, err)

	err = w.UpsertPublisher(ctx, "https://idp.example.com", "architect")
	require.NoError(t, err)

	err = w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex:        1,
		Digest:          "sha256:abc",
		ArtifactType:    "CapabilityCatalog",
		Status:          "sealed",
		SubjectID:       "my-app-v1",
		PublisherIssuer: "https://idp.example.com",
		PublisherSub:    "architect",
		Sealed:          time.Now(),
	})
	require.NoError(t, err)

	// Create capability entity
	err = w.UpsertEntity(ctx, EntityRecord{
		ID:               "cap-login",
		Label:            "Capability",
		Properties:       map[string]any{"title": "User Authentication", "description": "Login system"},
		EvidenceLogIndex: 1,
	})
	require.NoError(t, err)

	// Create threat entity
	err = w.UpsertEntity(ctx, EntityRecord{
		ID:               "thr-acct-takeover",
		Label:            "Threat",
		Properties:       map[string]any{"title": "Account Takeover"},
		EvidenceLogIndex: 1,
	})
	require.NoError(t, err)

	// Create INTRODUCES edge
	err = w.UpsertEdge(ctx, EdgeRecord{
		FromID:    "cap-login",
		FromLabel: "Capability",
		ToID:      "thr-acct-takeover",
		ToLabel:   "Threat",
		EdgeType:  "INTRODUCES",
	})
	require.NoError(t, err)

	// Query threat model
	tm, err := w.ThreatModel(ctx, "my-app-v1")
	require.NoError(t, err)
	require.Len(t, tm.Capabilities, 1)
	assert.Equal(t, "cap-login", tm.Capabilities[0].Id)
	assert.Equal(t, "User Authentication", tm.Capabilities[0].Title)
	require.Len(t, tm.Threats, 1)
	assert.Equal(t, "thr-acct-takeover", tm.Threats[0].Id)
}

func TestWriter_Coverage(t *testing.T) {
	driver := testDriver(t)
	clearGraph(t, driver)
	w := NewWriter(driver)

	ctx := context.Background()

	// Set up: subject, publisher, evidence for a ControlCatalog
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp.example.com", "architect"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 1, Digest: "sha256:cat1", ArtifactType: "ControlCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp.example.com", PublisherSub: "architect",
		Sealed: time.Now(),
	}))

	// Two controls
	require.NoError(t, w.UpsertEntity(ctx, EntityRecord{
		ID: "ctrl-1", Label: "Control",
		Properties:       map[string]any{"title": "Control One", "catalogID": "sast-v1"},
		EvidenceLogIndex: 1,
	}))
	require.NoError(t, w.UpsertEntity(ctx, EntityRecord{
		ID: "ctrl-2", Label: "Control",
		Properties:       map[string]any{"title": "Control Two", "catalogID": "sast-v1"},
		EvidenceLogIndex: 1,
	}))

	// One EvaluationLog covering ctrl-1 only
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp.example.com", "ci"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 2, Digest: "sha256:eval1", ArtifactType: "EvaluationLog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp.example.com", PublisherSub: "ci",
		Sealed: time.Now(),
	}))
	require.NoError(t, w.UpsertEntity(ctx, EntityRecord{
		ID: "finding-1", Label: "EvaluationFinding",
		Properties:       map[string]any{"result": "pass"},
		EvidenceLogIndex: 2,
	}))
	require.NoError(t, w.UpsertEdge(ctx, EdgeRecord{
		FromID: "finding-1", FromLabel: "EvaluationFinding",
		ToID: "ctrl-1", ToLabel: "Control",
		EdgeType: "EVALUATES",
	}))

	cov, err := w.Coverage(ctx, "my-app-v1", "sast-v1")
	require.NoError(t, err)
	assert.Equal(t, 1, cov.Covered)
	assert.Equal(t, 2, cov.Total)
}
