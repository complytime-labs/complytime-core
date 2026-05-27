// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/complytime-labs/complytime-core/internal/postgres"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Load configuration
	configPath := os.Getenv("WITNESS_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/witness/config.yaml"
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("witness service starting", "name", config.Witness.Name)

	// Load state
	statePath := os.Getenv("WITNESS_STATE_PATH")
	if statePath == "" {
		statePath = "/var/lib/witness/state.json"
	}

	state, err := LoadState(statePath)
	if err != nil {
		slog.Error("failed to load state", "error", err)
		os.Exit(1)
	}

	slog.Info("loaded witness state", "last_verified_index", state.LastVerifiedIndex)

	// Initialize Tessera client
	tesseraPath := os.Getenv("TESSERA_PATH")
	if tesseraPath == "" {
		tesseraPath = "/var/lib/tessera"
	}

	tesseraClient, err := tessera.NewClient(ctx, tesseraPath, tessera.DefaultOptions())
	if err != nil {
		slog.Error("failed to initialize Tessera client", "error", err)
		os.Exit(1)
	}
	defer tesseraClient.Close()

	slog.Info("tessera client initialized", "path", tesseraPath)

	// Initialize PostgreSQL connection
	pgURL := os.Getenv("POSTGRES_URL")
	if pgURL == "" {
		slog.Error("POSTGRES_URL environment variable is required")
		os.Exit(1)
	}

	pgClient, err := postgres.New(ctx, postgres.Config{URL: pgURL})
	if err != nil {
		slog.Error("failed to connect to PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer pgClient.Close()

	slog.Info("postgresql connected")

	storeClient := store.New(pgClient.Pool())

	// Create verifier adapter
	verifier := NewVerifier(&tesseraAdapter{tesseraClient}, &postgresAdapter{storeClient}, config)

	// Start verification loop
	go verificationLoop(ctx, verifier, storeClient, state, config, statePath)

	// Wait for shutdown signal
	<-ctx.Done()
	slog.Info("witness service shutting down")

	// Save state
	state.UpdatedAt = time.Now()
	if err := SaveState(statePath, state); err != nil {
		slog.Error("failed to save state", "error", err)
	}
}

// tesseraAdapter adapts tessera.Client to TesseraReader interface
type tesseraAdapter struct {
	client *tessera.Client
}

func (t *tesseraAdapter) Read(ctx context.Context, index uint64) ([]byte, error) {
	return t.client.Read(ctx, index)
}

// postgresAdapter adapts store.Store to PostgresQuerier interface
type postgresAdapter struct {
	store *store.Store
}

func (p *postgresAdapter) QueryEvidenceByLogIndex(ctx context.Context, logIndex uint64) (*EvidenceRow, error) {
	row, err := p.store.QueryEvidenceByLogIndex(ctx, logIndex)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, nil
	}
	return &EvidenceRow{
		Certified:       row.Certified,
		PublisherIssuer: row.PublisherIssuer,
		SubmittedBy:     row.SubmittedBy,
	}, nil
}

func (p *postgresAdapter) IsIndexWitnessed(ctx context.Context, index uint64) bool {
	return p.store.IsIndexWitnessed(ctx, index)
}

func (p *postgresAdapter) IsTargetRegistered(ctx context.Context, targetID string) bool {
	return p.store.IsTargetRegistered(ctx, targetID)
}

// verificationLoop polls Tessera for new entries and verifies them
func verificationLoop(ctx context.Context, verifier *Verifier, storeClient *store.Store, state *State, config *Config, statePath string) {
	ticker := time.NewTicker(config.Witness.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := verifyNewEntries(ctx, verifier, storeClient, state, config); err != nil {
				slog.Error("verification cycle failed", "error", err)
			}
			// Save state after each cycle
			state.UpdatedAt = time.Now()
			if err := SaveState(statePath, state); err != nil {
				slog.Warn("failed to save state", "error", err)
			}
		}
	}
}

// verifyNewEntries checks for new Tessera entries and verifies them
func verifyNewEntries(ctx context.Context, verifier *Verifier, storeClient *store.Store, state *State, config *Config) error {
	// Start from the next index after last verified
	currentIndex := state.LastVerifiedIndex + 1

	// Verify entries one at a time
	verified := 0
	for {
		verifyCtx, cancel := context.WithTimeout(ctx, config.Witness.VerificationTimeout)
		defer cancel()

		// Try to verify this index
		ok := verifier.VerifyEntry(verifyCtx, currentIndex)
		if !ok {
			// Verification failed or entry not ready yet
			// Stop here and try again on next poll
			break
		}

		// Mark as witnessed
		checkpointHash := fmt.Sprintf("checkpoint-%d", currentIndex)
		if err := storeClient.MarkIndexWitnessed(verifyCtx, currentIndex, config.Witness.Name, checkpointHash); err != nil {
			slog.Error("failed to mark index as witnessed", "log_index", currentIndex, "error", err)
			break
		}

		state.LastVerifiedIndex = currentIndex
		state.LastCheckpointHash = checkpointHash
		verified++

		slog.Info("verified entry", "log_index", currentIndex, "witness", config.Witness.Name)

		currentIndex++
	}

	if verified > 0 {
		slog.Info("verification cycle complete", "verified_count", verified, "last_index", state.LastVerifiedIndex)
	}

	return nil
}
