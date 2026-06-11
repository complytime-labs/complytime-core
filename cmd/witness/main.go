// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/db"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	envCfg, err := config.WitnessFromEnv()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Load configuration
	witnessCfg, err := LoadConfig(envCfg.ConfigPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("witness service starting", "name", witnessCfg.Witness.Name)

	// Load state
	state, err := LoadState(envCfg.StatePath)
	if err != nil {
		slog.Error("failed to load state", "error", err)
		os.Exit(1)
	}

	slog.Info("loaded witness state", "last_verified_index", state.LastVerifiedIndex)

	// Initialize read-only Tessera reader (no appender, no signer)
	tesseraReader := tessera.NewReader(envCfg.TesseraPath)
	defer func() { _ = tesseraReader.Close() }()

	slog.Info("tessera reader initialized", "path", envCfg.TesseraPath)

	// Initialize PostgreSQL connection
	pgClient, err := db.New(ctx, db.Config{URL: envCfg.PostgresURL})
	if err != nil {
		slog.Error("failed to connect to PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer pgClient.Close()

	slog.Info("postgresql connected")

	storeClient := store.New(pgClient.Pool())

	// Create verifier adapter
	verifier := NewVerifier(&tesseraAdapter{tesseraReader}, &postgresAdapter{storeClient}, witnessCfg)

	// Start verification loop with WaitGroup for clean shutdown
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		verificationLoop(ctx, verifier, storeClient, state, witnessCfg, envCfg.StatePath)
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	slog.Info("witness service shutting down, waiting for verification loop to finish")

	// Wait for the loop goroutine to exit, ensuring LastVerifiedIndex is final
	wg.Wait()

	// Save state after loop has fully stopped
	state.UpdatedAt = time.Now()
	if err := SaveState(envCfg.StatePath, state); err != nil {
		slog.Error("failed to save state", "error", err)
	}
	slog.Info("witness state saved", "last_verified_index", state.LastVerifiedIndex)
}

// tesseraAdapter adapts tessera.Reader to TesseraReader interface
type tesseraAdapter struct {
	reader *tessera.Reader
}

func (t *tesseraAdapter) Read(ctx context.Context, index uint64) ([]byte, error) {
	return t.reader.Read(ctx, index)
}

func (t *tesseraAdapter) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return t.reader.ReadCheckpoint(ctx)
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
		EvidenceID:      row.EvidenceID,
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

func (p *postgresAdapter) PolicyExistsByID(ctx context.Context, policyID string) bool {
	return p.store.PolicyExistsByID(ctx, policyID)
}

func (p *postgresAdapter) HasFailedTrustSignals(ctx context.Context, evidenceID string) (bool, error) {
	return p.store.HasFailedTrustSignals(ctx, evidenceID)
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

		// Try to verify this index
		ok := verifier.VerifyEntry(verifyCtx, currentIndex)
		if !ok {
			cancel()
			break
		}

		// Read current checkpoint from Tessera log for countersigning
		cpRaw, cpErr := verifier.tessera.ReadCheckpoint(verifyCtx)
		var checkpointHash string
		if cpErr != nil {
			slog.Warn("failed to read checkpoint, using index marker", "log_index", currentIndex, "error", cpErr)
			checkpointHash = ""
		} else {
			checkpointHash = base64.StdEncoding.EncodeToString(cpRaw)
		}

		if err := storeClient.MarkIndexWitnessed(verifyCtx, currentIndex, config.Witness.Name, checkpointHash); err != nil {
			cancel()
			slog.Error("failed to mark index as witnessed", "log_index", currentIndex, "error", err)
			break
		}

		cancel()

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
