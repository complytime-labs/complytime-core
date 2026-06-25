// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/version"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

func main() {
	version.CheckFlags("monitor")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	envCfg, err := config.MonitorFromEnv()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	witnessCfg, err := LoadConfig(envCfg.ConfigPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("monitor service starting", "name", witnessCfg.Witness.Name)

	state, err := LoadState(envCfg.StatePath)
	if err != nil {
		slog.Error("failed to load state", "error", err)
		os.Exit(1)
	}

	slog.Info("loaded monitor state", "last_verified_index", state.LastVerifiedIndex)

	tesseraReader := tessera.NewReader(envCfg.TesseraPath)
	defer func() { _ = tesseraReader.Close() }()

	slog.Info("tessera reader initialized", "path", envCfg.TesseraPath)

	// TODO: connect to NATS and initialize KV stores for publisher trust
	// and target lookups. Currently the monitor runs Tessera-only checks
	// (artifact type detection, schema validation). Publisher trust and
	// policy reference checks require NATS KV migration (#128).

	verifier := NewVerifier(&tesseraAdapter{tesseraReader}, witnessCfg)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		verificationLoop(ctx, verifier, state, witnessCfg, envCfg.StatePath)
	}()

	<-ctx.Done()
	slog.Info("monitor service shutting down, waiting for verification loop to finish")

	wg.Wait()

	state.UpdatedAt = time.Now()
	if err := SaveState(envCfg.StatePath, state); err != nil {
		slog.Error("failed to save state", "error", err)
	}
	slog.Info("monitor state saved", "last_verified_index", state.LastVerifiedIndex)
}

type tesseraAdapter struct {
	reader *tessera.Reader
}

func (t *tesseraAdapter) Read(ctx context.Context, index uint64) ([]byte, error) {
	return t.reader.Read(ctx, index)
}

func (t *tesseraAdapter) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return t.reader.ReadCheckpoint(ctx)
}

func verificationLoop(ctx context.Context, verifier *Verifier, state *State, config *Config, statePath string) {
	ticker := time.NewTicker(config.Witness.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := verifyNewEntries(ctx, verifier, state, config); err != nil {
				slog.Error("verification cycle failed", "error", err)
			}
			state.UpdatedAt = time.Now()
			if err := SaveState(statePath, state); err != nil {
				slog.Warn("failed to save state", "error", err)
			}
		}
	}
}

func verifyNewEntries(ctx context.Context, verifier *Verifier, state *State, config *Config) error {
	currentIndex := state.LastVerifiedIndex + 1

	verified := 0
	for {
		verifyCtx, cancel := context.WithTimeout(ctx, config.Witness.VerificationTimeout)

		ok := verifier.VerifyEntry(verifyCtx, currentIndex)
		cancel()
		if !ok {
			break
		}

		state.LastVerifiedIndex = currentIndex
		verified++

		slog.Info("verified entry", "log_index", currentIndex, "monitor", config.Witness.Name)

		currentIndex++
	}

	if verified > 0 {
		slog.Info("verification cycle complete", "verified_count", verified, "last_index", state.LastVerifiedIndex)
	}

	return nil
}
