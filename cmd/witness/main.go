// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
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

	// TODO: Initialize Tessera client
	// TODO: Initialize PostgreSQL connection
	// TODO: Start verification loop

	// Wait for shutdown signal
	<-ctx.Done()
	slog.Info("witness service shutting down")

	// Save state
	state.UpdatedAt = time.Now()
	if err := SaveState(statePath, state); err != nil {
		slog.Error("failed to save state", "error", err)
	}
}
