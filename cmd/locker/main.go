package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/complytime-labs/complytime-core/internal/locker"
)

func main() {
	// Get configuration from environment
	dataPath := os.Getenv("LOCKER_DATA_PATH")
	if dataPath == "" {
		dataPath = "/data/ledgers"
	}

	listenAddr := os.Getenv("LOCKER_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8081"
	}

	// Read shared secret for service-to-service authentication
	secret := os.Getenv("LOCKER_SECRET")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "LOCKER_SECRET is required")
		os.Exit(1)
	}

	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Create locker
	lk, err := locker.NewLocker(dataPath)
	if err != nil {
		slog.Error("failed to create locker", "error", err)
		os.Exit(1)
	}

	// Open existing ledgers on startup
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = lk.OpenExistingLedgers(ctx)
	cancel()
	if err != nil {
		slog.Error("failed to open existing ledgers", "error", err)
		os.Exit(1)
	}

	// Create HTTP handler and server
	handler := locker.NewHandler(lk, secret)
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("starting locker server", "addr", listenAddr, "dataPath", dataPath)

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		slog.Info("locker listening", "addr", listenAddr, "data", dataPath)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or server error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigChan:
		slog.Info("shutdown signal received, gracefully shutting down")
	case err := <-errCh:
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	// Shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
		os.Exit(1)
	}

	// Close locker
	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := lk.Close(closeCtx); err != nil {
		slog.Error("locker close error", "error", err)
		os.Exit(1)
	}

	slog.Info("locker server stopped successfully")
}
