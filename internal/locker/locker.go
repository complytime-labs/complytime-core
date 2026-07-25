package locker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/complytime-labs/complytime-core/internal/subjects"
)

// SanitizeLogValue strips line breaks and control characters from a string before logging.
func SanitizeLogValue(s string) string {
	// Remove line breaks explicitly to prevent log-forging in plain-text logs.
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")

	// Remove remaining ASCII control characters.
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

var (
	ErrLedgerExists    = errors.New("ledger already exists")
	ErrLedgerNotFound  = errors.New("ledger not found")
	ErrIndexOutOfRange = errors.New("index out of range")
)

// Locker manages N ledgers, one per subject. Each ledger is an independent
// Tessera transparency log stored under basePath/{subjectID}/.
type Locker struct {
	basePath string

	mu      sync.RWMutex
	ledgers map[string]*Ledger
}

// NewLocker creates a new locker that stores ledgers under basePath.
func NewLocker(basePath string) (*Locker, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("creating base path %s: %w", basePath, err)
	}
	return &Locker{
		basePath: basePath,
		ledgers:  make(map[string]*Ledger),
	}, nil
}

// CreateLedger initializes a new ledger for the given subject.
// Returns an error if a ledger for this subject already exists.
func (lk *Locker) CreateLedger(ctx context.Context, subjectID string) (*Ledger, error) {
	if err := subjects.ValidateSubjectID(subjectID); err != nil {
		return nil, err
	}

	lk.mu.Lock()
	defer lk.mu.Unlock()

	if _, exists := lk.ledgers[subjectID]; exists {
		return nil, fmt.Errorf("%w: %s", ErrLedgerExists, subjectID)
	}

	ledger, err := NewLedger(ctx, subjectID, lk.basePath)
	if err != nil {
		return nil, err
	}

	lk.ledgers[subjectID] = ledger
	slog.Info("created ledger", "subject", SanitizeLogValue(subjectID))
	return ledger, nil
}

// GetLedger returns the ledger for the given subject, if it exists.
func (lk *Locker) GetLedger(subjectID string) (*Ledger, bool) {
	lk.mu.RLock()
	defer lk.mu.RUnlock()
	l, ok := lk.ledgers[subjectID]
	return l, ok
}

// OpenExistingLedgers scans the base path for existing ledger directories
// and opens them. Call this on startup to restore state.
func (lk *Locker) OpenExistingLedgers(ctx context.Context) error {
	entries, err := os.ReadDir(lk.basePath)
	if err != nil {
		return fmt.Errorf("reading base path: %w", err)
	}

	lk.mu.Lock()
	defer lk.mu.Unlock()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		subjectID := entry.Name()
		if _, exists := lk.ledgers[subjectID]; exists {
			continue
		}
		ledger, err := NewLedger(ctx, subjectID, lk.basePath)
		if err != nil {
			slog.Error("failed to open ledger", "subject", SanitizeLogValue(subjectID), "error", err)
			continue
		}
		lk.ledgers[subjectID] = ledger
		slog.Info("opened existing ledger", "subject", SanitizeLogValue(subjectID))
	}
	return nil
}

// Subjects returns the list of subject IDs with active ledgers.
func (lk *Locker) Subjects() []string {
	lk.mu.RLock()
	defer lk.mu.RUnlock()
	subjects := make([]string, 0, len(lk.ledgers))
	for id := range lk.ledgers {
		subjects = append(subjects, id)
	}
	return subjects
}

// RegisterGauges registers async gauge callbacks for locker metrics.
// Call this after OpenExistingLedgers during startup.
func (lk *Locker) RegisterGauges(ctx context.Context) error {
	meter := otel.Meter("complytime-locker")

	// Register gauge for total ledger count
	_, err := meter.Int64ObservableGauge("locker.ledger.count",
		metric.WithDescription("Number of active ledgers"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			lk.mu.RLock()
			count := len(lk.ledgers)
			lk.mu.RUnlock()
			o.Observe(int64(count))
			return nil
		}),
	)
	if err != nil {
		return fmt.Errorf("registering locker.ledger.count: %w", err)
	}

	// Register gauge for per-subject entry counts
	_, err = meter.Int64ObservableGauge("locker.ledger.entries",
		metric.WithDescription("Number of entries in each ledger by subject ID"),
		metric.WithInt64Callback(func(callbackCtx context.Context, o metric.Int64Observer) error {
			lk.mu.RLock()
			subjects := make([]string, 0, len(lk.ledgers))
			ledgers := make([]*Ledger, 0, len(lk.ledgers))
			for subjectID, ledger := range lk.ledgers {
				subjects = append(subjects, subjectID)
				ledgers = append(ledgers, ledger)
			}
			lk.mu.RUnlock()

			// Iterate outside the lock to avoid holding it during I/O
			for i, ledger := range ledgers {
				size, err := ledger.integratedSize(callbackCtx)
				if err != nil {
					// Log but don't fail the callback
					slog.Warn("failed to get ledger size for gauge", "subject", subjects[i], "error", err)
					continue
				}
				o.Observe(int64(size), metric.WithAttributes(attribute.String("subjectId", subjects[i])))
			}
			return nil
		}),
	)
	if err != nil {
		return fmt.Errorf("registering locker.ledger.entries: %w", err)
	}

	slog.Info("registered locker gauge callbacks")
	return nil
}

// Close gracefully shuts down all ledgers.
func (lk *Locker) Close(ctx context.Context) error {
	lk.mu.Lock()
	defer lk.mu.Unlock()

	var firstErr error
	for id, ledger := range lk.ledgers {
		if err := ledger.Close(ctx); err != nil {
			slog.Error("failed to close ledger", "subject", id, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
