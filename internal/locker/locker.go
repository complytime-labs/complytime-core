package locker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
)

var (
	ErrLedgerExists   = errors.New("ledger already exists")
	ErrLedgerNotFound = errors.New("ledger not found")
	ErrIndexOutOfRange = errors.New("index out of range")
)

// subjectIDPattern validates subjectID as a flat slug.
// Allows alphanumeric, underscores, hyphens. No dots (NATS subject delimiter).
// Must start with alphanumeric. Max 254 characters.
var subjectIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,253}$`)

// Locker manages N ledgers, one per subject. Each ledger is an independent
// Tessera transparency log stored under basePath/{subjectID}/.
type Locker struct {
	basePath string

	mu      sync.RWMutex
	ledgers map[string]*Ledger
}

// ValidateSubjectID checks if a subjectID is valid and safe for use as a directory name.
func ValidateSubjectID(subjectID string) error {
	if subjectID == "" {
		return fmt.Errorf("subjectID cannot be empty")
	}
	if !subjectIDPattern.MatchString(subjectID) {
		return fmt.Errorf("subjectID must start with alphanumeric and contain only alphanumeric, dot, underscore, hyphen (max 254 chars)")
	}
	return nil
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
	if err := ValidateSubjectID(subjectID); err != nil {
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
	slog.Info("created ledger", "subject", subjectID)
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
			slog.Error("failed to open ledger", "subject", subjectID, "error", err)
			continue
		}
		lk.ledgers[subjectID] = ledger
		slog.Info("opened existing ledger", "subject", subjectID)
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
