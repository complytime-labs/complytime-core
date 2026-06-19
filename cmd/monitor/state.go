// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type State struct {
	LastVerifiedIndex  uint64    `json:"last_verified_index"`
	LastCheckpointHash string    `json:"last_checkpoint_hash"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func SaveState(path string, state *State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { //nolint:gosec // G703: path from operator-controlled state dir
		return fmt.Errorf("create state directory: %w", err)
	}

	// Write to temp file first for atomicity
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { //nolint:gosec // G703: path from operator-controlled state dir
		return fmt.Errorf("write temp state file: %w", err)
	}

	// Atomic rename ensures state file is never corrupted
	if err := os.Rename(tmp, path); err != nil { //nolint:gosec // G703: operator-controlled state dir
		return fmt.Errorf("rename state file: %w", err)
	}

	return nil
}

func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G703: operator-controlled state file
	if err != nil {
		if os.IsNotExist(err) {
			// Return zero state if file doesn't exist
			return &State{
				LastVerifiedIndex:  0,
				LastCheckpointHash: "",
				UpdatedAt:          time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	return &state, nil
}
