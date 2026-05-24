// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
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

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}

	return nil
}

func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
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
