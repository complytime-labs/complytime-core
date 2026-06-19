// SPDX-License-Identifier: Apache-2.0

package tessera

import "time"

type Options struct {
	CheckpointTime    time.Duration // Checkpoint interval (e.g., 10m)
	CheckpointSize    int           // Checkpoint batch size (e.g., 100 entries)
	SignerKeyPath     string        // Path to persist signer key (empty = ephemeral)
	WitnessPolicyPath string        // Path to Sigsum-format witness policy file (empty = no witnesses)
	WitnessTimeout    time.Duration // Max wait for witness cosignatures (default: 5s)
	WitnessFailOpen   bool          // Publish checkpoint even if witnesses unreachable (default: false)
}

func DefaultOptions() Options {
	return Options{
		CheckpointTime:  10 * time.Minute,
		CheckpointSize:  100,
		WitnessTimeout:  5 * time.Second,
		WitnessFailOpen: false,
	}
}
