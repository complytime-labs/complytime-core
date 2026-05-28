// SPDX-License-Identifier: Apache-2.0

package tessera

import "time"

type Options struct {
	CheckpointTime time.Duration // Checkpoint interval (e.g., 10m)
	CheckpointSize int           // Checkpoint batch size (e.g., 100 entries)
}

func DefaultOptions() Options {
	return Options{
		CheckpointTime: 10 * time.Minute,
		CheckpointSize: 100,
	}
}
