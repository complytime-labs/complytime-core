// internal/tessera/options.go
package tessera

import "time"

type Options struct {
	CheckpointTime time.Duration // Checkpoint interval (e.g., 10m)
	CheckpointSize int           // Checkpoint batch size (e.g., 100 entries)
}

func DefaultOptions() Options {
	return Options{
		CheckpointTime: 100 * time.Millisecond, // Short for tests; adjust in production
		CheckpointSize: 100,
	}
}
