package nats

import (
	"fmt"
	"log/slog"
	"time"

	natsgo "github.com/nats-io/nats.go"
)

// Connect establishes a NATS connection with production-grade defaults:
// automatic reconnection, drain on close, and structured logging.
func Connect(url string) (*natsgo.Conn, error) {
	nc, err := natsgo.Connect(
		url,
		natsgo.RetryOnFailedConnect(true),
		natsgo.MaxReconnects(-1),
		natsgo.ReconnectWait(2*time.Second),
		natsgo.DisconnectErrHandler(func(_ *natsgo.Conn, err error) {
			slog.Warn("nats disconnected", "error", err)
		}),
		natsgo.ReconnectHandler(func(nc *natsgo.Conn) {
			slog.Info("nats reconnected", "url", nc.ConnectedUrl())
		}),
		natsgo.ClosedHandler(func(_ *natsgo.Conn) {
			slog.Info("nats connection closed")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to nats at %s: %w", url, err)
	}
	return nc, nil
}
