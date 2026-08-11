package graph

import (
	"fmt"

	"github.com/knadh/koanf/v2"

	appconfig "github.com/complytime-labs/complytime-core/internal/config"
)

// GraphConfig holds all configuration for the graph service.
type GraphConfig struct {
	NatsURL        string
	LockerURL      string
	TokenFile      string
	MemgraphURL    string
	JWTAudience    string
	ListenAddr     string
	CedarPolicyDir string
	Issuers        appconfig.IssuersConfig
}

// LoadGraphConfig reads graph service configuration from a loaded koanf instance.
func LoadGraphConfig(k *koanf.Koanf) (*GraphConfig, error) {
	required := map[string]string{
		"nats.url":     k.String("nats.url"),
		"locker.url":   k.String("locker.url"),
		"token.file":   k.String("token.file"),
		"memgraph.url": k.String("memgraph.url"),
		"jwt.audience": k.String("jwt.audience"),
	}
	for key, val := range required {
		if val == "" {
			return nil, fmt.Errorf("%s is required", key)
		}
	}

	listenAddr := k.String("graph.listen.addr")
	if listenAddr == "" {
		listenAddr = ":8082"
	}

	issuers, err := appconfig.UnmarshalIssuers(k)
	if err != nil {
		return nil, err
	}

	return &GraphConfig{
		NatsURL:        required["nats.url"],
		LockerURL:      required["locker.url"],
		TokenFile:      required["token.file"],
		MemgraphURL:    required["memgraph.url"],
		JWTAudience:    required["jwt.audience"],
		ListenAddr:     listenAddr,
		CedarPolicyDir: k.String("cedar.policy.dir"),
		Issuers:        issuers,
	}, nil
}
