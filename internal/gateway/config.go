package gateway

import (
	"fmt"

	"github.com/knadh/koanf/v2"

	appconfig "github.com/complytime-labs/complytime-core/internal/config"
)

// GatewayConfig holds all configuration for the gateway service.
type GatewayConfig struct {
	NatsURL        string
	ListenAddr     string
	JWTAudience    string
	CedarPolicyDir string
	Issuers        appconfig.IssuersConfig
}

// LoadGatewayConfig reads gateway configuration from a loaded koanf instance.
func LoadGatewayConfig(k *koanf.Koanf) (*GatewayConfig, error) {
	audience := k.String("jwt.audience")
	if audience == "" {
		return nil, fmt.Errorf("jwt.audience (JWT_AUDIENCE) is required")
	}

	natsURL := k.String("nats.url")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	listenAddr := k.String("gateway.listen.addr")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	issuers, err := appconfig.UnmarshalIssuers(k)
	if err != nil {
		return nil, err
	}

	return &GatewayConfig{
		NatsURL:        natsURL,
		ListenAddr:     listenAddr,
		JWTAudience:    audience,
		CedarPolicyDir: k.String("cedar.policy.dir"),
		Issuers:        issuers,
	}, nil
}
