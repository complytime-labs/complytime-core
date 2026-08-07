package locker

import (
	"fmt"

	"github.com/knadh/koanf/v2"

	appconfig "github.com/complytime-labs/complytime-core/internal/config"
)

// LockerConfig holds all configuration for the locker service.
type LockerConfig struct {
	NatsURL        string
	ListenAddr     string
	DataPath       string
	JWTAudience    string
	CedarPolicyDir string
	Issuers        appconfig.IssuersConfig
}

// LoadLockerConfig reads locker configuration from a loaded koanf instance.
func LoadLockerConfig(k *koanf.Koanf) (*LockerConfig, error) {
	audience := k.String("jwt.audience")
	if audience == "" {
		return nil, fmt.Errorf("jwt.audience (JWT_AUDIENCE) is required")
	}

	natsURL := k.String("nats.url")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	listenAddr := k.String("locker.listen.addr")
	if listenAddr == "" {
		listenAddr = ":8081"
	}

	dataPath := k.String("locker.data.path")
	if dataPath == "" {
		dataPath = "/data/ledgers"
	}

	issuers, err := appconfig.UnmarshalIssuers(k)
	if err != nil {
		return nil, err
	}

	return &LockerConfig{
		NatsURL:        natsURL,
		ListenAddr:     listenAddr,
		DataPath:       dataPath,
		JWTAudience:    audience,
		CedarPolicyDir: k.String("cedar.policy.dir"),
		Issuers:        issuers,
	}, nil
}
