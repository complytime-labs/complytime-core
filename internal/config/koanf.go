package config

import (
	"flag"
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Load builds a koanf instance with precedence: flags > env vars > config file.
// configPath may be empty (no file loaded). flagSet may be nil (no flag layer).
// Env var mapping: uppercase with underscores → lowercase dot-separated.
// e.g. NATS_URL → nats.url, PRIMARY_ISSUER → primary.issuer
func Load(configPath string, flagSet *flag.FlagSet) (*koanf.Koanf, error) {
	k := koanf.New(".")

	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("loading config file %q: %w", configPath, err)
		}
	}

	if err := k.Load(env.Provider("", ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(s), "_", ".")
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	if flagSet != nil {
		flagMap := make(map[string]interface{})
		flagSet.Visit(func(f *flag.Flag) {
			key := strings.ReplaceAll(f.Name, "-", ".")
			flagMap[key] = f.Value.String()
		})
		if len(flagMap) > 0 {
			if err := k.Load(confmap.Provider(flagMap, "."), nil); err != nil {
				return nil, fmt.Errorf("loading flags: %w", err)
			}
		}
	}

	return k, nil
}
