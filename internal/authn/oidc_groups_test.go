package authn

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractGroupsWithDropped(t *testing.T) {
	known := map[string]struct{}{
		"complytime-admin":   {},
		"complytime-auditor": {},
	}

	tests := []struct {
		name        string
		claims      map[string]any
		groupClaim  string
		wantRecog   []string
		wantDropped []string
	}{
		{
			name:        "all recognized",
			claims:      map[string]any{"groups": []any{"complytime-admin", "complytime-auditor"}},
			groupClaim:  "groups",
			wantRecog:   []string{"complytime-admin", "complytime-auditor"},
			wantDropped: nil,
		},
		{
			name:        "all dropped",
			claims:      map[string]any{"groups": []any{"hr-payroll", "ops-team"}},
			groupClaim:  "groups",
			wantRecog:   nil,
			wantDropped: []string{"hr-payroll", "ops-team"},
		},
		{
			name:        "mixed recognized and dropped",
			claims:      map[string]any{"groups": []any{"complytime-admin", "hr-payroll", "ops-team"}},
			groupClaim:  "groups",
			wantRecog:   []string{"complytime-admin"},
			wantDropped: []string{"hr-payroll", "ops-team"},
		},
		{
			name:        "empty claim path returns nothing",
			claims:      map[string]any{"groups": []any{"complytime-admin"}},
			groupClaim:  "",
			wantRecog:   nil,
			wantDropped: nil,
		},
		{
			name:        "missing claim returns nothing",
			claims:      map[string]any{"sub": "user1"},
			groupClaim:  "groups",
			wantRecog:   nil,
			wantDropped: nil,
		},
		{
			name:        "case normalization — recognized",
			claims:      map[string]any{"groups": []any{"ComplyTime-Admin"}},
			groupClaim:  "groups",
			wantRecog:   []string{"complytime-admin"},
			wantDropped: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recog, dropped := extractGroupsWithDropped(tt.claims, tt.groupClaim, known)
			assert.Equal(t, tt.wantRecog, recog)
			assert.Equal(t, tt.wantDropped, dropped)
		})
	}
}

func TestNewOIDCIssuer_InvalidGroupMode(t *testing.T) {
	srv, _, _ := newRegistryTestJWKSServer(t)

	_, err := NewOIDCIssuer(context.Background(), OIDCIssuerConfig{
		URL:       srv.URL,
		GroupMode: "unknown-mode",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC_GROUP_MODE")
}

func TestOIDCIssuer_AuditModeLogsDroppedGroups(t *testing.T) {
	srv, _, privKey := newRegistryTestJWKSServer(t)

	issuer, err := NewOIDCIssuer(context.Background(), OIDCIssuerConfig{
		URL:        srv.URL,
		GroupClaim: "groups",
		AdminGroup: "complytime-admin",
		GroupMode:  GroupModeAudit,
	})
	require.NoError(t, err)

	token := mintRegistryToken(t, privKey, srv.URL, "test-audience", map[string]any{
		"groups": []any{"complytime-admin", "hr-payroll", "ops-team"},
	})

	var buf bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	_, err = issuer.Authenticate(context.Background(), token, "test-audience")
	require.NoError(t, err)

	log := buf.String()
	assert.True(t, strings.Contains(log, "hr-payroll") || strings.Contains(log, "ops-team"),
		"expected dropped groups in audit log, got: %s", log)
}
