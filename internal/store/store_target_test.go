package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func TestTargetRow_InsertAndQuery(t *testing.T) {
	var ts requirements.TargetStore = (*Store)(nil)
	_ = ts

	row := requirements.TargetRow{
		TargetID:        "prod-cluster",
		TesseraLogIndex: 42,
		TargetName:      "Production K8s Cluster",
		TargetType:      "kubernetes-cluster",
		Technologies:    []string{"kubernetes", "postgresql"},
		Geopolitical:    []string{"EU"},
		Sensitivity:     []string{"confidential"},
		Users:           []string{},
		Groups:          []string{"platform"},
		RegisteredAt:    time.Now().UTC(),
		RegisteredBy:    "repo:org/infra:ref:refs/heads/main",
	}

	assert.Equal(t, "prod-cluster", row.TargetID)
	assert.Equal(t, uint64(42), row.TesseraLogIndex)
	assert.Contains(t, row.Technologies, "kubernetes")
}
