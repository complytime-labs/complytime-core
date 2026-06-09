// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

func registerTargetRoutes(g *echo.Group, s Stores) {
	if s.Targets == nil {
		return
	}
	g.GET("/policies/discover", policyQueryHandler(s.Targets, s.PolicyDimensions))
	g.GET("/targets", listTargetsHandler(s.Targets))
}

// PolicyDimensionStore defines queries for policies with dimension matching.
type PolicyDimensionStore interface {
	QueryPoliciesByDimensions(ctx context.Context, dims DimensionQuery) ([]PolicyWithDimensions, error)
}

// DimensionQuery holds parameters for dimension-based policy matching.
type DimensionQuery struct {
	Technologies []string
	Geopolitical []string
	Sensitivity  []string
	Users        []string
	Groups       []string
	Timestamp    time.Time
}

// PolicyWithDimensions represents a policy with its dimensional metadata.
type PolicyWithDimensions struct {
	LogIndex        uint64    `json:"log_index"`
	PolicyID        string    `json:"policy_id"`
	Title           string    `json:"title"`
	Version         string    `json:"version,omitempty"`
	Technologies    []string  `json:"technologies,omitempty"`
	Geopolitical    []string  `json:"geopolitical,omitempty"`
	Sensitivity     []string  `json:"sensitivity,omitempty"`
	EvaluationStart time.Time `json:"evaluation_start,omitempty"`
	EvaluationEnd   time.Time `json:"evaluation_end,omitempty"`
}

// PolicyQueryResponse is returned by the policy discovery endpoint.
type PolicyQueryResponse struct {
	Target             TargetSummary          `json:"target"`
	ApplicablePolicies []PolicyWithDimensions `json:"applicable_policies"`
}

// TargetSummary is a brief target representation in API responses.
type TargetSummary struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Technologies []string `json:"technologies,omitempty"`
	Geopolitical []string `json:"geopolitical,omitempty"`
	Sensitivity  []string `json:"sensitivity,omitempty"`
	RegisteredAt string   `json:"registered_at"`
}

func policyQueryHandler(targets TargetStore, policies PolicyDimensionStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		targetID := c.QueryParam("target_id")
		if targetID == "" {
			return jsonError(c, http.StatusBadRequest, "missing target_id parameter")
		}

		timestampStr := c.QueryParam("timestamp")
		timestamp := time.Now().UTC()
		if timestampStr != "" {
			var err error
			timestamp, err = time.Parse(time.RFC3339, timestampStr)
			if err != nil {
				return jsonError(c, http.StatusBadRequest, "invalid timestamp format — expected RFC3339")
			}
		}

		ctx := c.Request().Context()

		target, err := targets.GetLatestTarget(ctx, targetID, timestamp)
		if err != nil {
			return jsonError(c, http.StatusInternalServerError, "failed to query target")
		}
		if target == nil {
			return jsonError(c, http.StatusNotFound, "target not found")
		}

		if policies == nil {
			return c.JSON(http.StatusOK, PolicyQueryResponse{
				Target:             targetToSummary(target),
				ApplicablePolicies: []PolicyWithDimensions{},
			})
		}

		dims := DimensionQuery{
			Technologies: target.Technologies,
			Geopolitical: target.Geopolitical,
			Sensitivity:  target.Sensitivity,
			Users:        target.Users,
			Groups:       target.Groups,
			Timestamp:    timestamp,
		}

		matched, err := policies.QueryPoliciesByDimensions(ctx, dims)
		if err != nil {
			return jsonError(c, http.StatusInternalServerError, "failed to query policies")
		}
		if matched == nil {
			matched = []PolicyWithDimensions{}
		}

		return c.JSON(http.StatusOK, PolicyQueryResponse{
			Target:             targetToSummary(target),
			ApplicablePolicies: matched,
		})
	}
}

func listTargetsHandler(targets TargetStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		all, err := targets.ListTargets(ctx)
		if err != nil {
			return jsonError(c, http.StatusInternalServerError, "failed to list targets")
		}
		if all == nil {
			all = []TargetRow{}
		}
		return c.JSON(http.StatusOK, all)
	}
}

func targetToSummary(t *TargetRow) TargetSummary {
	return TargetSummary{
		ID:           t.TargetID,
		Name:         t.TargetName,
		Type:         t.TargetType,
		Technologies: t.Technologies,
		Geopolitical: t.Geopolitical,
		Sensitivity:  t.Sensitivity,
		RegisteredAt: t.RegisteredAt.Format(time.RFC3339),
	}
}

func arraysOverlap(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if set[v] {
			return true
		}
	}
	return false
}
