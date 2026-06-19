// SPDX-License-Identifier: Apache-2.0

package gemara

import (
	"fmt"
	"time"

	sdk "github.com/gemaraproj/go-gemara"
	goyaml "github.com/goccy/go-yaml"
)

// AuditLogSummary holds the extracted metadata and classification counts
// from a parsed Gemara #AuditLog artifact.
type AuditLogSummary struct {
	AuditStart   time.Time
	AuditEnd     time.Time
	TargetID     string
	Framework    string
	Strengths    int
	Findings     int
	Gaps         int
	Observations int
}

// ParseAuditLog parses a Gemara #AuditLog YAML string and returns an
// AuditLogSummary with dates, target, and classification counts.
func ParseAuditLog(content string) (*AuditLogSummary, error) {
	var log sdk.AuditLog
	if err := goyaml.Unmarshal([]byte(content), &log); err != nil {
		return nil, fmt.Errorf("parse audit log YAML: %w", err)
	}

	if len(log.Results) == 0 {
		return nil, fmt.Errorf("audit log has no results")
	}

	summary := &AuditLogSummary{
		TargetID: log.Target.Id,
	}

	if log.Metadata.Date != "" {
		if t, err := time.Parse(time.RFC3339, string(log.Metadata.Date)); err == nil {
			summary.AuditEnd = t
		}
	}

	// Derive audit_start from earliest evidence collected timestamp
	var earliest time.Time
	for _, r := range log.Results {
		for _, ev := range r.Evidence {
			if t, err := time.Parse(time.RFC3339, string(ev.CollectedAt)); err == nil {
				if earliest.IsZero() || t.Before(earliest) {
					earliest = t
				}
			}
		}
	}
	if !earliest.IsZero() {
		summary.AuditStart = earliest
	} else if !summary.AuditEnd.IsZero() {
		summary.AuditStart = summary.AuditEnd
	}

	if summary.AuditEnd.IsZero() && !summary.AuditStart.IsZero() {
		summary.AuditEnd = summary.AuditStart
	}

	if len(log.Metadata.MappingReferences) > 0 {
		summary.Framework = log.Metadata.MappingReferences[0].Title
	}

	for _, r := range log.Results {
		switch r.Type {
		case sdk.ResultStrength:
			summary.Strengths++
		case sdk.ResultFinding:
			summary.Findings++
		case sdk.ResultGap:
			summary.Gaps++
		case sdk.ResultObservation:
			summary.Observations++
		}
	}

	return summary, nil
}
