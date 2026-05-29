// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"fmt"
	"time"

	gemara "github.com/gemaraproj/go-gemara"
)

// parseDatetime converts a gemara.Datetime (ISO 8601 string) to *time.Time.
// Returns nil when the input is empty.
func parseDatetime(dt gemara.Datetime) (*time.Time, error) {
	s := string(dt)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("parse datetime %q: %w", s, err)
	}
	return &t, nil
}

// evalResultToCompliance maps assessment results to compliance status.
func evalResultToCompliance(result string) string {
	switch result {
	case "Passed":
		return "Compliant"
	case "Failed":
		return "Non-Compliant"
	case "Not Applicable":
		return "Not Applicable"
	default:
		return "Unknown"
	}
}

// FlattenEvaluationLog produces one EvidenceRow per AssessmentLog entry.
// Remediation columns are nil for evaluation-only records.
// policyID is derived by the caller from metadata.mapping-references.
func FlattenEvaluationLog(log *gemara.EvaluationLog, policyID string) ([]EvidenceRow, error) {
	if len(log.Evaluations) == 0 {
		return nil, fmt.Errorf("evaluation log %s has no evaluations", log.Metadata.Id)
	}

	var rows []EvidenceRow
	for _, eval := range log.Evaluations {
		if eval == nil {
			continue
		}
		for _, al := range eval.AssessmentLogs {
			if al == nil {
				continue
			}

			start, err := parseDatetime(al.Start)
			if err != nil {
				return nil, err
			}

			var collectedAt time.Time
			if start != nil {
				collectedAt = *start
			}

			reqID := al.Requirement.EntryId
			steps := uint16(al.StepsExecuted)

		row := EvidenceRow{
			EvidenceID: log.Metadata.Id,

			TargetID:   log.Target.Id,
			TargetName: strPtr(log.Target.Name),
			TargetType: strPtr(log.Target.Type.String()),
			TargetEnv:  strPtr(log.Target.Environment),
			Owner:      strPtr(log.Target.Owner.Name),

			EngineName:    strPtr(log.Metadata.Author.Name),
			EngineVersion: strPtr(log.Metadata.Version),

			RuleID: eval.Control.EntryId,

				EvalResult:  al.Result.String(),
				EvalMessage: strPtr(al.Message),

				PolicyID:             strPtr(policyID),
				ControlID:            strPtr(eval.Control.EntryId),
				ControlCatalogID:     strPtr(eval.Control.ReferenceId),
				ControlApplicability: al.Applicability,
				RequirementID:        strPtr(reqID),
				Confidence:           strPtr(al.ConfidenceLevel.String()),
				StepsExecuted:        uint16Ptr(steps),
				ComplianceStatus:     evalResultToCompliance(al.Result.String()),
				Frameworks:           []string{},
				Requirements:         []string{},

				EnrichmentStatus: "Success",

				CollectedAt: collectedAt,
			}

			if al.Plan != nil {
				row.PlanID = strPtr(al.Plan.EntryId)
			}

			rows = append(rows, row)
		}
	}
	return rows, nil
}

// dispositionToRemediation maps enforcement dispositions to remediation actions.
func dispositionToRemediation(d string) string {
	switch d {
	case "Enforced":
		return "Remediate"
	case "Tolerated":
		return "Waive"
	case "Clear":
		return "Allow"
	default:
		return "Unknown"
	}
}

// FlattenEnforcementLog produces one EvidenceRow per AssessmentFinding
// with co-located evaluation and remediation columns populated.
// policyID is derived by the caller from metadata.mapping-references.
func FlattenEnforcementLog(log *gemara.EnforcementLog, policyID string) ([]EvidenceRow, error) {
	if len(log.Actions) == 0 {
		return nil, fmt.Errorf("enforcement log %s has no actions", log.Metadata.Id)
	}

	var rows []EvidenceRow
	for _, action := range log.Actions {
		if action == nil {
			continue
		}

		start, err := parseDatetime(action.Start)
		if err != nil {
			return nil, err
		}

		var collectedAt time.Time
		if start != nil {
			collectedAt = *start
		}

		remAction := dispositionToRemediation(action.Disposition.String())
		remStatus := "Success"

		exceptionRefs := make([]string, 0, len(action.Justification.Exceptions))
		for _, exc := range action.Justification.Exceptions {
			exceptionRefs = append(exceptionRefs, exc.ReferenceId)
		}
		hasException := len(exceptionRefs) > 0

		var exceptionID *string
		if hasException {
			exceptionID = strPtr(exceptionRefs[0])
		}

		for _, af := range action.Justification.Assessments {
			controlID := af.Requirement.ReferenceId
			requirementID := af.Requirement.EntryId

			rows = append(rows, EvidenceRow{
				EvidenceID: log.Metadata.Id,

				TargetID:   log.Target.Id,
				TargetName: strPtr(log.Target.Name),
				TargetType: strPtr(log.Target.Type.String()),
				TargetEnv:  strPtr(log.Target.Environment),
				Owner:      strPtr(log.Target.Owner.Name),

				EngineName:    strPtr(log.Metadata.Author.Name),
				EngineVersion: strPtr(log.Metadata.Version),

				RuleID: action.Method.EntryId,

				EvalResult:  af.Result.String(),
				EvalMessage: action.Message,

				PolicyID:         strPtr(policyID),
				ControlID:        strPtr(controlID),
				ControlCatalogID: strPtr(action.Method.ReferenceId),
				RequirementID:    strPtr(requirementID),
				ComplianceStatus: evalResultToCompliance(af.Result.String()),
				Frameworks:       []string{},
				Requirements:     []string{},

				RemediationAction: strPtr(remAction),
				RemediationStatus: strPtr(remStatus),
				RemediationDesc:   action.Message,
				ExceptionID:       exceptionID,
				ExceptionActive:   &hasException,

				EnrichmentStatus: "Success",

				CollectedAt: collectedAt,
			})
		}
	}
	return rows, nil
}
