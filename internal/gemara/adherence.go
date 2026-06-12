// SPDX-License-Identifier: Apache-2.0

package gemara

import (
	"strings"
	"time"

	sdk "github.com/gemaraproj/go-gemara"
)

// ExtractAdherenceFrequencies parses policy YAML and returns a map of
// requirement_id → max evidence age derived from each assessment plan's
// frequency field. Requirements without a plan are not included.
func ExtractAdherenceFrequencies(content string) map[string]time.Duration {
	var partial struct {
		Adherence struct {
			AssessmentPlans []sdk.AssessmentPlan `yaml:"assessment-plans"`
		} `yaml:"adherence"`
	}
	if err := UnmarshalYAML([]byte(content), &partial); err != nil {
		return nil
	}

	if len(partial.Adherence.AssessmentPlans) == 0 {
		return nil
	}

	out := make(map[string]time.Duration, len(partial.Adherence.AssessmentPlans))
	for _, plan := range partial.Adherence.AssessmentPlans {
		if plan.RequirementId == "" {
			continue
		}
		if d := frequencyToDuration(plan.Frequency); d > 0 {
			out[plan.RequirementId] = d
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func frequencyToDuration(freq string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(freq)) {
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 30 * 24 * time.Hour
	case "quarterly":
		return 90 * 24 * time.Hour
	case "annually", "annual":
		return 365 * 24 * time.Hour
	default:
		return 0
	}
}
