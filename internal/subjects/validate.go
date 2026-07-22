package subjects

import (
	"fmt"
	"regexp"
)

// subjectIDPattern validates subjectID as a flat slug.
// Allows alphanumeric, underscores, hyphens. No dots (NATS subject delimiter).
// Must start with alphanumeric. Max 254 characters.
var subjectIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,253}$`)

// ValidateSubjectID checks if a subjectID is valid and safe for use as a directory name.
func ValidateSubjectID(subjectID string) error {
	if subjectID == "" {
		return fmt.Errorf("subjectID cannot be empty")
	}
	if !subjectIDPattern.MatchString(subjectID) {
		return fmt.Errorf("subjectID must start with alphanumeric and contain only alphanumeric, underscore, hyphen (max 254 chars)")
	}
	return nil
}
