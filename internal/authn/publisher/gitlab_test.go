package publisher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitLabCIValidateTrustEntry(t *testing.T) {
	g := &GitLabCIIssuer{url: "https://gitlab.com"}

	valid := []string{
		"project_path:my-group/my-project:ref_type:branch:ref:main",
		"project_path:org/sub-group/project:ref_type:tag:ref:v1.0.0",
		"project_path:group/project:ref_type:branch:ref:feature/my-feature",
	}
	invalid := []string{
		"",
		"repo:org/project:ref:refs/heads/main",
		"project_path:no-slash",
		"project_path:group/project:invalid_type:branch:ref:main",
		"project_path:group/project",
		"project_path:group/project:ref_type:commit:ref:abc123",
	}

	for _, sub := range valid {
		assert.NoError(t, g.ValidateTrustEntry(sub), "should accept: %s", sub)
	}
	for _, sub := range invalid {
		assert.Error(t, g.ValidateTrustEntry(sub), "should reject: %s", sub)
	}
}
