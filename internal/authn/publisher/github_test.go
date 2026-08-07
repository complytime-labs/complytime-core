package publisher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitHubActionsValidateTrustEntry(t *testing.T) {
	g := &GitHubActionsIssuer{url: GitHubActionsIssuerURL}

	valid := []string{
		"repo:org/repo:ref:refs/heads/main",
		"repo:org/repo:environment:production",
		"repo:org/repo:pull_request:",
		"repo:org/repo:tag:v1.0.0",
		"repo:org/repo:ref:refs/tags/v2.0.0",
		"repo:org/repo:branch:main",
	}
	invalid := []string{
		"",
		"not-a-repo",
		"repo:missing-slash",
		"repo:org/repo",
		"https://token.actions.githubusercontent.com",
	}

	for _, sub := range valid {
		assert.NoError(t, g.ValidateTrustEntry(sub), "should accept: %s", sub)
	}
	for _, sub := range invalid {
		assert.Error(t, g.ValidateTrustEntry(sub), "should reject: %s", sub)
	}
}
