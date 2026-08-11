package publisher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKubernetesValidateTrustEntry(t *testing.T) {
	k := &KubernetesIssuer{url: "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"}

	valid := []string{
		"system:serviceaccount:default:my-service-account",
		"system:serviceaccount:kube-system:coredns",
		"system:serviceaccount:production:complytime-publisher",
		"system:serviceaccount:ci:tekton-pipeline",
	}
	invalid := []string{
		"",
		"not-a-service-account",
		"system:serviceaccount:default",
		"system:serviceaccount::name",
		"system:serviceaccount:namespace:",
		"serviceaccount:default:my-sa",
		"arn:aws:sts::123456789012:assumed-role/role/session",
	}

	for _, sub := range valid {
		assert.NoError(t, k.ValidateTrustEntry(sub), "should accept: %s", sub)
	}
	for _, sub := range invalid {
		assert.Error(t, k.ValidateTrustEntry(sub), "should reject: %s", sub)
	}
}
