package publisher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGCPWorkloadValidateTrustEntry(t *testing.T) {
	g := &GCPWorkloadIssuer{url: GCPWorkloadIssuerURL}

	valid := []string{
		"https://iam.googleapis.com/projects/my-project/locations/global/workloadIdentityPools/my-pool/subject/my-subject",
		"service-account@my-project.iam.gserviceaccount.com",
		"svc@example-project.iam.gserviceaccount.com",
	}
	invalid := []string{
		"",
		"not-gcp",
		"user@gmail.com",
		"someone@example.com",
	}

	for _, sub := range valid {
		assert.NoError(t, g.ValidateTrustEntry(sub), "should accept: %s", sub)
	}
	for _, sub := range invalid {
		assert.Error(t, g.ValidateTrustEntry(sub), "should reject: %s", sub)
	}
}
