// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestE2E(t *testing.T) {
	if os.Getenv("POSTGRES_TEST_URL") == "" {
		t.Skip("POSTGRES_TEST_URL not set, skipping E2E tests")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "E2E Suite")
}
