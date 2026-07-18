//go:build acceptance

package acceptance_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAcceptance(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Acceptance Suite")
}

var _ = BeforeSuite(func() {
	By("verifying all services are healthy")
	services := map[string]string{
		"gateway":  gatewayURL("/healthz"),
		"locker":   lockerURL("/healthz"),
		"testjwks": testjwksURL("/healthz"),
	}

	for name, url := range services {
		Eventually(func() int {
			resp, err := http.Get(url)
			if err != nil {
				return 0
			}
			defer resp.Body.Close()
			return resp.StatusCode
		}, 30*time.Second, 1*time.Second).Should(Equal(http.StatusOK),
			fmt.Sprintf("%s should be healthy at %s", name, url))
	}

	By("registering a test subject with a trusted publisher")
	adminToken := mintToken("test-admin", "complytime-gateway", true, false)
	registerSubject(adminToken, "acceptance-test-subject", testjwksURL(""), "test-publisher")
})
