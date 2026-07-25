//go:build acceptance

package acceptance_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OTel Instrumentation", func() {
	Describe("Prometheus metrics", func() {
		It("gateway exposes /metrics endpoint", func() {
			resp, err := http.Get(prometheusURL("gateway"))
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring("target_info"))
		})

		It("locker exposes /metrics endpoint", func() {
			resp, err := http.Get(prometheusURL("locker"))
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring("target_info"))
		})
	})

	Describe("Distributed tracing", func() {
		It("ingest-to-seal flow produces linked traces in Jaeger", func() {
			// Trigger an ingest flow
			token := mintToken("test-publisher", "complytime-gateway", false, false)
			artifact := map[string]interface{}{
				"metadata": map[string]interface{}{"type": "evaluation-log"},
				"target":   map[string]interface{}{"id": "acceptance-test-subject"},
			}
			body, err := json.Marshal(artifact)
			Expect(err).NotTo(HaveOccurred())
			ingestAndSeal(token, "acceptance-test-subject", body, 2)

			// Query Jaeger for gateway traces
			Eventually(func() bool {
				resp, err := http.Get(jaegerAPIURL("/api/traces?service=complytime-gateway&limit=5"))
				if err != nil {
					return false
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					return false
				}
				return strings.Contains(string(respBody), "complytime-gateway")
			}, 30*time.Second, 2*time.Second).Should(BeTrue(), "Jaeger should contain gateway traces")
		})
	})
})
