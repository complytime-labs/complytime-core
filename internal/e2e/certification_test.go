// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/complytime-labs/complytime-core/internal/postgres"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

var _ = Describe("Certification Pipeline", func() {
	var (
		ctx           context.Context
		pgClient      *postgres.Client
		st            *store.Store
		tracker       *store.IngestTracker
		server        *httptest.Server
		jwtCtx        *jwtTestContext
		tesseraClient *tessera.Client
	)

	BeforeEach(func() {
		ctx = context.Background()
		pgURL := os.Getenv("POSTGRES_TEST_URL")

		By("Connecting to PostgreSQL")
		var err error
		pgClient, err = postgres.New(ctx, postgres.Config{URL: pgURL})
		Expect(err).NotTo(HaveOccurred(), "Failed to connect to PostgreSQL")
		DeferCleanup(pgClient.Close)

		By("Running migrations")
		err = pgClient.EnsureSchema(ctx)
		Expect(err).NotTo(HaveOccurred(), "Failed to run migrations")

		By("Cleaning up evidence from previous tests")
		_, err = pgClient.Pool().Exec(ctx, "TRUNCATE evidence, witnessed_indices, certifications CASCADE")
		Expect(err).NotTo(HaveOccurred(), "Failed to truncate evidence tables")

		st = store.New(pgClient.Pool())

		By("Starting NATS server")
		natsServer := startTestNATSServer(GinkgoT())
		natsURL := natsServer.ClientURL()

		By("Creating Tessera client")
		tesseraClient = newTestTessera(GinkgoT())

		By("Creating JWT verifier")
		jwtCtx = newTestJWTVerifier(GinkgoT())

		By("Subscribing NATS worker")
		bus := connectTestNATS(GinkgoT(), natsURL)
		tracker = store.NewIngestTracker()

		workerCtx, cancelWorker := context.WithCancel(context.Background())
		DeferCleanup(cancelWorker)

		stores := store.Stores{
			Evidence: st,
			Policies: st,
			Controls: st,
			Mappings: st,
		}

		worker := store.IngestWorker(workerCtx, stores, bus, tracker)
		_, err = bus.SubscribeIngestRaw(worker)
		Expect(err).NotTo(HaveOccurred(), "Failed to subscribe worker to NATS")

		By("Setting up certification pipeline with 100ms debounce")
		certBus := connectTestNATS(GinkgoT(), natsURL)
		setupCertificationPipeline(st, certBus)

		By("Starting HTTP server")
		ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ingestHandler.ServeHTTP(w, r)
		}))
		DeferCleanup(server.Close)
	})

	Context("when evidence passes all certifiers", func() {
		It("marks evidence as certified", func() {
			By("Loading certifiable evaluation log fixture")
			evalLogYAML, err := os.ReadFile("testdata/evaluation_log_certifiable.yaml")
			Expect(err).NotTo(HaveOccurred(), "Failed to read certifiable test YAML")

			By("Generating JWT token")
			testSubject := "repo:org/test-repo:ref:refs/heads/main"
			token := jwtCtx.generateTestJWT(GinkgoT(), testSubject)

			By("Submitting evidence via HTTP POST")
			resp, result := submitEvidence(GinkgoT(), server.URL, token, evalLogYAML)
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted), "Expected 202 Accepted")

			jobID, ok := result["job_id"].(string)
			Expect(ok).To(BeTrue(), "job_id not found in response")

			logIndex := uint64(result["log_index"].(float64))
			GinkgoWriter.Printf("Submitted certifiable evidence: job_id=%s, log_index=%d\n", jobID, logIndex)

			By("Waiting for worker to process")
			waitForJob(tracker, jobID)

			By("Waiting for certification pipeline to complete (debounce + processing)")
			// The certification pipeline fires after 100ms debounce and then
			// queries evidence rows for the policy. We poll until certified=true.
			Eventually(func() bool {
				rows, err := st.QueryEvidence(ctx, store.EvidenceFilter{
					PolicyIDs: []string{"test-policy"},
					Limit:     1,
				})
				if err != nil || len(rows) == 0 {
					return false
				}
				return rows[0].Certified
			}).WithTimeout(5 * time.Second).WithPolling(200 * time.Millisecond).Should(
				BeTrue(), "Evidence should be certified after pipeline runs",
			)

			By("Verifying certification verdicts in the certifications table")
			evidenceRows, err := st.QueryEvidence(ctx, store.EvidenceFilter{
				PolicyIDs: []string{"test-policy"},
				Limit:     10,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(evidenceRows).NotTo(BeEmpty(), "Expected evidence rows for test-policy")

			for _, evRow := range evidenceRows {
				certs, err := st.QueryCertifications(ctx, evRow.EvidenceID)
				Expect(err).NotTo(HaveOccurred())
				Expect(certs).NotTo(BeEmpty(), "Expected certification rows for evidence %s", evRow.EvidenceID)

				for _, cert := range certs {
					GinkgoWriter.Printf("  Certification: certifier=%s verdict=%s reason=%s\n",
						cert.Certifier, cert.Result, cert.Reason)
					Expect(cert.Result).To(Equal("pass"),
						"Certifier %s should pass for certifiable evidence", cert.Certifier)
				}
			}
		})
	})

	Context("when evidence fails certification", func() {
		It("leaves evidence as not certified", func() {
			By("Loading minimal evaluation log fixture (missing engine metadata)")
			// The evaluation_log_sample.yaml uses metadata.author.name="test-engine"
			// which maps to engine_name in the flattener. The SchemaCertifier will pass
			// but the ExecutorCertifier may fail if the engine is not in KnownEngines.
			// For this test, we use inline YAML that lacks a recognized engine name.
			failYAML := []byte(`metadata:
  type: EvaluationLog
  id: eval-fail-001
  version: 1.0.0
  date: "2026-05-26T12:00:00Z"
  author:
    name: unknown-engine
    version: 0.0.1
  mapping-references:
    - id: fail-policy
      title: Fail Policy
      version: "1.0.0"
target:
  id: tgt-fail-001
  name: Fail Target
  type: Software
evaluations:
  - control:
      entry-id: AC-2
      reference-id: nist-800-53
    assessment-logs:
      - result: Passed
        start: "2026-05-26T12:00:00Z"
        requirement:
          entry-id: AC-2.1
`)

			By("Generating JWT token")
			token := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/test-repo:ref:refs/heads/main")

			By("Submitting evidence via HTTP POST")
			resp, result := submitEvidence(GinkgoT(), server.URL, token, failYAML)
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted), "Expected 202 Accepted")

			jobID, ok := result["job_id"].(string)
			Expect(ok).To(BeTrue(), "job_id not found in response")

			logIndex := uint64(result["log_index"].(float64))
			GinkgoWriter.Printf("Submitted failing evidence: job_id=%s, log_index=%d\n", jobID, logIndex)

			By("Waiting for worker to process")
			waitForJob(tracker, jobID)

			By("Waiting for certification pipeline to complete")
			// Give the debouncer time to fire (100ms) plus some margin for processing.
			// After processing, evidence should still be NOT certified because
			// unknown-engine is not in the KnownEngines map.
			Eventually(func() bool {
				// Check that certifications table has been populated (indicating
				// the pipeline ran), but certified flag is false.
				evRows, err := st.QueryEvidence(ctx, store.EvidenceFilter{
					PolicyIDs: []string{"fail-policy"},
					Limit:     10,
				})
				if err != nil || len(evRows) == 0 {
					return false
				}
				certs, err := st.QueryCertifications(ctx, evRows[0].EvidenceID)
				if err != nil {
					return false
				}
				return len(certs) > 0 // Pipeline ran
			}).WithTimeout(5 * time.Second).WithPolling(200 * time.Millisecond).Should(
				BeTrue(), "Certification pipeline should have processed the evidence",
			)

			By("Verifying evidence remains not certified")
			evRows, err := st.QueryEvidence(ctx, store.EvidenceFilter{
				PolicyIDs: []string{"fail-policy"},
				Limit:     10,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(evRows).NotTo(BeEmpty(), "Evidence should exist in database")
			Expect(evRows[0].Certified).To(BeFalse(),
				"Evidence with unknown engine should NOT be certified")

			By("Verifying at least one certification verdict is 'fail'")
			certs, err := st.QueryCertifications(ctx, evRows[0].EvidenceID)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).NotTo(BeEmpty())

			hasFail := false
			for _, cert := range certs {
				GinkgoWriter.Printf("  Certification: certifier=%s verdict=%s reason=%s\n",
					cert.Certifier, cert.Result, cert.Reason)
				if cert.Result == "fail" {
					hasFail = true
				}
			}
			Expect(hasFail).To(BeTrue(), "At least one certifier should have verdict=fail")
		})
	})
})
