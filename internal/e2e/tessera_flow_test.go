// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/complytime-labs/complytime-core/internal/postgres"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

var _ = Describe("Tessera Evidence Flow", func() {
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

		By("Starting HTTP server")
		ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ingestHandler.ServeHTTP(w, r)
		}))
		DeferCleanup(server.Close)
	})

	Context("happy path", func() {
		It("ingests evidence through the full pipeline", func() {
			By("Loading test YAML fixture")
			evalLogYAML, err := os.ReadFile("testdata/evaluation_log_sample.yaml")
			Expect(err).NotTo(HaveOccurred(), "Failed to read test YAML")

			By("Generating JWT token")
			testSubject := "repo:org/test-repo:ref:refs/heads/main"
			token := jwtCtx.generateTestJWT(GinkgoT(), testSubject)

			By("Submitting evidence via HTTP POST")
			resp, result := submitEvidence(GinkgoT(), server.URL, token, evalLogYAML)
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted), "Expected 202 Accepted")

			jobID, ok := result["job_id"].(string)
			Expect(ok).To(BeTrue(), "job_id not found in response")

			logIndexFloat, ok := result["log_index"].(float64)
			Expect(ok).To(BeTrue(), "log_index not found in response")
			logIndex := uint64(logIndexFloat)

			GinkgoWriter.Printf("Submitted evidence: job_id=%s, log_index=%d\n", jobID, logIndex)

			By("Waiting for worker to process")
			waitForJob(tracker, jobID)

			By("Verifying Tessera contains entry")
			tesseraEntry, err := tesseraClient.Read(ctx, logIndex)
			Expect(err).NotTo(HaveOccurred(), "Failed to read from Tessera")
			Expect(tesseraEntry).NotTo(BeEmpty(), "Tessera entry is empty")
			Expect(string(tesseraEntry)).To(ContainSubstring("metadata"), "Tessera entry missing metadata")

			By("Verifying PostgreSQL has evidence with publisher fields")
			evidenceRow, err := st.QueryEvidenceByLogIndex(ctx, logIndex)
			Expect(err).NotTo(HaveOccurred(), "Failed to query evidence by log_index")
			Expect(evidenceRow).NotTo(BeNil(), "Evidence not found in database")

			Expect(evidenceRow.PublisherIssuer).To(Equal(jwtCtx.IssuerURL),
				"PublisherIssuer not populated - worker bug not fixed!")
			Expect(evidenceRow.SubmittedBy).To(Equal(testSubject),
				"SubmittedBy not populated - worker bug not fixed!")
			Expect(evidenceRow.PublisherType).To(Equal("pipeline"),
				"PublisherType not populated - worker bug not fixed!")

			GinkgoWriter.Printf("  - PublisherIssuer: %s\n", evidenceRow.PublisherIssuer)
			GinkgoWriter.Printf("  - SubmittedBy: %s\n", evidenceRow.SubmittedBy)
			GinkgoWriter.Printf("  - PublisherType: %s\n", evidenceRow.PublisherType)
			GinkgoWriter.Printf("  - Certified: %v\n", evidenceRow.Certified)

			By("Simulating witness service marking index as witnessed")
			witnessName := "test-witness"
			err = st.MarkIndexWitnessed(ctx, logIndex, witnessName, "test-checkpoint-hash")
			Expect(err).NotTo(HaveOccurred(), "Failed to mark index as witnessed")

			By("Verifying witness marking persists")
			witnessed := st.IsIndexWitnessed(ctx, logIndex)
			Expect(witnessed).To(BeTrue(), "Index should be marked witnessed")
		})
	})

	Context("invalid JWT", func() {
		It("rejects with 403 Forbidden", func() {
			By("Submitting with invalid token")
			req, err := http.NewRequest("POST", server.URL, bytes.NewReader([]byte("test")))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer invalid-token")

			resp, err := http.DefaultClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()

			By("Verifying rejection")
			Expect(resp.StatusCode).To(Equal(http.StatusForbidden), "Expected 403 Forbidden for invalid JWT")
		})
	})

	Context("untrusted publisher", func() {
		It("stores evidence but witness would reject", func() {
			By("Loading test YAML fixture")
			evalLogYAML, err := os.ReadFile("testdata/evaluation_log_sample.yaml")
			Expect(err).NotTo(HaveOccurred())

			By("Submitting evidence with untrusted subject")
			untrustedSubject := "repo:malicious/attacker:ref:refs/heads/main"
			token := jwtCtx.generateTestJWT(GinkgoT(), untrustedSubject)

			resp, result := submitEvidence(GinkgoT(), server.URL, token, evalLogYAML)
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted))

			jobID := result["job_id"].(string)
			logIndex := uint64(result["log_index"].(float64))

			By("Waiting for worker to process")
			waitForJob(tracker, jobID)

			By("Verifying evidence was stored with untrusted subject")
			evidenceRow, err := st.QueryEvidenceByLogIndex(ctx, logIndex)
			Expect(err).NotTo(HaveOccurred())
			Expect(evidenceRow).NotTo(BeNil())

			Expect(evidenceRow.SubmittedBy).To(Equal(untrustedSubject),
				"Evidence should have untrusted subject stored")
			GinkgoWriter.Printf("Evidence stored with untrusted publisher subject: %s\n", untrustedSubject)
		})
	})
})
