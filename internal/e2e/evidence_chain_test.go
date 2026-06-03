// SPDX-License-Identifier: Apache-2.0

package e2e

import (
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

var _ = Describe("Evidence Chain", func() {
	var (
		ctx           context.Context
		pgClient      *postgres.Client
		st            *store.Store
		tracker       *store.IngestTracker
		ingestServer  *httptest.Server
		jwtCtx        *jwtTestContext
		tesseraClient *tessera.Client
	)

	BeforeEach(func() {
		ctx = context.Background()
		pgURL := os.Getenv("POSTGRES_TEST_URL")

		By("Connecting to PostgreSQL")
		var err error
		pgClient, err = postgres.New(ctx, postgres.Config{URL: pgURL})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(pgClient.Close)

		By("Running migrations")
		err = pgClient.EnsureSchema(ctx)
		Expect(err).NotTo(HaveOccurred())

		By("Cleaning up evidence from previous tests")
		_, err = pgClient.Pool().Exec(ctx, "TRUNCATE evidence, witnessed_indices, trust_signals CASCADE")
		Expect(err).NotTo(HaveOccurred(), "Failed to truncate evidence tables")

		st = store.New(pgClient.Pool())

		By("Starting NATS server")
		natsServer := startTestNATSServer(GinkgoT())
		natsURL := natsServer.ClientURL()

		By("Creating Tessera client and JWT verifier")
		tesseraClient = newTestTessera(GinkgoT())
		jwtCtx = newTestJWTVerifier(GinkgoT())
		bus := connectTestNATS(GinkgoT(), natsURL)
		tracker = store.NewIngestTracker()

		workerCtx, cancelWorker := context.WithCancel(ctx)
		DeferCleanup(cancelWorker)

		stores := store.Stores{
			Evidence:         st,
			Policies:         st,
			Controls:         st,
			Mappings:         st,
			Targets:          st,
			PolicyDimensions: st,
		}

		worker := store.IngestWorker(workerCtx, stores, bus, tracker)
		_, err = bus.SubscribeIngestRaw(worker)
		Expect(err).NotTo(HaveOccurred())

		By("Starting HTTP server")
		ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
		ingestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ingestHandler.ServeHTTP(w, r)
		}))
		DeferCleanup(ingestServer.Close)
	})

	It("links evidence to policy via tessera log_index", func() {
		By("Ingesting policy through /api/ingest")
		policyYAML, err := os.ReadFile("testdata/policy_sample.yaml")
		Expect(err).NotTo(HaveOccurred())

		policyToken := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/policies:ref:refs/heads/main")
		policyResp, policyResult := submitEvidence(GinkgoT(), ingestServer.URL, policyToken, policyYAML)
		Expect(policyResp.StatusCode).To(Equal(http.StatusAccepted))

		policyJobID := policyResult["job_id"].(string)
		policyLogIndex := uint64(policyResult["log_index"].(float64))
		GinkgoWriter.Printf("Submitted policy: job_id=%s, log_index=%d\n", policyJobID, policyLogIndex)

		By("Waiting for policy worker to process")
		waitForJob(tracker, policyJobID)

		By("Verifying policy is stored in PostgreSQL with tessera_log_index")
		var storedLogIndex *uint64
		err = pgClient.Pool().QueryRow(ctx,
			`SELECT tessera_log_index FROM policies WHERE policy_id = $1`,
			"infra-baseline",
		).Scan(&storedLogIndex)
		Expect(err).NotTo(HaveOccurred())
		Expect(storedLogIndex).NotTo(BeNil(), "tessera_log_index should be set on ingested policy")
		Expect(*storedLogIndex).To(Equal(policyLogIndex), "tessera_log_index should match ingest response")

		By("Creating EvaluationLog that references the policy via mapping-references")
		// The derivePolicyID function uses the first mapping-reference id as
		// the policy_id. We use "infra-baseline" to link to the policy above.
		evalYAML := []byte(`metadata:
  type: EvaluationLog
  id: eval-chain-001
  version: 1.0.0
  date: "2026-05-26T12:00:00Z"
  author:
    name: test-engine
    version: 1.0.0
  mapping-references:
    - id: infra-baseline
      title: Infrastructure Baseline
      version: "2.0.0"
target:
  id: tgt-chain-001
  name: Chain Test Target
  type: Software
evaluations:
  - control:
      entry-id: AC-1
      reference-id: nist-800-53
    assessment-logs:
      - result: Passed
        start: "2026-05-26T12:00:00Z"
        requirement:
          entry-id: AC-1.1
`)

		By("Submitting EvaluationLog")
		evidenceToken := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/evaluations:ref:refs/heads/main")
		evidenceResp, evidenceResult := submitEvidence(GinkgoT(), ingestServer.URL, evidenceToken, evalYAML)
		Expect(evidenceResp.StatusCode).To(Equal(http.StatusAccepted))

		evidenceJobID := evidenceResult["job_id"].(string)
		evidenceLogIndex := uint64(evidenceResult["log_index"].(float64))
		GinkgoWriter.Printf("Submitted evidence: job_id=%s, log_index=%d\n", evidenceJobID, evidenceLogIndex)

		By("Waiting for evidence worker to process")
		waitForJob(tracker, evidenceJobID)

		By("Verifying both entries exist in Tessera")
		policyEntry, err := tesseraClient.Read(ctx, policyLogIndex)
		Expect(err).NotTo(HaveOccurred())
		Expect(policyEntry).NotTo(BeEmpty(), "Policy entry should exist in Tessera")

		evidenceEntry, err := tesseraClient.Read(ctx, evidenceLogIndex)
		Expect(err).NotTo(HaveOccurred())
		Expect(evidenceEntry).NotTo(BeEmpty(), "Evidence entry should exist in Tessera")

		By("Verifying evidence has policy_id matching the ingested policy")
		evidenceRows, err := st.QueryEvidence(ctx, store.EvidenceFilter{
			PolicyIDs: []string{"infra-baseline"},
			Limit:     10,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(evidenceRows).NotTo(BeEmpty(), "Expected evidence rows linked to infra-baseline policy")

		for _, ev := range evidenceRows {
			GinkgoWriter.Printf("  Evidence: id=%s policy_id=%s log_index=%v\n",
				ev.EvidenceID, ev.PolicyID, ev.LogIndex)
			Expect(ev.PolicyID).To(Equal("infra-baseline"),
				"Evidence policy_id should match the ingested policy")
			Expect(ev.LogIndex).NotTo(BeNil(), "Evidence should have a log_index")
			Expect(*ev.LogIndex).To(Equal(evidenceLogIndex),
				"Evidence log_index should match ingest response")
		}

		By("Verifying policy tessera_log_index in DB matches the policy ingest response")
		GinkgoWriter.Printf("Policy tessera_log_index: %d\n", *storedLogIndex)
		GinkgoWriter.Printf("Evidence tessera_log_index: %d\n", evidenceLogIndex)
		Expect(*storedLogIndex).To(Equal(policyLogIndex),
			"Policy and evidence should have distinct, traceable log indices")
		Expect(policyLogIndex).NotTo(Equal(evidenceLogIndex),
			"Policy and evidence should have different log indices")

		By("Verifying the reference chain: evidence -> policy_id -> policies.tessera_log_index")
		// Retrieve the policy by the policy_id that the evidence references
		policy, err := st.GetPolicy(ctx, "infra-baseline")
		Expect(err).NotTo(HaveOccurred())
		Expect(policy).NotTo(BeNil())
		Expect(policy.PolicyID).To(Equal("infra-baseline"))

		// Confirm the policy was ingested through Tessera (has tessera_log_index)
		var policyTLI *uint64
		err = pgClient.Pool().QueryRow(ctx,
			`SELECT tessera_log_index FROM policies WHERE policy_id = $1`,
			"infra-baseline",
		).Scan(&policyTLI)
		Expect(err).NotTo(HaveOccurred())
		Expect(policyTLI).NotTo(BeNil())
		Expect(*policyTLI).To(Equal(policyLogIndex),
			"Reference chain: evidence.policy_id -> policies.tessera_log_index should be intact")

		GinkgoWriter.Printf("Reference chain verified: evidence(log_index=%d) -> policy_id=infra-baseline -> policy(tessera_log_index=%d)\n",
			evidenceLogIndex, *policyTLI)
	})
})
