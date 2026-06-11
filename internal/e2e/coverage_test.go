// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/complytime-labs/complytime-core/internal/db"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/gemara"
	"github.com/complytime-labs/complytime-core/internal/posture"
	"github.com/complytime-labs/complytime-core/internal/store"
)

var _ = Describe("Coverage Endpoint", func() {
	var (
		ctx          context.Context
		pgClient     *db.Client
		st           *store.Store
		tracker      *store.IngestTracker
		ingestServer *httptest.Server
		apiServer    *httptest.Server
		jwtCtx       *jwtTestContext
	)

	BeforeEach(func() {
		ctx = context.Background()
		pgURL := os.Getenv("POSTGRES_TEST_URL")

		By("Connecting to PostgreSQL")
		var err error
		pgClient, err = db.New(ctx, db.Config{URL: pgURL})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(pgClient.Close)

		err = pgClient.EnsureSchema(ctx)
		Expect(err).NotTo(HaveOccurred())

		_, err = pgClient.Pool().Exec(ctx,
			"TRUNCATE evidence, controls, assessment_requirements, policies, witnessed_indices, trust_signals CASCADE")
		Expect(err).NotTo(HaveOccurred())

		st = store.New(pgClient.Pool())

		By("Starting NATS and Tessera")
		natsServer := startTestNATSServer(GinkgoT())
		tesseraClient := newTestTessera(GinkgoT())
		jwtCtx = newTestJWTVerifier(GinkgoT())
		bus := connectTestNATS(GinkgoT(), natsServer.ClientURL())
		tracker = store.NewIngestTracker()

		workerCtx, cancelWorker := context.WithCancel(ctx)
		DeferCleanup(cancelWorker)

		stores := store.Stores{
			Evidence: st,
			Policies: st,
			Controls: st,
			Mappings: st,
		}
		setupJetStreamWorker(GinkgoT(), workerCtx, bus, stores, bus, tracker, tesseraClient)

		By("Starting ingest server")
		ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
		ingestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ingestHandler.ServeHTTP(w, r)
		}))
		DeferCleanup(ingestServer.Close)

		By("Starting API server with coverage endpoint")
		e := echo.New()
		e.HideBanner = true
		apiStores := store.Stores{
			Policies:    st,
			Mappings:    st,
			Coverage:    st,
			Evidence:    st,
			Controls:    st,
			Catalogs:    st,
		}
		store.Register(e.Group("/api"), apiStores)
		apiServer = httptest.NewServer(e)
		DeferCleanup(apiServer.Close)
	})

	It("reports coverage with gaps and covered controls", func() {
		By("Inserting controls for test-policy directly")
		controls := []gemara.ControlRow{
			{CatalogID: "test-controls", ControlID: "AC-1", Title: "Access Control Policy", PolicyID: "test-policy"},
			{CatalogID: "test-controls", ControlID: "AC-2", Title: "Account Management", PolicyID: "test-policy"},
			{CatalogID: "test-controls", ControlID: "AC-3", Title: "Access Enforcement", PolicyID: "test-policy"},
			{CatalogID: "test-controls", ControlID: "CM-1", Title: "Configuration Management Policy", PolicyID: "test-policy"},
		}
		err := st.InsertControls(ctx, controls)
		Expect(err).NotTo(HaveOccurred())

		By("Ingesting evidence that covers AC-1 only")
		evalLogYAML, err := os.ReadFile("testdata/evaluation_log_certifiable.yaml")
		Expect(err).NotTo(HaveOccurred())

		token := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/test-repo:ref:refs/heads/main")
		resp, result := submitEvidence(GinkgoT(), ingestServer.URL, token, evalLogYAML)
		Expect(resp.StatusCode).To(Equal(http.StatusAccepted))
		waitForJob(tracker, result["job_id"].(string))

		By("Waiting for evidence to be queryable")
		Eventually(func() int {
			rows, _ := st.QueryEvidence(ctx, evidence.EvidenceFilter{PolicyIDs: []string{"test-policy"}, Limit: 1})
			return len(rows)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(BeNumerically(">", 0))

		By("Querying coverage endpoint")
		coverageURL := fmt.Sprintf("%s/api/policies/test-policy/coverage", apiServer.URL)
		coverageResp, err := http.Get(coverageURL) //nolint:gosec // G107: test server URL
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = coverageResp.Body.Close() }()

		Expect(coverageResp.StatusCode).To(Equal(http.StatusOK))

		var coverage posture.CoverageResult
		err = json.NewDecoder(coverageResp.Body).Decode(&coverage)
		Expect(err).NotTo(HaveOccurred())

		GinkgoWriter.Printf("Coverage: %d/%d controls (%.1f%%)\n",
			coverage.CoveredControls, coverage.TotalControls, coverage.CoveragePct)
		GinkgoWriter.Printf("  Covered: %v\n", coverage.Covered)
		GinkgoWriter.Printf("  Gaps:    %v\n", coverage.Gaps)

		Expect(coverage.PolicyID).To(Equal("test-policy"))
		Expect(coverage.TotalControls).To(Equal(4))
		Expect(coverage.Covered).To(ContainElement("AC-1"))
		Expect(coverage.Gaps).To(ContainElements("AC-2", "AC-3", "CM-1"))
		Expect(coverage.CoveredControls).To(Equal(1))
		Expect(coverage.CoveragePct).To(Equal(25.0))
	})

	It("returns 404 for a policy with no controls", func() {
		coverageURL := fmt.Sprintf("%s/api/policies/nonexistent-policy/coverage", apiServer.URL)
		resp, err := http.Get(coverageURL) //nolint:gosec // G107: test server URL
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()

		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
	})

	It("detects stale evidence with max_age", func() {
		By("Inserting controls")
		controls := []gemara.ControlRow{
			{CatalogID: "test-controls", ControlID: "AC-1", Title: "Access Control Policy", PolicyID: "test-policy"},
			{CatalogID: "test-controls", ControlID: "AC-2", Title: "Account Management", PolicyID: "test-policy"},
		}
		err := st.InsertControls(ctx, controls)
		Expect(err).NotTo(HaveOccurred())

		By("Inserting old evidence directly")
		oldTime := time.Now().Add(-60 * 24 * time.Hour) // 60 days ago
		_, err = pgClient.Pool().Exec(ctx,
			`INSERT INTO evidence (evidence_id, target_id, policy_id, control_id, requirement_id,
				rule_id, eval_result, compliance_status, collected_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			"old-ev-1", "tgt-1", "test-policy", "AC-1", "AC-1.1",
			"rule-1", "Passed", "Compliant", oldTime)
		Expect(err).NotTo(HaveOccurred())

		By("Querying with max_age=720h (30 days)")
		coverageURL := fmt.Sprintf("%s/api/policies/test-policy/coverage?max_age=720h", apiServer.URL)
		coverageResp, err := http.Get(coverageURL) //nolint:gosec // G107: test server URL
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = coverageResp.Body.Close() }()

		Expect(coverageResp.StatusCode).To(Equal(http.StatusOK))

		var coverage posture.CoverageResult
		err = json.NewDecoder(coverageResp.Body).Decode(&coverage)
		Expect(err).NotTo(HaveOccurred())

		GinkgoWriter.Printf("Stale controls: %v\n", coverage.Stale)

		Expect(coverage.Covered).To(ContainElement("AC-1"))
		Expect(coverage.Stale).To(ContainElement("AC-1"))
		Expect(coverage.Gaps).To(ContainElement("AC-2"))
	})
})
