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

	"github.com/complytime-labs/complytime-core/internal/certify"
	"github.com/complytime-labs/complytime-core/internal/db"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/store"
)

var _ = Describe("Verification Endpoint", func() {
	var (
		ctx           context.Context
		st            *store.Store
		tracker       *store.IngestTracker
		ingestServer  *httptest.Server
		apiServer     *httptest.Server
		jwtCtx        *jwtTestContext
	)

	BeforeEach(func() {
		ctx = context.Background()
		pgURL := os.Getenv("POSTGRES_TEST_URL")

		By("Connecting to PostgreSQL")
		pgClient, err := db.New(ctx, db.Config{URL: pgURL})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(pgClient.Close)

		err = pgClient.EnsureSchema(ctx)
		Expect(err).NotTo(HaveOccurred())

		_, err = pgClient.Pool().Exec(ctx, "TRUNCATE evidence, witnessed_indices, trust_signals CASCADE")
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

		By("Setting up certification pipeline")
		certBus := connectTestNATS(GinkgoT(), natsServer.ClientURL())
		setupCertificationPipeline(st, certBus)

		By("Starting ingest server")
		ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
		ingestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ingestHandler.ServeHTTP(w, r)
		}))
		DeferCleanup(ingestServer.Close)

		By("Starting API server with verification endpoint")
		e := echo.New()
		e.HideBanner = true
		apiStores := store.Stores{
			Evidence:     st,
			TrustSignals: st,
		}
		store.Register(e.Group("/api"), apiStores)
		apiServer = httptest.NewServer(e)
		DeferCleanup(apiServer.Close)
	})

	It("returns trust signals via the verification endpoint", func() {
		By("Ingesting certifiable evidence")
		evalLogYAML, err := os.ReadFile("testdata/evaluation_log_certifiable.yaml")
		Expect(err).NotTo(HaveOccurred())

		token := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/test-repo:ref:refs/heads/main")
		resp, result := submitEvidence(GinkgoT(), ingestServer.URL, token, evalLogYAML)
		Expect(resp.StatusCode).To(Equal(http.StatusAccepted))

		jobID := result["job_id"].(string)
		waitForJob(tracker, jobID)

		By("Waiting for certification pipeline to produce trust signals")
		var evidenceID string
		Eventually(func() bool {
			rows, err := st.QueryEvidence(ctx, evidence.EvidenceFilter{
				PolicyIDs: []string{"test-policy"},
				Limit:     1,
			})
			if err != nil || len(rows) == 0 {
				return false
			}
			evidenceID = rows[0].EvidenceID
			signals, err := st.QueryTrustSignals(ctx, evidenceID)
			if err != nil {
				return false
			}
			return len(signals) > 0
		}).WithTimeout(5 * time.Second).WithPolling(200 * time.Millisecond).Should(BeTrue())

		By("Hitting the verification endpoint")
		verifyURL := fmt.Sprintf("%s/api/evidence/%s/verification", apiServer.URL, evidenceID)
		verifyResp, err := http.Get(verifyURL) //nolint:gosec // G107: test server URL
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = verifyResp.Body.Close() }()

		Expect(verifyResp.StatusCode).To(Equal(http.StatusOK))

		var verifyResult struct {
			EvidenceID string                   `json:"evidence_id"`
			Verified   bool                     `json:"verified"`
			Signals    []certify.TrustSignalRow `json:"signals"`
		}
		err = json.NewDecoder(verifyResp.Body).Decode(&verifyResult)
		Expect(err).NotTo(HaveOccurred())

		Expect(verifyResult.EvidenceID).To(Equal(evidenceID))
		Expect(verifyResult.Signals).NotTo(BeEmpty())

		By("Verifying all signals pass")
		for _, s := range verifyResult.Signals {
			GinkgoWriter.Printf("  Signal: layer=%s check=%s result=%s\n", s.Layer, s.CheckName, s.Result)
			Expect(string(s.Result)).To(Equal("pass"))
		}
		Expect(verifyResult.Verified).To(BeTrue())
	})

	It("returns 404 for evidence with no trust signals", func() {
		verifyURL := fmt.Sprintf("%s/api/evidence/%s/verification", apiServer.URL, "nonexistent-id")
		resp, err := http.Get(verifyURL) //nolint:gosec // G107: test server URL
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()

		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
	})
})
