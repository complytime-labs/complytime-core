// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/postgres"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

var _ = Describe("Policy Enrollment", func() {
	var (
		ctx           context.Context
		pgClient      *postgres.Client
		st            *store.Store
		tracker       *store.IngestTracker
		ingestServer  *httptest.Server
		jwtCtx        *jwtTestContext
		natsURL       string
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

		st = store.New(pgClient.Pool())

		By("Starting NATS server")
		natsServer := startTestNATSServer(GinkgoT())
		natsURL = natsServer.ClientURL()

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

		setupJetStreamWorker(GinkgoT(), workerCtx, bus, stores, bus, tracker, tesseraClient)

		By("Starting HTTP server")
		ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
		ingestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ingestHandler.ServeHTTP(w, r)
		}))
		DeferCleanup(ingestServer.Close)
	})

	Context("target registration", func() {
		It("stores target with correct dimensions in PostgreSQL", func() {
			By("Subscribing to target registration events")
			eventBus := connectTestNATS(GinkgoT(), natsURL)
			eventCh := make(chan events.TargetRegisteredEvent, 1)
			_, err := eventBus.SubscribeTargetRegistered(func(evt events.TargetRegisteredEvent) {
				eventCh <- evt
			})
			Expect(err).NotTo(HaveOccurred())

			By("Loading TargetRegistration fixture")
			regYAML, err := os.ReadFile("testdata/target_registration_sample.yaml")
			Expect(err).NotTo(HaveOccurred())

			By("Submitting TargetRegistration")
			testSubject := "repo:org/infrastructure:ref:refs/heads/main"
			token := jwtCtx.generateTestJWT(GinkgoT(), testSubject)

			resp, result := submitEvidence(GinkgoT(), ingestServer.URL, token, regYAML)
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted), "Expected 202 Accepted")

			jobID := result["job_id"].(string)
			logIndex := uint64(result["log_index"].(float64))
			GinkgoWriter.Printf("Submitted TargetRegistration: job_id=%s, log_index=%d\n", jobID, logIndex)

			By("Waiting for worker to process")
			waitForJob(tracker, jobID)

			By("Verifying Tessera contains entry")
			tesseraEntry, err := tesseraClient.Read(ctx, logIndex)
			Expect(err).NotTo(HaveOccurred())
			Expect(tesseraEntry).NotTo(BeEmpty())
			Expect(string(tesseraEntry)).To(ContainSubstring("TargetRegistration"))

			By("Verifying target stored in PostgreSQL with correct dimensions")
			target, err := st.GetLatestTarget(ctx, "prod-cluster", time.Now())
			Expect(err).NotTo(HaveOccurred())
			Expect(target).NotTo(BeNil(), "Target not found in database")

			Expect(target.TargetID).To(Equal("prod-cluster"))
			Expect(target.TargetName).To(Equal("Production Kubernetes Cluster"))
			Expect(target.TargetType).To(Equal("kubernetes-cluster"))
			Expect(target.Technologies).To(Equal([]string{"kubernetes", "postgresql"}))
			Expect(target.Geopolitical).To(Equal([]string{"EU"}))
			Expect(target.Sensitivity).To(Equal([]string{"confidential"}))
			Expect(target.RegisteredBy).To(Equal(testSubject))
			Expect(target.TesseraLogIndex).To(Equal(logIndex))

			By("Verifying NATS event received")
			Eventually(eventCh).WithTimeout(5 * time.Second).Should(Receive(SatisfyAll(
				WithTransform(func(e events.TargetRegisteredEvent) string { return e.TargetID }, Equal("prod-cluster")),
				WithTransform(func(e events.TargetRegisteredEvent) uint64 { return e.LogIndex }, Equal(logIndex)),
				WithTransform(func(e events.TargetRegisteredEvent) string { return e.RegisteredBy }, Equal(testSubject)),
			)))
		})

		It("rejects TargetRegistration with missing target.id", func() {
			By("Submitting malformed TargetRegistration")
			malformedYAML := []byte(`metadata:
  type: TargetRegistration
  id: bad-reg
  date: "2026-05-26T10:00:00Z"
target:
  name: Missing ID Target
dimensions:
  technologies: [kubernetes]
`)

			token := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/test:ref:refs/heads/main")
			resp, result := submitEvidence(GinkgoT(), ingestServer.URL, token, malformedYAML)
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted))

			jobID := result["job_id"].(string)

			By("Waiting for worker to fail the job")
			Eventually(func() string {
				status := tracker.Get(jobID)
				if status == nil {
					return ""
				}
				return status.Status
			}).WithTimeout(10 * time.Second).WithPolling(50 * time.Millisecond).Should(Equal("failed"))

			status := tracker.Get(jobID)
			Expect(status).NotTo(BeNil())
			Expect(status.Error).To(ContainSubstring("missing target.id"))
			GinkgoWriter.Printf("Malformed TargetRegistration correctly rejected: %s\n", status.Error)
		})
	})

	Context("policy discovery", func() {
		It("matches policies by dimension overlap", func() {
			By("Registering target")
			regYAML, err := os.ReadFile("testdata/target_registration_sample.yaml")
			Expect(err).NotTo(HaveOccurred())

			token := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/infrastructure:ref:refs/heads/main")
			resp, result := submitEvidence(GinkgoT(), ingestServer.URL, token, regYAML)
			Expect(resp.StatusCode).To(Equal(http.StatusAccepted))
			waitForJob(tracker, result["job_id"].(string))
			GinkgoWriter.Printf("Registered target prod-cluster\n")

			By("Ingesting policy through /api/ingest")
			policyYAML, err := os.ReadFile("testdata/policy_sample.yaml")
			Expect(err).NotTo(HaveOccurred())

			policyToken := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/policies:ref:refs/heads/main")
			policyHTTPResp, policyResult := submitEvidence(GinkgoT(), ingestServer.URL, policyToken, policyYAML)
			Expect(policyHTTPResp.StatusCode).To(Equal(http.StatusAccepted))

			policyJobID := policyResult["job_id"].(string)
			policyLogIndex := uint64(policyResult["log_index"].(float64))
			waitForJob(tracker, policyJobID)
			GinkgoWriter.Printf("Ingested policy via /api/ingest: job_id=%s, log_index=%d\n", policyJobID, policyLogIndex)

			By("Verifying tessera_log_index propagated to the policies table")
			var storedLogIndex *uint64
			err = pgClient.Pool().QueryRow(ctx,
				`SELECT tessera_log_index FROM policies WHERE policy_id = $1`,
				"infra-baseline",
			).Scan(&storedLogIndex)
			Expect(err).NotTo(HaveOccurred())
			Expect(storedLogIndex).NotTo(BeNil(), "tessera_log_index should be set on ingested policy")
			Expect(*storedLogIndex).To(Equal(policyLogIndex), "tessera_log_index should match ingest response")

			By("Setting up API server")
			stores := store.Stores{
				Evidence:         st,
				Policies:         st,
				Controls:         st,
				Mappings:         st,
				Targets:          st,
				PolicyDimensions: st,
			}
			apiServer := setupAPIServer(stores)
			DeferCleanup(apiServer.Close)

			By("Querying for applicable policies")
			queryURL := fmt.Sprintf("%s/api/policies/discover?target_id=prod-cluster&timestamp=2026-05-26T10:00:00Z", apiServer.URL)
			queryResp, err := http.Get(queryURL) //nolint:gosec // G107: test server URL
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = queryResp.Body.Close() }()
			Expect(queryResp.StatusCode).To(Equal(http.StatusOK))

			var policyResp store.PolicyQueryResponse
			err = json.NewDecoder(queryResp.Body).Decode(&policyResp)
			Expect(err).NotTo(HaveOccurred())

			Expect(policyResp.Target.ID).To(Equal("prod-cluster"))
			Expect(policyResp.Target.Name).To(Equal("Production Kubernetes Cluster"))

			Expect(policyResp.ApplicablePolicies).To(HaveLen(1), "Expected 1 applicable policy")
			Expect(policyResp.ApplicablePolicies[0].PolicyID).To(Equal("infra-baseline"))
			Expect(policyResp.ApplicablePolicies[0].LogIndex).To(Equal(policyLogIndex))

			By("Querying with non-existent target")
			queryURL = fmt.Sprintf("%s/api/policies/discover?target_id=nonexistent&timestamp=2026-05-26T10:00:00Z", apiServer.URL)
			queryResp2, err := http.Get(queryURL) //nolint:gosec // G107: test server URL
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = queryResp2.Body.Close() }()
			Expect(queryResp2.StatusCode).To(Equal(http.StatusNotFound))
		})

		It("extracts dimensions from ingested policy YAML", func() {
			By("Ingesting policy through /api/ingest")
			policyYAML, err := os.ReadFile("testdata/policy_sample.yaml")
			Expect(err).NotTo(HaveOccurred())

			policyToken := jwtCtx.generateTestJWT(GinkgoT(), "repo:org/policies:ref:refs/heads/main")
			policyResp, policyResult := submitEvidence(GinkgoT(), ingestServer.URL, policyToken, policyYAML)
			Expect(policyResp.StatusCode).To(Equal(http.StatusAccepted))

			policyJobID := policyResult["job_id"].(string)
			waitForJob(tracker, policyJobID)

			By("Querying stored policy dimensions")
			var technologies, geopolitical []string
			var evalStart, evalEnd *time.Time
			err = pgClient.Pool().QueryRow(ctx,
				`SELECT technologies, geopolitical, evaluation_timeline_start, evaluation_timeline_end
				 FROM policies WHERE policy_id = $1`, "infra-baseline",
			).Scan(&technologies, &geopolitical, &evalStart, &evalEnd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying technology dimensions")
			Expect(technologies).To(ContainElement("kubernetes"),
				"Policy scope.in.technologies should contain kubernetes")

			By("Verifying geopolitical dimensions")
			Expect(geopolitical).To(ContainElement("EU"),
				"Policy scope.in.geopolitical should contain EU")

			By("Verifying evaluation timeline")
			Expect(evalStart).NotTo(BeNil(), "evaluation_timeline_start should be set")
			Expect(evalEnd).NotTo(BeNil(), "evaluation_timeline_end should be set")

			expectedStart, _ := time.Parse(time.RFC3339, "2026-04-01T00:00:00Z")
			expectedEnd, _ := time.Parse(time.RFC3339, "2026-06-30T00:00:00Z")
			Expect(evalStart.UTC()).To(Equal(expectedStart.UTC()),
				"evaluation_timeline_start should match policy YAML")
			Expect(evalEnd.UTC()).To(Equal(expectedEnd.UTC()),
				"evaluation_timeline_end should match policy YAML")

			GinkgoWriter.Printf("Policy dimensions verified:\n")
			GinkgoWriter.Printf("  technologies: %v\n", technologies)
			GinkgoWriter.Printf("  geopolitical: %v\n", geopolitical)
			GinkgoWriter.Printf("  eval_start: %v\n", evalStart)
			GinkgoWriter.Printf("  eval_end: %v\n", evalEnd)
		})
	})

	Context("target registration versioning", func() {
		It("returns correct version for each timestamp", func() {
			By("Registering target at T1 with technologies=[kubernetes]")
			t1 := time.Now().UTC().Add(-2 * time.Hour)
			err := st.InsertTarget(ctx, store.TargetRow{
				TargetID:        "versioned-target",
				TesseraLogIndex: 100,
				TargetName:      "Versioned Target v1",
				TargetType:      "kubernetes-cluster",
				Technologies:    []string{"kubernetes"},
				Geopolitical:    []string{"US"},
				Sensitivity:     []string{},
				Users:           []string{},
				Groups:          []string{},
				RegisteredAt:    t1,
				RegisteredBy:    "repo:org/infra:ref:refs/heads/main",
			})
			Expect(err).NotTo(HaveOccurred())

			By("Registering target at T2 with technologies=[kubernetes, postgresql]")
			t2 := time.Now().UTC().Add(-1 * time.Hour)
			err = st.InsertTarget(ctx, store.TargetRow{
				TargetID:        "versioned-target",
				TesseraLogIndex: 200,
				TargetName:      "Versioned Target v2",
				TargetType:      "kubernetes-cluster",
				Technologies:    []string{"kubernetes", "postgresql"},
				Geopolitical:    []string{"US", "EU"},
				Sensitivity:     []string{"confidential"},
				Users:           []string{},
				Groups:          []string{},
				RegisteredAt:    t2,
				RegisteredBy:    "repo:org/infra:ref:refs/heads/main",
			})
			Expect(err).NotTo(HaveOccurred())

			By("Querying target at T1 should return v1")
			// Query just after T1
			queryTime1 := t1.Add(1 * time.Second)
			target1, err := st.GetLatestTarget(ctx, "versioned-target", queryTime1)
			Expect(err).NotTo(HaveOccurred())
			Expect(target1).NotTo(BeNil(), "Target should exist at T1")
			Expect(target1.TargetName).To(Equal("Versioned Target v1"))
			Expect(target1.Technologies).To(Equal([]string{"kubernetes"}),
				"At T1, target should have only kubernetes")
			Expect(target1.TesseraLogIndex).To(Equal(uint64(100)))

			GinkgoWriter.Printf("Target at T1: name=%s technologies=%v\n",
				target1.TargetName, target1.Technologies)

			By("Querying target at T2 should return v2")
			// Query just after T2
			queryTime2 := t2.Add(1 * time.Second)
			target2, err := st.GetLatestTarget(ctx, "versioned-target", queryTime2)
			Expect(err).NotTo(HaveOccurred())
			Expect(target2).NotTo(BeNil(), "Target should exist at T2")
			Expect(target2.TargetName).To(Equal("Versioned Target v2"))
			Expect(target2.Technologies).To(Equal([]string{"kubernetes", "postgresql"}),
				"At T2, target should have kubernetes and postgresql")
			Expect(target2.Geopolitical).To(Equal([]string{"US", "EU"}),
				"At T2, target should have US and EU")
			Expect(target2.Sensitivity).To(Equal([]string{"confidential"}),
				"At T2, target should have confidential sensitivity")
			Expect(target2.TesseraLogIndex).To(Equal(uint64(200)))

			GinkgoWriter.Printf("Target at T2: name=%s technologies=%v\n",
				target2.TargetName, target2.Technologies)

			By("Querying target before T1 should return nil")
			targetBefore, err := st.GetLatestTarget(ctx, "versioned-target", t1.Add(-1*time.Second))
			Expect(err).NotTo(HaveOccurred())
			Expect(targetBefore).To(BeNil(),
				"Target should not exist before first registration")

			By("Querying target at current time should return v2 (latest)")
			targetNow, err := st.GetLatestTarget(ctx, "versioned-target", time.Now().UTC())
			Expect(err).NotTo(HaveOccurred())
			Expect(targetNow).NotTo(BeNil())
			Expect(targetNow.TargetName).To(Equal("Versioned Target v2"),
				"Current query should return latest version")
		})
	})
})

// setupAPIServer creates an Echo server with the policy discovery routes
func setupAPIServer(stores store.Stores) *httptest.Server {
	e := newTestEchoServer()
	apiGroup := e.Group("/api")
	store.Register(apiGroup, stores)
	return httptest.NewServer(e)
}
