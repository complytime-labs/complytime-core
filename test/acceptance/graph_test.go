//go:build acceptance

package acceptance_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("graph service", Ordered, Label("graph"), func() {
	var (
		publisherToken string
		subjectID      = "graph-acceptance-test"
	)

	BeforeAll(func() {
		By("registering graph test subject")
		adminToken := mintToken("graph-test-admin", "complytime-locker", true, false)
		registerSubject(adminToken, subjectID, "http://testjwks:8888", "graph-test-publisher")

		By("minting publisher token")
		publisherToken = mintToken("graph-test-publisher", "complytime-gateway", false, false)
	})

	Describe("end-to-end graph materialization", func() {
		var catalogDigest string

		It("ingests a ControlCatalog via the gateway", func() {
			catalog := map[string]interface{}{
				"metadata": map[string]interface{}{
					"type":           "ControlCatalog",
					"id":             "graph-test-catalog",
					"version":        "1.0.0",
					"description":    "Acceptance test control catalog",
					"gemara-version": "0.1.0",
					"author": map[string]interface{}{
						"id":   "acceptance-tester",
						"name": "Acceptance Tester",
						"type": "Software Assisted",
					},
				},
				"title": "Graph Test Catalog",
				"groups": []map[string]interface{}{
					{
						"id":          "access-control",
						"title":       "Access Control",
						"description": "Controls for access management",
					},
				},
				"controls": []map[string]interface{}{
					{
						"id":        "AC-1",
						"title":     "Access Control Policy",
						"group":     "access-control",
						"objective": "Establish access control requirements",
						"assessment-requirements": []map[string]interface{}{
							{
								"id":            "AC-1.1",
								"text":          "Verify access control policy exists",
								"applicability": []string{"all"},
							},
						},
					},
					{
						"id":        "AC-2",
						"title":     "Account Management",
						"group":     "access-control",
						"objective": "Manage system accounts",
						"assessment-requirements": []map[string]interface{}{
							{
								"id":            "AC-2.1",
								"text":          "Verify account provisioning process",
								"applicability": []string{"all"},
							},
						},
					},
				},
			}

			body, err := json.Marshal(catalog)
			Expect(err).NotTo(HaveOccurred())

			// Use index 4 (Publisher=1, Consumer NATS=2, Consumer verify=3)
			catalogDigest, _ = ingestAndSeal(publisherToken, subjectID, body, 4)
			Expect(catalogDigest).NotTo(BeEmpty())
		})

		It("materializes the catalog in the graph", func() {
			waitForGraphMaterialization(subjectID, 30*time.Second)
		})

		It("returns subject summary with artifact type counts", func() {
			req, err := newRequest("GET", graphURL("/api/subjects/"+subjectID), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			var result struct {
				ID            string `json:"id"`
				EvidenceCount int64  `json:"evidenceCount"`
				ArtifactTypes map[string]struct {
					Count       int64     `json:"count"`
					LastUpdated time.Time `json:"lastUpdated"`
				} `json:"artifactTypes"`
				PublisherCount int `json:"publisherCount"`
			}
			Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())

			Expect(result.ID).To(Equal(subjectID))
			Expect(result.EvidenceCount).To(BeNumerically(">", 0))
			Expect(result.ArtifactTypes).To(HaveKey("ControlCatalog"))
			Expect(result.ArtifactTypes["ControlCatalog"].Count).To(BeNumerically(">=", 1))
			Expect(result.PublisherCount).To(BeNumerically(">=", 1))
		})

		It("returns threat model with controls from the catalog", func() {
			req, err := newRequest("GET", graphURL("/api/subjects/"+subjectID+"/threat-model"), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			var result struct {
				SubjectID    string `json:"subjectId"`
				Capabilities []struct {
					ID     string   `json:"id"`
					Title  string   `json:"title"`
					Source struct{} `json:"source"`
				} `json:"capabilities"`
				Threats []struct {
					ID     string   `json:"id"`
					Title  string   `json:"title"`
					Source struct{} `json:"source"`
				} `json:"threats"`
				Controls []struct {
					ID                     string   `json:"id"`
					Title                  string   `json:"title"`
					Objective              string   `json:"objective"`
					AssessmentRequirements []string `json:"assessmentRequirements"`
					Source                 struct {
						LogIndex  int64     `json:"logIndex"`
						Digest    string    `json:"digest"`
						Publisher struct{}  `json:"publisher"`
						Sealed    time.Time `json:"sealed"`
					} `json:"source"`
				} `json:"controls"`
				Vectors []struct{} `json:"vectors"`
			}
			Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())

			Expect(result.SubjectID).To(Equal(subjectID))
			Expect(result.Controls).NotTo(BeEmpty(), "Threat model should include controls")

			foundAC1 := false
			foundAC2 := false
			for _, ctrl := range result.Controls {
				if ctrl.ID == "AC-1" {
					foundAC1 = true
					Expect(ctrl.Title).To(Equal("Access Control Policy"))
					Expect(ctrl.Objective).To(Equal("Establish access control requirements"))
					Expect(ctrl.AssessmentRequirements).To(ContainElement(ContainSubstring("Verify access control policy exists")))
					Expect(ctrl.Source.LogIndex).To(BeNumerically(">", 0))
					Expect(ctrl.Source.Digest).NotTo(BeEmpty())
				}
				if ctrl.ID == "AC-2" {
					foundAC2 = true
					Expect(ctrl.Title).To(Equal("Account Management"))
				}
			}
			Expect(foundAC1).To(BeTrue(), "AC-1 should be in threat model")
			Expect(foundAC2).To(BeTrue(), "AC-2 should be in threat model")
		})

		It("returns coverage for the catalog", func() {
			req, err := newRequest("GET", graphURL(fmt.Sprintf("/api/subjects/%s/coverage?catalog=graph-test-catalog", subjectID)), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			var result struct {
				SubjectID   string `json:"subjectId"`
				Catalog     string `json:"catalog"`
				CatalogType string `json:"catalogType"`
				Covered     int    `json:"covered"`
				Total       int    `json:"total"`
				Controls    []struct {
					ID             string    `json:"id"`
					Title          string    `json:"title"`
					Status         string    `json:"status"`
					LatestEvidence time.Time `json:"latestEvidence,omitempty"`
				} `json:"controls"`
			}
			Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())

			Expect(result.SubjectID).To(Equal(subjectID))
			Expect(result.Catalog).To(Equal("graph-test-catalog"))
			Expect(result.CatalogType).To(Equal("ControlCatalog"))
			Expect(result.Total).To(BeNumerically(">=", 2))
			Expect(result.Controls).NotTo(BeEmpty())
		})

		It("returns paginated evidence with filtering", func() {
			req, err := newRequest("GET", graphURL(fmt.Sprintf("/api/subjects/%s/evidence?type=ControlCatalog&limit=10", subjectID)), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			var result struct {
				SubjectID string `json:"subjectId"`
				Evidence  []struct {
					LogIndex     int64     `json:"logIndex"`
					Digest       string    `json:"digest"`
					ArtifactType string    `json:"artifactType"`
					Status       string    `json:"status"`
					Publisher    struct{}  `json:"publisher"`
					Sealed       time.Time `json:"sealed"`
				} `json:"evidence"`
				NextCursor string `json:"nextCursor,omitempty"`
			}
			Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())

			Expect(result.SubjectID).To(Equal(subjectID))
			Expect(result.Evidence).NotTo(BeEmpty(), "Should return evidence items")

			for _, item := range result.Evidence {
				Expect(item.ArtifactType).To(Equal("ControlCatalog"), "Filter should apply")
				Expect(item.LogIndex).To(BeNumerically(">", 0))
				Expect(item.Digest).NotTo(BeEmpty())
				Expect(item.Status).NotTo(BeEmpty())
			}
		})
	})

	Describe("error handling", func() {
		It("returns 404 for unknown subject", func() {
			req, err := newRequest("GET", graphURL("/api/subjects/nonexistent-subject/threat-model"), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		})

		It("returns 400 for coverage without catalog parameter", func() {
			req, err := newRequest("GET", graphURL("/api/subjects/"+subjectID+"/coverage"), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		})

		It("returns 404 for coverage with unknown catalog", func() {
			req, err := newRequest("GET", graphURL(fmt.Sprintf("/api/subjects/%s/coverage?catalog=nonexistent", subjectID)), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		})
	})

	Describe("list subjects", func() {
		It("returns all subjects with summaries", func() {
			req, err := newRequest("GET", graphURL("/api/subjects"), nil)
			Expect(err).NotTo(HaveOccurred())
			token := graphServiceToken()
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			var result struct {
				Subjects []struct {
					ID            string `json:"id"`
					EvidenceCount int64  `json:"evidenceCount"`
					ArtifactTypes map[string]struct {
						Count       int64     `json:"count"`
						LastUpdated time.Time `json:"lastUpdated"`
					} `json:"artifactTypes"`
					PublisherCount int `json:"publisherCount"`
				} `json:"subjects"`
			}
			Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())
			Expect(result.Subjects).NotTo(BeEmpty(), "Should return at least one subject")

			foundSubject := false
			for _, s := range result.Subjects {
				if s.ID == subjectID {
					foundSubject = true
					Expect(s.EvidenceCount).To(BeNumerically(">", 0))
				}
			}
			Expect(foundSubject).To(BeTrue(), "Should include graph test subject")
		})
	})
})
