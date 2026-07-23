//go:build acceptance

package acceptance_test

import (
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Publisher", Ordered, func() {
	var (
		publisherToken string
		subjectID      = "publisher-test-subject"
	)

	BeforeAll(func() {
		publisherToken = mintToken("test-publisher", "complytime-gateway", false, false)
		adminToken := mintToken("test-admin", "complytime-locker", true, false)
		registerSubject(adminToken, subjectID, "http://testjwks:8888", "test-publisher")
	})

	Describe("authenticated and trusted", func() {
		var (
			digest   string
			logIndex int64
		)

		It("seals well-formed JSON evidence and returns a job ID", func() {
			artifact := map[string]interface{}{
				"type":      "test-artifact",
				"target":    map[string]string{"id": subjectID},
				"timestamp": time.Now().Format(time.RFC3339),
				"data":      "acceptance test data",
			}
			body, err := json.Marshal(artifact)
			Expect(err).NotTo(HaveOccurred())

			digest, logIndex = ingestAndSeal(publisherToken, subjectID, body, 1)
		})

		It("sealed evidence has a valid digest", func() {
			Expect(digest).NotTo(BeEmpty())
			Expect(len(digest)).To(Equal(64)) // SHA-256 hex
		})

		It("sealed evidence has a non-negative log index", func() {
			Expect(logIndex).To(BeNumerically(">=", 0))
		})

		It("digest is verifiable in the locker", func() {
			serviceToken := lockerServiceToken()
			url := lockerURL(fmt.Sprintf("/ledgers/%s/verify/%s", subjectID, digest))
			resp := authenticatedRequest("GET", url, serviceToken, nil)
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(200))

			var result struct {
				Found bool  `json:"found"`
				Index int64 `json:"index"`
			}
			Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())
			Expect(result.Found).To(BeTrue())
		})

		It("receipt is fetchable by log index", func() {
			serviceToken := lockerServiceToken()
			entry := fetchLockerEntry(serviceToken, subjectID, logIndex)
			Expect(entry).NotTo(BeEmpty())
		})

		It("fetched receipt unwraps to original submitted content", func() {
			serviceToken := lockerServiceToken()
			entry := fetchLockerEntry(serviceToken, subjectID, logIndex)
			content := unwrapReceipt(entry)

			var parsed map[string]interface{}
			Expect(json.Unmarshal(content, &parsed)).To(Succeed())
			Expect(parsed["type"]).To(Equal("test-artifact"))
			Expect(parsed["data"]).To(Equal("acceptance test data"))
		})
	})

	Describe("DSSE envelope", func() {
		It("seals DSSE artifact and returns a receipt", func() {
			dsseEnvelope := map[string]interface{}{
				"payloadType": "application/vnd.in-toto+json",
				"payload":     "eyJ0ZXN0IjogImRzc2UgYWNjZXB0YW5jZSJ9",
				"signatures":  []map[string]string{{"sig": "test-sig"}},
			}
			body, err := json.Marshal(dsseEnvelope)
			Expect(err).NotTo(HaveOccurred())

			req, err := newRequest("POST", gatewayURL("/api/ingest"), body)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer "+publisherToken)
			req.Header.Set("Content-Type", "application/vnd.dsse+json")
			req.Header.Set("X-Subject-ID", subjectID)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(202))

			var result struct {
				JobId string `json:"jobId"`
			}
			Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())
			Expect(result.JobId).NotTo(BeEmpty(), "Gateway should return correlation ID")
		})
	})

	Describe("authenticated but untrusted", func() {
		It("rejects evidence submission with 403", func() {
			untrustedToken := mintToken("untrusted-publisher", "complytime-gateway", false, false)

			artifact := map[string]interface{}{"type": "test", "data": "should be rejected"}
			body, err := json.Marshal(artifact)
			Expect(err).NotTo(HaveOccurred())

			req, err := newRequest("POST", gatewayURL("/api/ingest"), body)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer "+untrustedToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Subject-ID", subjectID)

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(403))
		})
	})

	Describe("unauthenticated", func() {
		It("rejects evidence submission with 401", func() {
			artifact := map[string]interface{}{"type": "test", "data": "no auth"}
			body, err := json.Marshal(artifact)
			Expect(err).NotTo(HaveOccurred())

			req, err := newRequest("POST", gatewayURL("/api/ingest"), body)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Subject-ID", subjectID)
			// No Authorization header

			resp, err := httpClient().Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(401))
		})
	})

	Describe("malformed evidence", func() {
		PIt("rejects evidence that fails schema validation")
	})
})
