//go:build acceptance

package acceptance_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/gomega"
)

func gatewayURL(path string) string {
	return "http://localhost:8080" + path
}

func lockerURL(path string) string {
	return "http://localhost:8081" + path
}

func testjwksURL(path string) string {
	return "http://localhost:8888" + path
}

func natsURL() string {
	return "nats://localhost:4222"
}

func mintToken(sub, audience string, admin, service bool) string {
	reqBody, err := json.Marshal(map[string]interface{}{
		"sub":      sub,
		"audience": []string{audience},
		"admin":    admin,
		"service":  service,
	})
	Expect(err).NotTo(HaveOccurred())

	resp, err := http.Post(testjwksURL("/mint"), "application/json", bytes.NewReader(reqBody))
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	var result struct {
		Token string `json:"token"`
	}
	Expect(json.NewDecoder(resp.Body).Decode(&result)).To(Succeed())
	return result.Token
}

func authenticatedRequest(method, url, token string, body []byte) *http.Response {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred())
	return resp
}

func registerSubject(adminToken, subjectID, issuer, sub string) {
	reqBody, err := json.Marshal(map[string]interface{}{
		"subjectId": subjectID,
		"trustedPublishers": []map[string]string{
			{"issuer": issuer, "sub": sub},
		},
	})
	Expect(err).NotTo(HaveOccurred())

	resp := authenticatedRequest("POST", gatewayURL("/api/admin/subjects"), adminToken, reqBody)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return // subject already registered from a prior run
	}
	Expect(resp.StatusCode).To(Equal(http.StatusCreated))
}

func ingestAndSeal(token, subjectID string, body []byte) (string, int64) {
	req, err := http.NewRequest("POST", gatewayURL("/api/ingest"), bytes.NewReader(body))
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Subject-ID", subjectID)

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusAccepted))

	var ingestResult struct {
		JobId string `json:"jobId"`
	}
	Expect(json.NewDecoder(resp.Body).Decode(&ingestResult)).To(Succeed())

	// Poll until sealed
	var digest string
	var logIndex int64

	Eventually(func() string {
		statusResp := authenticatedRequest("GET",
			gatewayURL("/api/ingest/jobs/"+ingestResult.JobId), token, nil)
		defer statusResp.Body.Close()
		Expect(statusResp.StatusCode).To(Equal(http.StatusOK))

		var status struct {
			Status   string  `json:"status"`
			Digest   *string `json:"digest"`
			LogIndex *int64  `json:"logIndex"`
		}
		Expect(json.NewDecoder(statusResp.Body).Decode(&status)).To(Succeed())

		if status.Status == "sealed" {
			Expect(status.Digest).NotTo(BeNil())
			Expect(status.LogIndex).NotTo(BeNil())
			digest = *status.Digest
			logIndex = *status.LogIndex
		}
		return status.Status
	}, 30*time.Second, 500*time.Millisecond).Should(Equal("sealed"))

	return digest, logIndex
}

func fetchLockerEntry(serviceToken, subjectID string, index int64) []byte {
	url := lockerURL(fmt.Sprintf("/ledgers/%s/entry/%d", subjectID, index))
	resp := authenticatedRequest("GET", url, serviceToken, nil)
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	data, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	return data
}

func unwrapReceipt(entry []byte) []byte {
	var raw map[string]interface{}
	Expect(json.Unmarshal(entry, &raw)).To(Succeed())

	predicateType, ok := raw["predicate_type"].(string)
	Expect(ok).To(BeTrue(), "entry should have predicate_type")
	Expect(predicateType).To(Equal("gemara-receipt/v1"))

	predicate, ok := raw["predicate"].(map[string]interface{})
	Expect(ok).To(BeTrue())

	encodedContent, ok := predicate["content"].(string)
	Expect(ok).To(BeTrue())

	content, err := base64.StdEncoding.DecodeString(encodedContent)
	Expect(err).NotTo(HaveOccurred())
	return content
}

func lockerServiceToken() string {
	return mintToken("acceptance-test-consumer", "complytime-locker", false, true)
}
