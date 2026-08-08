//go:build acceptance

package acceptance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/gomega"
)

func gatewayURL(path string) string {
	return "http://localhost:8090" + path
}

func lockerURL(path string) string {
	return "http://localhost:8081" + path
}

func testjwksURL(path string) string {
	return "http://localhost:8888" + path
}

func testjwksOIDCURL(path string) string {
	return "http://localhost:8889" + path
}

func natsURL() string {
	return "nats://acceptance-test:acceptance-test-password@localhost:4222"
}

func graphURL(path string) string {
	return "http://localhost:8082" + path
}

func waitForGraphMaterialization(subjectID string, timeout time.Duration) {
	Eventually(func() int64 {
		req, err := newRequest("GET", graphURL("/api/subjects/"+subjectID), nil)
		if err != nil {
			return 0
		}
		token := graphServiceToken()
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := httpClient().Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return 0
		}

		var result struct {
			EvidenceCount int64 `json:"evidenceCount"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return 0
		}
		return result.EvidenceCount
	}, timeout, 500*time.Millisecond).Should(BeNumerically(">", 0), "Evidence should be materialized in graph")
}

// mintToken mints a workload publisher token from testjwks (port 8888).
// Use this for publisher identities that will be registered as trusted publishers.
func mintToken(sub, audience string) string {
	reqBody, err := json.Marshal(map[string]interface{}{
		"sub":      sub,
		"audience": []string{audience},
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

// mintOIDCToken mints a token from testjwks-oidc (port 8889), the primary OIDC issuer.
// groups controls group membership; use authn.DefaultAdminGroup or authn.DefaultAuditorGroup.
func mintOIDCToken(sub, audience string, groups []string) string {
	reqBody, err := json.Marshal(map[string]interface{}{
		"sub":      sub,
		"audience": []string{audience},
		"groups":   groups,
	})
	Expect(err).NotTo(HaveOccurred())

	resp, err := http.Post(testjwksOIDCURL("/mint"), "application/json", bytes.NewReader(reqBody))
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

	resp := authenticatedRequest("POST", gatewayURL("/admin/subjects"), adminToken, reqBody)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return // subject already registered from a prior run
	}
	Expect(resp.StatusCode).To(Equal(http.StatusCreated))
}

func ingestAndSeal(token, subjectID string, body []byte, entryIndex int64) (string, int64) {
	// Submit artifact to gateway
	req, err := http.NewRequest("POST", gatewayURL("/api/ingest"), bytes.NewReader(body))
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Subject-ID", subjectID)

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusAccepted))

	// Wait for the receipt to appear in the locker at the expected index.
	// The locker seals asynchronously via NATS — poll the entry endpoint.
	// entryIndex 0 is the registration receipt, so evidence starts at 1.
	serviceToken := lockerServiceToken()
	var digest string

	Eventually(func() bool {
		url := lockerURL(fmt.Sprintf("/ledgers/%s/entry/%d", subjectID, entryIndex))
		fetchResp := authenticatedRequest("GET", url, serviceToken, nil)
		defer fetchResp.Body.Close()

		if fetchResp.StatusCode != http.StatusOK {
			return false
		}

		entryBytes, err := io.ReadAll(fetchResp.Body)
		if err != nil || len(entryBytes) == 0 {
			return false
		}

		h := sha256.Sum256(entryBytes)
		digest = hex.EncodeToString(h[:])
		return true
	}, 30*time.Second, 500*time.Millisecond).Should(BeTrue(), "Receipt should be sealed in locker")

	return digest, entryIndex
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
	return mintOIDCToken("acceptance-test-consumer", "complytime-locker", []string{"complytime-auditor"})
}

func graphServiceToken() string {
	return mintOIDCToken("acceptance-test-consumer", "complytime-graph", []string{"complytime-auditor"})
}

func newRequest(method, url string, body []byte) (*http.Request, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	return http.NewRequest(method, url, bodyReader)
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
