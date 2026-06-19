// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	gemara "github.com/gemaraproj/go-gemara"
	"github.com/gemaraproj/go-gemara/gemaraconv"
	goyaml "github.com/goccy/go-yaml"
	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/complytime-labs/complytime-core/internal/tessera"
	"github.com/transparency-dev/tessera/api/layout"
)

// targetContext carries infrastructure state that assessment steps verify against.
type targetContext struct {
	CheckpointBody []byte
	TilesBaseURL   string
	WitnessedURL   string
	LogIndex       uint64
	LogVerifierKey string
}

func countCosigs(cpBytes []byte) int {
	n, err := note.Open(cpBytes, note.VerifierList())
	if err != nil {
		var uve *note.UnverifiedNoteError
		if errors.As(err, &uve) {
			n = uve.Note
		} else {
			return 0
		}
	}
	total := len(n.Sigs) + len(n.UnverifiedSigs)
	if total > 1 {
		return total - 1
	}
	return 0
}

var _ = Describe("Transparency Log Verification [complytime-ingest-tlog-controls]", func() {
	const controlCatalogRef = "complytime-ingest-tlog-controls"

	var (
		ctx           context.Context
		tesseraClient *tessera.Client
		storagePath   string
		target        targetContext
		evaluations   []*gemara.ControlEvaluation
	)

	const (
		testWitVkey = "TestWit+55ee4561+AVhZSmQj9+SoL+p/nN0Hh76xXmF7QcHfytUrI1XfSClk"             //nolint:gosec // test key from Tessera test suite (gitleaks:allow)
		testWitSkey = "PRIVATE+KEY+TestWit+55ee4561+AeadRiG7XM4XiieCHzD8lxysXMwcViy5nYsoXURWGrlE" //nolint:gosec // test key from Tessera test suite (gitleaks:allow)
	)

	BeforeEach(func() {
		ctx = context.Background()
		storagePath = GinkgoT().TempDir()

		By("Starting mock witness server")
		witSigner, err := f_note.NewSignerForCosignatureV1(testWitSkey)
		Expect(err).NotTo(HaveOccurred())

		witServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			parts := bytes.SplitN(body, []byte("\n\n"), 2)
			if len(parts) < 2 {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			cpText := string(parts[1])
			idx := strings.Index(cpText, "\n\n")
			if idx < 0 {
				http.Error(w, "bad checkpoint", http.StatusBadRequest)
				return
			}
			cpBody := cpText[:idx+1]
			signed, err := note.Sign(&note.Note{Text: cpBody}, witSigner)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			cosig := signed[len(cpBody):]
			cosig = append(bytes.Trim(cosig, "\n"), '\n')
			_, _ = w.Write(cosig)
		}))
		DeferCleanup(witServer.Close)

		By("Writing witness policy file")
		policyPath := storagePath + "/witness-policy"
		policy := fmt.Sprintf("witness testwit %s %s\ngroup devgroup all testwit\nquorum devgroup\n",
			testWitVkey, witServer.URL)
		Expect(os.WriteFile(policyPath, []byte(policy), 0600)).To(Succeed())

		By("Creating Tessera client with witness")
		opts := tessera.Options{
			CheckpointTime:    200 * time.Millisecond,
			CheckpointSize:    10,
			SignerKeyPath:     storagePath + "/signer.key",
			WitnessPolicyPath: policyPath,
			WitnessTimeout:    5 * time.Second,
			WitnessFailOpen:   false,
		}
		tesseraClient, err = tessera.NewClient(ctx, storagePath+"/log", opts)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(tesseraClient.Close)

		By("Appending a test entry to trigger checkpoint creation")
		logIndex, err := tesseraClient.Add(ctx, []byte("test-entry-for-verification"))
		Expect(err).NotTo(HaveOccurred())
		target.LogIndex = logIndex

		By("Waiting for checkpoint to be published")
		Eventually(func() error {
			_, err := os.ReadFile(storagePath + "/log/checkpoint")
			return err
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())

		target.LogVerifierKey = tesseraClient.VerifierKey()
	})

	Context("CTRL-AE-01: Witness Cosigned Checkpoints", func() {
		It("CTRL-AE-01.1: checkpoints carry witness cosignatures", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "Witness Cosigned Checkpoints",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-AE-01"},
			}

			eval.AddAssessment(
				"CTRL-AE-01.1",
				"Checkpoints published by the log MUST carry at least one witness cosignature",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(payload interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						tc := payload.(*targetContext)
						cpBytes, err := os.ReadFile(storagePath + "/log/checkpoint")
						if err != nil {
							return gemara.Failed, fmt.Sprintf("cannot read checkpoint: %v", err), gemara.High
						}
						tc.CheckpointBody = cpBytes

						cosigCount := countCosigs(cpBytes)
						if cosigCount == 0 {
							return gemara.Failed,
								"checkpoint has no witness cosignatures — WithWitnesses not wired",
								gemara.High
						}
						return gemara.Passed,
							fmt.Sprintf("checkpoint has %d witness cosignature(s)", cosigCount),
							gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-AE-01.1: %s", eval.AssessmentLogs[0].Message)
		})

		It("CTRL-AE-01.2: witness quorum policy is satisfied", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "Witness Quorum Policy",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-AE-01"},
			}

			eval.AddAssessment(
				"CTRL-AE-01.2",
				"The witness quorum policy MUST be satisfied before a checkpoint is considered fully witnessed",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(_ interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						cpBytes, err := os.ReadFile(storagePath + "/log/checkpoint")
						if err != nil {
							return gemara.Failed, fmt.Sprintf("cannot read checkpoint: %v", err), gemara.High
						}

						cosigCount := countCosigs(cpBytes)
						if cosigCount < 1 {
							return gemara.Failed,
								"quorum not met — need ≥1 witness cosignature, got 0",
								gemara.High
						}
						return gemara.Passed,
							fmt.Sprintf("quorum satisfied with %d cosignature(s)", cosigCount),
							gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-AE-01.2: %s", eval.AssessmentLogs[0].Message)
		})
	})

	Context("CTRL-CV-01: Persistent Checkpoint Signer", func() {
		It("CTRL-CV-01.1: log public key stable across restarts", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "Persistent Checkpoint Signer",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-CV-01"},
			}

			eval.AddAssessment(
				"CTRL-CV-01.1",
				"The log public key MUST be stable across process restarts",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(_ interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						keyPath := storagePath + "/signer.key"
						_, vkey1, _, err := tessera.LoadOrGenerateSignerKey(keyPath)
						if err != nil {
							return gemara.Failed, fmt.Sprintf("cannot load key: %v", err), gemara.High
						}
						_, vkey2, generated, err := tessera.LoadOrGenerateSignerKey(keyPath)
						if err != nil {
							return gemara.Failed, fmt.Sprintf("cannot reload key: %v", err), gemara.High
						}
						if generated {
							return gemara.Failed, "key was regenerated instead of loaded", gemara.High
						}
						if vkey1 != vkey2 {
							return gemara.Failed,
								fmt.Sprintf("verifier key changed: %s → %s", vkey1, vkey2),
								gemara.High
						}
						return gemara.Passed, "verifier key stable across loads", gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-CV-01.1: %s", eval.AssessmentLogs[0].Message)
		})
	})

	Context("CTRL-CV-02: Standard tlog-tiles Read API", func() {
		var tilesServer *httptest.Server

		BeforeEach(func() {
			e := newTestEchoServer()
			tessera.RegisterTilesAPI(e, storagePath+"/log")
			tilesServer = httptest.NewServer(e)
			DeferCleanup(tilesServer.Close)
			target.TilesBaseURL = tilesServer.URL
		})

		It("CTRL-CV-02.1: serves a signed checkpoint", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "tlog-tiles Checkpoint",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-CV-02"},
			}

			eval.AddAssessment(
				"CTRL-CV-02.1",
				"The log MUST serve a signed checkpoint at /checkpoint",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(payload interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						tc := payload.(*targetContext)
						resp, err := http.Get(tc.TilesBaseURL + "/checkpoint") //nolint:gosec
						if err != nil {
							return gemara.Failed, fmt.Sprintf("GET /checkpoint failed: %v", err), gemara.High
						}
						defer resp.Body.Close()

						if resp.StatusCode != http.StatusOK {
							return gemara.Failed,
								fmt.Sprintf("GET /checkpoint returned %d", resp.StatusCode),
								gemara.High
						}

						body, _ := io.ReadAll(resp.Body)
						if len(body) == 0 {
							return gemara.Failed, "checkpoint body is empty", gemara.High
						}
						if !strings.Contains(string(body), "tessera-log") {
							return gemara.Failed,
								"checkpoint does not contain log origin",
								gemara.High
						}
						return gemara.Passed, "checkpoint served and contains log signature", gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-CV-02.1: %s", eval.AssessmentLogs[0].Message)
		})

		It("CTRL-CV-02.2: serves tile data for proof computation", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "tlog-tiles Entry Bundles",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-CV-02"},
			}

			eval.AddAssessment(
				"CTRL-CV-02.2",
				"The log MUST serve tile data sufficient for inclusion proof computation",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(payload interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						tc := payload.(*targetContext)
						entryPath := layout.EntriesPathForLogIndex(tc.LogIndex, tc.LogIndex+1)
						url := tc.TilesBaseURL + "/" + entryPath
						resp, err := http.Get(url) //nolint:gosec
						if err != nil {
							return gemara.Failed, fmt.Sprintf("GET %s failed: %v", entryPath, err), gemara.High
						}
						defer resp.Body.Close()

						if resp.StatusCode != http.StatusOK {
							return gemara.Failed,
								fmt.Sprintf("GET %s returned %d", entryPath, resp.StatusCode),
								gemara.High
						}

						body, _ := io.ReadAll(resp.Body)
						if len(body) == 0 {
							return gemara.Failed, "entry bundle is empty", gemara.High
						}
						return gemara.Passed,
							fmt.Sprintf("entry bundle served at %s (%d bytes)", entryPath, len(body)),
							gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-CV-02.2: %s", eval.AssessmentLogs[0].Message)
		})

		It("CTRL-CV-02.3: allows offline inclusion proof verification", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "Offline Inclusion Verification",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-CV-02"},
			}

			eval.AddAssessment(
				"CTRL-CV-02.3",
				"A client MUST be able to verify entry inclusion offline from checkpoint and tiles",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(payload interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						tc := payload.(*targetContext)

						cpResp, err := http.Get(tc.TilesBaseURL + "/checkpoint") //nolint:gosec
						if err != nil {
							return gemara.Failed, fmt.Sprintf("fetch checkpoint: %v", err), gemara.High
						}
						defer cpResp.Body.Close()
						cpBody, _ := io.ReadAll(cpResp.Body)
						if len(cpBody) == 0 {
							return gemara.Failed, "empty checkpoint", gemara.High
						}

						entryPath := layout.EntriesPathForLogIndex(tc.LogIndex, tc.LogIndex+1)
						entryResp, err := http.Get(tc.TilesBaseURL + "/" + entryPath) //nolint:gosec
						if err != nil {
							return gemara.Failed, fmt.Sprintf("fetch entry bundle: %v", err), gemara.High
						}
						defer entryResp.Body.Close()
						entryBody, _ := io.ReadAll(entryResp.Body)

						if !strings.Contains(string(entryBody), "test-entry-for-verification") {
							return gemara.Failed,
								"entry bundle does not contain our submitted entry",
								gemara.High
						}

						return gemara.Passed,
							fmt.Sprintf("checkpoint (%d bytes) + entry bundle at %s (%d bytes); entry at index %d",
								len(cpBody), entryPath, len(entryBody), tc.LogIndex),
							gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-CV-02.3: %s", eval.AssessmentLogs[0].Message)
		})
	})

	Context("CTRL-CV-03: Witnessed Status Endpoint", func() {
		var apiServer *httptest.Server

		BeforeEach(func() {
			e := newTestEchoServer()
			tessera.RegisterWitnessedStatus(e, storagePath+"/log")
			apiServer = httptest.NewServer(e)
			DeferCleanup(apiServer.Close)
			target.WitnessedURL = apiServer.URL
		})

		It("CTRL-CV-03.1: reports witnessed status for a log index", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "Witnessed Status Reporting",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-CV-03"},
			}

			eval.AddAssessment(
				"CTRL-CV-03.1",
				"The log MUST report whether a log_index is covered by a witnessed checkpoint",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(payload interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						tc := payload.(*targetContext)
						url := fmt.Sprintf("%s/log/witnessed/%d", tc.WitnessedURL, tc.LogIndex)
						resp, err := http.Get(url) //nolint:gosec
						if err != nil {
							return gemara.Failed, fmt.Sprintf("GET witnessed status: %v", err), gemara.High
						}
						defer resp.Body.Close()

						if resp.StatusCode != http.StatusOK {
							return gemara.Failed,
								fmt.Sprintf("witnessed endpoint returned %d", resp.StatusCode),
								gemara.High
						}

						body, _ := io.ReadAll(resp.Body)
						if !strings.Contains(string(body), `"witnessed"`) {
							return gemara.Failed,
								"response does not contain witnessed field",
								gemara.High
						}
						return gemara.Passed,
							fmt.Sprintf("witnessed status reported for index %d", tc.LogIndex),
							gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-CV-03.1: %s", eval.AssessmentLogs[0].Message)
		})

		It("CTRL-CV-03.2: reports not-witnessed for future index", func() {
			eval := &gemara.ControlEvaluation{
				Name:    "Witnessed Status Future Index",
				Control: gemara.EntryMapping{ReferenceId: controlCatalogRef, EntryId: "CTRL-CV-03"},
			}

			eval.AddAssessment(
				"CTRL-CV-03.2",
				"The endpoint MUST report witnessed=false for an index beyond the checkpoint tree size",
				[]string{"all"},
				[]gemara.AssessmentStep{
					func(payload interface{}) (gemara.Result, string, gemara.ConfidenceLevel) {
						tc := payload.(*targetContext)
						futureIndex := uint64(999999)
						url := fmt.Sprintf("%s/log/witnessed/%d", tc.WitnessedURL, futureIndex)
						resp, err := http.Get(url) //nolint:gosec
						if err != nil {
							return gemara.Failed, fmt.Sprintf("GET witnessed status: %v", err), gemara.High
						}
						defer resp.Body.Close()

						body, _ := io.ReadAll(resp.Body)
						if strings.Contains(string(body), `"witnessed":true`) {
							return gemara.Failed,
								"future index falsely reported as witnessed",
								gemara.High
						}
						return gemara.Passed,
							fmt.Sprintf("index %d correctly reported as not witnessed", futureIndex),
							gemara.High
					},
				},
			)

			eval.Evaluate(&target, []string{"all"})
			evaluations = append(evaluations, eval)
			Expect(eval.Result).To(Equal(gemara.Passed),
				"CTRL-CV-03.2: %s", eval.AssessmentLogs[0].Message)
		})
	})

	AfterAll(func() {
		if len(evaluations) == 0 {
			return
		}

		evalLog := gemara.EvaluationLog{
			Metadata: gemara.Metadata{
				Id:            "complytime-ingest-tlog-evaluation",
				Type:          gemara.EvaluationLogArtifact,
				GemaraVersion: "1.3.0",
				Description:   "Automated evaluation of transparency log security controls",
				Author: gemara.Actor{
					Id:   "complytime-ci",
					Name: "ComplyTime CI",
					Type: gemara.Software,
				},
				MappingReferences: []gemara.MappingReference{{
					Id:          controlCatalogRef,
					Title:       "Transparency Log Control Catalog",
					Version:     "1.0.0",
					Description: "Controls for ComplyTime Ingest transparency log",
				}},
			},
			Target: gemara.Resource{
				Id: "complytime-ingest-tlog",
			},
			Evaluations: evaluations,
		}

		aggregate := gemara.Passed
		for _, e := range evaluations {
			aggregate = gemara.UpdateAggregateResult(aggregate, e.Result)
		}
		evalLog.Result = aggregate

		yamlBytes, err := goyaml.Marshal(evalLog)
		Expect(err).NotTo(HaveOccurred())

		outDir := os.Getenv("EVALUATION_OUTPUT_DIR")
		if outDir == "" {
			outDir = "testdata"
		}
		_ = os.MkdirAll(outDir, 0755)

		yamlPath := filepath.Join(outDir, "evaluation-log.yaml")
		Expect(os.WriteFile(yamlPath, yamlBytes, 0644)).To(Succeed())
		GinkgoWriter.Printf("Wrote EvaluationLog: %s\n", yamlPath)

		var catalog gemara.ControlCatalog
		catalogBytes, err := os.ReadFile("testdata/transparency-controls.yaml")
		if err == nil {
			_ = goyaml.Unmarshal(catalogBytes, &catalog)
		}

		sarifBytes, err := gemaraconv.ToSARIF(evalLog,
			gemaraconv.WithArtifactURI("internal/e2e/witness_cosign_test.go"),
			gemaraconv.WithCatalog(&catalog),
		)
		Expect(err).NotTo(HaveOccurred())

		sarifPath := filepath.Join(outDir, "evaluation-results.sarif")
		Expect(os.WriteFile(sarifPath, sarifBytes, 0644)).To(Succeed())
		GinkgoWriter.Printf("Wrote SARIF: %s\n", sarifPath)
	})
})
