package ingest

// IngestRef is the message structure published to JetStream for ingest work items.
// This is the shared NATS message contract used by both gateway and locker.
type IngestRef struct {
	JobID         string `json:"jobId"`
	SubjectID     string `json:"subjectId"`
	ContentDigest string `json:"contentDigest"`
	ArtifactType  string `json:"artifactType"`
	ReceiptBytes  []byte `json:"receiptBytes"`
}
