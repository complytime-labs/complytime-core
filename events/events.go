// Package events defines the CloudEvents data types for the ComplyTime
// evidence lifecycle. These types are the stable contract between producers
// (gateway, S3+Lambda bridge) and consumers (thin DB, external subscribers).
package events

const (
	TypeEvidenceIngested  = "dev.complytime.evidence.ingested"
	TypeEvidenceSealed    = "dev.complytime.evidence.sealed"
	TypeSubjectRegistered = "dev.complytime.subject.registered"
)

// PublisherIdentity identifies the entity that produced evidence.
type PublisherIdentity struct {
	Issuer string `json:"issuer"`
	Sub    string `json:"sub"`
}

// EvidenceIngestedData is the CloudEvents data payload for evidence.ingested events.
// Emitted by both S3+Lambda and gateway when evidence arrives but before it's sealed.
type EvidenceIngestedData struct {
	ContentDigest string            `json:"contentDigest"`
	ArtifactType  string            `json:"artifactType"`
	StorageRef    string            `json:"storageRef"`
	SubjectID     string            `json:"subjectId"`
	Publisher     PublisherIdentity `json:"publisher"`
	ShardID       *string           `json:"shardId,omitempty"`
}

// EvidenceSealedData is the CloudEvents data payload for evidence.sealed events.
// Emitted by gateway only, after the locker confirms evidence is sealed with a receipt.
type EvidenceSealedData struct {
	ContentDigest string  `json:"contentDigest"`
	LogIndex      int64   `json:"logIndex"`
	ReceiptDigest string  `json:"receiptDigest"`
	ReceiptType   string  `json:"receiptType"`
	StorageRef    string  `json:"storageRef"`
	SubjectID     string  `json:"subjectId"`
	ShardID       *string `json:"shardId,omitempty"`
}

// SubjectRegisteredData is the CloudEvents data payload for subject.registered events.
type SubjectRegisteredData struct {
	SubjectID string `json:"subjectId"`
}
