package nats

const (
	// SubjectIngest is the JetStream subject for ingest work items.
	// Gateway publishes IngestRef messages here; the ingest worker consumes them.
	SubjectIngest = "core.ingest"

	// SubjectEvidencePrefix is the pub/sub prefix for evidence-sealed events.
	// Full subject: core.evidence.{subject_id}
	SubjectEvidencePrefix = "core.evidence"

	// SubjectRegistration is published when a subject is registered or updated.
	SubjectRegistration = "core.subject.registered"

	// SubjectMappingImported is published when a MappingDocument is ingested.
	SubjectMappingImported = "core.mapping.imported"
)

// EvidenceSubject returns the full NATS subject for an evidence event for the given subject.
func EvidenceSubject(subjectID string) string {
	return SubjectEvidencePrefix + "." + subjectID
}
