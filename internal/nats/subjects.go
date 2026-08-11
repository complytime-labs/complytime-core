package nats

const (
	// SubjectIngest is the JetStream subject for ingest work items.
	// Gateway publishes IngestRef messages here; the ingest worker consumes them.
	SubjectIngest = "core.ingest"

	// SubjectEvidenceIngestedPrefix is the pub/sub prefix for evidence-ingested events.
	// Full subject: core.evidence.ingested.{subject_id}
	SubjectEvidenceIngestedPrefix = "core.evidence.ingested"

	// SubjectEvidenceSealedPrefix is the pub/sub prefix for evidence-sealed events.
	// Full subject: core.evidence.sealed.{subject_id}
	SubjectEvidenceSealedPrefix = "core.evidence.sealed"

	// SubjectRegistration is published when a subject is registered or updated.
	SubjectRegistration = "core.subject.registered"

	// SubjectMappingImported is published when a MappingDocument is ingested.
	SubjectMappingImported = "core.mapping.imported"

	// SubjectAdminRegisterSubject is the NATS core request-reply subject for subject registration.
	// Gateway publishes; locker handles.
	SubjectAdminRegisterSubject = "core.admin.subjects.register"

	// SubjectAdminSealTrust is the NATS core request-reply subject for trust receipt sealing.
	// Gateway publishes; locker handles.
	SubjectAdminSealTrust = "core.admin.trust.seal"
)

// EvidenceIngestedSubject returns the full NATS subject for an evidence-ingested event.
func EvidenceIngestedSubject(subjectID string) string {
	return SubjectEvidenceIngestedPrefix + "." + subjectID
}

// EvidenceSealedSubject returns the full NATS subject for an evidence-sealed event.
func EvidenceSealedSubject(subjectID string) string {
	return SubjectEvidenceSealedPrefix + "." + subjectID
}
