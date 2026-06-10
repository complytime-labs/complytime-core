-- SPDX-License-Identifier: Apache-2.0
-- Migration 011: deduplicate certifications — one verdict per (evidence_id, certifier)

DELETE FROM certifications
WHERE id NOT IN (
    SELECT DISTINCT ON (evidence_id, certifier) id
    FROM certifications
    ORDER BY evidence_id, certifier, certified_at DESC
);

ALTER TABLE certifications
    ADD CONSTRAINT uq_certifications_evidence_certifier
    UNIQUE (evidence_id, certifier);
