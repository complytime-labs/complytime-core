-- Remove enrichment_status column and its CHECK constraint.
-- The enrichment pipeline (TruthBeam/Compass) has been removed;
-- evidence quality is validated by certifiers instead.
ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_enrichment_status_chk;
ALTER TABLE evidence DROP COLUMN IF EXISTS enrichment_status;
