-- Drop certified column and certifications table
-- Trust signals are now the only source of certification status

-- Drop certifications table (replaced by trust_signals)
DROP TABLE IF EXISTS certifications;

-- Drop certified column from evidence table
ALTER TABLE evidence DROP COLUMN IF EXISTS certified;
