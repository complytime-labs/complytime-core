-- SPDX-License-Identifier: Apache-2.0
-- Migration 014: Create a read-only Postgres role for external dashboard
-- clients (Grafana, Metabase, ad-hoc SQL). The password is set at deploy
-- time via POSTGRES_READER_PASSWORD; the migration uses a placeholder.

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'studio_reader') THEN
    CREATE ROLE studio_reader LOGIN PASSWORD 'changeme';
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO studio_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO studio_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO studio_reader;
