-- SPDX-License-Identifier: Apache-2.0
-- Migration 016: Grant studio_reader SELECT access to the workbench schema.
-- Matches the initdb grants for fresh installs. Required for upgrades where
-- the workbench schema was created after initial Postgres setup.

DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'studio_reader') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA workbench TO studio_reader';
        EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA workbench TO studio_reader';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA workbench GRANT SELECT ON TABLES TO studio_reader';
    END IF;
END $$;
