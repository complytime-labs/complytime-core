-- SPDX-License-Identifier: Apache-2.0
-- Migration 017: Schema-scoped grants for service roles.
--
-- Assigns least-privilege grants to gateway_rw and workbench_rw roles.
-- Role creation and passwords are handled by the Helm initdb script
-- (postgres.yaml 01-schemas-and-roles.sql). This migration only
-- manages grants and revocations — it is safe to re-run.
--
-- If roles do not exist (non-Helm deploy), create them with NOLOGIN
-- so grants succeed. Operators must ALTER ROLE ... LOGIN PASSWORD
-- before services can connect.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway_rw') THEN
        CREATE ROLE gateway_rw NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'workbench_rw') THEN
        CREATE ROLE workbench_rw NOLOGIN;
    END IF;
END $$;

-- Gateway: full access to public schema
GRANT ALL ON SCHEMA public TO gateway_rw;
GRANT ALL ON ALL TABLES IN SCHEMA public TO gateway_rw;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO gateway_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON TABLES TO gateway_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON SEQUENCES TO gateway_rw;

-- Workbench: full access to workbench schema
CREATE SCHEMA IF NOT EXISTS workbench;
GRANT ALL ON SCHEMA workbench TO workbench_rw;
GRANT ALL ON ALL TABLES IN SCHEMA workbench TO workbench_rw;
GRANT ALL ON ALL SEQUENCES IN SCHEMA workbench TO workbench_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA workbench
    GRANT ALL ON TABLES TO workbench_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA workbench
    GRANT ALL ON SEQUENCES TO workbench_rw;

-- Revoke cross-schema access (role-specific and PUBLIC fallback)
REVOKE ALL ON SCHEMA workbench FROM gateway_rw;
REVOKE ALL ON SCHEMA public FROM workbench_rw;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM workbench_rw;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM workbench_rw;
