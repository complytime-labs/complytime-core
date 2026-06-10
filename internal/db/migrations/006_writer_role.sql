-- SPDX-License-Identifier: Apache-2.0
-- Migration 006: allow writer role on users
--
-- 001_users.sql has no role CHECK; environments that constrained roles may use
-- CHECK (role IN (...)) or role = ANY (ARRAY[...]). Drop matching CHECKs on
-- public.users, then add users_role_check for admin | writer | reviewer.

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT c.conname AS name
        FROM pg_constraint c
        JOIN pg_class t ON c.conrelid = t.oid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'users'
          AND c.contype = 'c'
          AND (
              pg_get_constraintdef(c.oid) ~* '(role).{0,24}IN\s*\('
              OR pg_get_constraintdef(c.oid) ~* '\(?role\)?\s*=\s*ANY\s*\(\s*ARRAY'
          )
    LOOP
        EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', r.name);
    END LOOP;
END $$;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'writer', 'reviewer'));
