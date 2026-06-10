-- SPDX-License-Identifier: Apache-2.0
-- Migration 015: Move program-related tables to the workbench schema.
-- Handles upgrades from existing deployments where these tables live in public.
-- For fresh installs the workbench migration runner creates them directly.
--
-- Race safety: if the workbench migration runner already created a table in
-- the workbench schema, we skip the ALTER and drop the now-redundant public
-- copy (child tables first to satisfy FK constraints).

CREATE SCHEMA IF NOT EXISTS workbench;

DO $$
DECLARE
    _move_table TEXT;
BEGIN
    -- Order matters: child tables before parent (programs last).
    FOREACH _move_table IN ARRAY ARRAY[
        'recommendation_dismissals',
        'program_findings',
        'program_members',
        'jobs',
        'programs'
    ] LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = _move_table
        ) THEN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'workbench' AND table_name = _move_table
            ) THEN
                EXECUTE format(
                    'ALTER TABLE public.%I SET SCHEMA workbench', _move_table
                );
            ELSE
                EXECUTE format('DROP TABLE public.%I CASCADE', _move_table);
            END IF;
        END IF;
    END LOOP;
END $$;
