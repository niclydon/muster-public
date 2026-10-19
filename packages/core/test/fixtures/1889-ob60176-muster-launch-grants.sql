-- Migration number 1889 RESERVED via migration_registry
-- (nexus_lease_allocate, slug 'ob60176-muster-launch-grants', floor 1888).
-- Do not renumber.
--
-- OB-60176: Muster identity hardening from adversarial review
-- (docs/projects/2026-09-14-ob60176-identity-adversarial-review*.md, triage in
-- docs/projects/2026-09-14-ob60176-identity-review-triage.md).
--   * agent_bus.launch_grants: launch provenance written only by an authenticated launcher
--     through the Muster API before its runner claims work (XA-01, CA-01, CA-02). Grants are
--     history: never deleted, identity immutable, revoked at most once, and at most one active
--     grant per agent_id. Each grant is bound to the launcher key that created it (XB-01, XB-02).
--   * principal_audit_events accepts 'launch_granted' and 'launch_grant_revoked'.
--   * public.muster_lock_claim(uuid): lets the API hold a claim row with FOR SHARE for the rest of
--     its issuance transaction, so the claim cannot be released between the check and the token
--     (XA-07), without giving muster_api UPDATE on operator_backlog_claims.
--   * agent_bus.muster_api_privilege_violations(role): the complete required and prohibited
--     privilege set for the API role, including inherited and PUBLIC privileges, over every
--     relation, sequence, schema, and SECURITY DEFINER function in the database (XC-01, XD-01).
--     Operators can re-run it at any time; it returns an empty array when the role is correct.
--   * The muster_api role must already exist (created by the postgres superuser, NOINHERIT, no
--     memberships; this migration cannot create roles). It gets least-privilege grants, and the
--     migration fails if the role is missing or any privilege check fails (XB-03, XC-01).
-- Additive: no existing row is changed.

BEGIN;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muster_api') THEN
    RAISE EXCEPTION 'OB-60176: role muster_api must exist before migration 1889 (create it as the postgres superuser, password in secrets-vault muster/database)';
  END IF;
  -- The migration role does not own schema agent_bus, so it cannot grant USAGE on it; a GRANT here would
  -- silently do nothing. The schema owner grants it out of band, like the role itself.
  IF NOT has_schema_privilege('muster_api', 'agent_bus', 'USAGE') THEN
    RAISE EXCEPTION 'OB-60176: grant schema usage first, as the schema owner: GRANT USAGE ON SCHEMA agent_bus TO muster_api';
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS agent_bus.launch_grants (
  grant_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id             TEXT NOT NULL CHECK (length(btrim(agent_id)) > 0),
  launcher_agent_id    TEXT NOT NULL CHECK (length(btrim(launcher_agent_id)) > 0),
  launcher_key_id      UUID NOT NULL REFERENCES agent_bus.principal_keys (key_id) ON DELETE RESTRICT,
  launcher_session_id  TEXT NOT NULL CHECK (length(btrim(launcher_session_id)) > 0),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  claim_window_ends_at TIMESTAMPTZ NOT NULL,
  revoked_at           TIMESTAMPTZ,
  revoke_reason        TEXT CHECK (revoke_reason IS NULL OR length(btrim(revoke_reason)) > 0),
  CHECK (claim_window_ends_at > created_at),
  CHECK (claim_window_ends_at <= created_at + interval '1 hour'),
  CHECK (agent_id <> launcher_agent_id),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS launch_grants_one_active
  ON agent_bus.launch_grants (agent_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS launch_grants_launcher_idx
  ON agent_bus.launch_grants (launcher_agent_id, created_at DESC);

CREATE OR REPLACE FUNCTION agent_bus.launch_grants_guard_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW IS NOT DISTINCT FROM OLD THEN
    RETURN OLD;
  END IF;
  IF NEW.grant_id IS DISTINCT FROM OLD.grant_id
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
     OR NEW.launcher_agent_id IS DISTINCT FROM OLD.launcher_agent_id
     OR NEW.launcher_key_id IS DISTINCT FROM OLD.launcher_key_id
     OR NEW.launcher_session_id IS DISTINCT FROM OLD.launcher_session_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.claim_window_ends_at IS DISTINCT FROM OLD.claim_window_ends_at THEN
    RAISE EXCEPTION 'agent_bus.launch_grants identity is immutable (grant %)', OLD.grant_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'agent_bus.launch_grants revocation is final (grant %)', OLD.grant_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$fn$;

DROP TRIGGER IF EXISTS launch_grants_guard_update ON agent_bus.launch_grants;
CREATE TRIGGER launch_grants_guard_update
  BEFORE UPDATE ON agent_bus.launch_grants
  FOR EACH ROW EXECUTE FUNCTION agent_bus.launch_grants_guard_update();

DROP TRIGGER IF EXISTS launch_grants_no_delete ON agent_bus.launch_grants;
CREATE TRIGGER launch_grants_no_delete
  BEFORE DELETE ON agent_bus.launch_grants
  FOR EACH ROW EXECUTE FUNCTION agent_bus.reject_update();

ALTER TABLE agent_bus.principal_audit_events
  DROP CONSTRAINT IF EXISTS principal_audit_events_event_type_check;
ALTER TABLE agent_bus.principal_audit_events
  ADD CONSTRAINT principal_audit_events_event_type_check CHECK (event_type IN (
    'key_issued', 'key_rotated', 'key_revoked', 'token_issued', 'token_revoked',
    'registration_requested', 'registration_approved', 'registration_rejected',
    'registration_consumed', 'session_superseded', 'launch_granted', 'launch_grant_revoked'));

-- Persistent seat keys are enrolled only by the operator's admin path, never by the API role (CA-07).
CREATE OR REPLACE FUNCTION agent_bus.principal_keys_guard_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW.key_kind = 'persistent' AND current_user = 'muster_api' THEN
    RAISE EXCEPTION 'muster_api may not enroll persistent keys; use muster-admin'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$fn$;

DROP TRIGGER IF EXISTS principal_keys_guard_insert ON agent_bus.principal_keys;
CREATE TRIGGER principal_keys_guard_insert
  BEFORE INSERT ON agent_bus.principal_keys
  FOR EACH ROW EXECUTE FUNCTION agent_bus.principal_keys_guard_insert();

-- Holds one claim row until the calling transaction ends (XA-07). Read-only apart from the row lock;
-- runs as the migration owner so muster_api needs no UPDATE privilege on the claims table.
CREATE OR REPLACE FUNCTION public.muster_lock_claim(p_claim_id UUID)
RETURNS TABLE (runner_id TEXT, claimed_at TIMESTAMPTZ, active BOOLEAN, remaining_seconds INTEGER)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $fn$
  SELECT c.runner_id,
         c.claimed_at,
         c.claim_status = 'active' AND c.released_at IS NULL AND c.lease_expires_at > now(),
         GREATEST(0, EXTRACT(EPOCH FROM (c.lease_expires_at - now())))::int
    FROM public.operator_backlog_claims c
   WHERE c.id = p_claim_id
     FOR SHARE
$fn$;

-- Complete privilege contract for the API role (XC-01). has_*_privilege includes inherited
-- privileges and PUBLIC grants; the role must also have no memberships and no elevated attributes.
CREATE OR REPLACE FUNCTION agent_bus.muster_api_privilege_violations(p_role TEXT)
RETURNS TEXT[]
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v TEXT[] := '{}';
  r RECORD;
  obj RECORD;
  item TEXT;
  identity_tables CONSTANT TEXT[] := ARRAY[
    'agent_bus.registry_entries', 'agent_bus.registration_requests', 'agent_bus.principal_keys',
    'agent_bus.issued_tokens', 'agent_bus.token_revocations', 'agent_bus.launch_grants',
    'agent_bus.principal_audit_events'];
BEGIN
  SELECT oid, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
    INTO r FROM pg_roles WHERE rolname = p_role;
  IF NOT FOUND THEN
    RETURN ARRAY[format('role %s does not exist', p_role)];
  END IF;
  IF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication THEN
    v := v || format('role %s has elevated attributes', p_role);
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) THEN
    v := v || format('role %s is a member of another role', p_role);
  END IF;

  FOREACH item IN ARRAY ARRAY[
    'agent_bus.registry_entries:SELECT', 'agent_bus.registration_requests:SELECT',
    'agent_bus.registration_requests:INSERT', 'agent_bus.principal_keys:SELECT',
    'agent_bus.principal_keys:INSERT', 'agent_bus.issued_tokens:SELECT', 'agent_bus.issued_tokens:INSERT',
    'agent_bus.token_revocations:SELECT', 'agent_bus.token_revocations:INSERT',
    'agent_bus.launch_grants:SELECT', 'agent_bus.launch_grants:INSERT', 'agent_bus.principal_audit_events:INSERT']
  LOOP
    IF NOT has_table_privilege(p_role, split_part(item, ':', 1), split_part(item, ':', 2)) THEN
      v := v || ('missing ' || item);
    END IF;
  END LOOP;

  FOREACH item IN ARRAY ARRAY[
    'agent_bus.registry_entries:agent_id:INSERT', 'agent_bus.registry_entries:last_seen_at:UPDATE',
    'agent_bus.registration_requests:status:UPDATE', 'agent_bus.principal_keys:revoked_at:UPDATE',
    'agent_bus.issued_tokens:revoked_at:UPDATE', 'agent_bus.issued_tokens:superseded_by_jti:UPDATE',
    'agent_bus.launch_grants:revoked_at:UPDATE', 'public.operator_backlog_claims:runner_id:SELECT',
    'public.operator_backlog_claims:claimed_at:SELECT']
  LOOP
    IF NOT has_column_privilege(p_role, split_part(item, ':', 1), split_part(item, ':', 2), split_part(item, ':', 3)) THEN
      v := v || ('missing ' || item);
    END IF;
  END LOOP;

  IF NOT has_schema_privilege(p_role, 'agent_bus', 'USAGE') THEN
    v := v || 'missing agent_bus:USAGE'::TEXT;
  END IF;
  IF NOT has_function_privilege(p_role, 'public.muster_lock_claim(uuid)', 'EXECUTE') THEN
    v := v || 'missing public.muster_lock_claim(uuid):EXECUTE'::TEXT;
  END IF;

  -- Column-grantable privileges are checked with has_any_column_privilege, which also sees table-level grants.
  FOREACH item IN ARRAY ARRAY[
    'agent_bus.messages:SELECT', 'agent_bus.messages:INSERT', 'agent_bus.messages:UPDATE',
    'agent_bus.messages:REFERENCES', 'public.operator_backlog_claims:INSERT',
    'public.operator_backlog_claims:UPDATE', 'public.operator_backlog_claims:REFERENCES',
    'agent_bus.principal_audit_events:SELECT', 'agent_bus.principal_audit_events:UPDATE']
  LOOP
    IF has_any_column_privilege(p_role, split_part(item, ':', 1), split_part(item, ':', 2)) THEN
      v := v || ('prohibited ' || item);
    END IF;
  END LOOP;

  FOREACH item IN ARRAY ARRAY['agent_bus.messages', 'public.operator_backlog_claims'] || identity_tables
  LOOP
    IF has_table_privilege(p_role, item, 'DELETE') THEN v := v || ('prohibited ' || item || ':DELETE'); END IF;
    IF has_table_privilege(p_role, item, 'TRUNCATE') THEN v := v || ('prohibited ' || item || ':TRUNCATE'); END IF;
    IF has_table_privilege(p_role, item, 'TRIGGER') THEN v := v || ('prohibited ' || item || ':TRIGGER'); END IF;
  END LOOP;
  FOREACH item IN ARRAY identity_tables
  LOOP
    IF has_any_column_privilege(p_role, item, 'REFERENCES') THEN v := v || ('prohibited ' || item || ':REFERENCES'); END IF;
  END LOOP;

  IF has_column_privilege(p_role, 'public.operator_backlog_claims', 'metadata', 'SELECT') THEN
    v := v || 'prohibited public.operator_backlog_claims:metadata:SELECT'::TEXT;
  END IF;
  IF has_column_privilege(p_role, 'agent_bus.registry_entries', 'tombstoned_at', 'UPDATE') THEN
    v := v || 'prohibited agent_bus.registry_entries:tombstoned_at:UPDATE'::TEXT;
  END IF;
  IF has_column_privilege(p_role, 'agent_bus.registry_entries', 'tombstoned_at', 'INSERT') THEN
    v := v || 'prohibited agent_bus.registry_entries:tombstoned_at:INSERT'::TEXT;
  END IF;
  IF has_schema_privilege(p_role, 'agent_bus', 'CREATE') THEN
    v := v || 'prohibited agent_bus:CREATE'::TEXT;
  END IF;
  IF has_schema_privilege(p_role, 'public', 'CREATE') THEN
    v := v || 'prohibited public:CREATE'::TEXT;
  END IF;

  -- Everything else the role can reach, in every schema, directly, through PUBLIC, or inherited (XD-01).
  FOR obj IN
    SELECT c.oid, n.nspname || '.' || c.relname AS name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
  LOOP
    CONTINUE WHEN obj.name = ANY (identity_tables) OR obj.name = 'public.operator_backlog_claims';
    IF has_any_column_privilege(p_role, obj.oid, 'SELECT') OR has_any_column_privilege(p_role, obj.oid, 'INSERT')
       OR has_any_column_privilege(p_role, obj.oid, 'UPDATE') OR has_any_column_privilege(p_role, obj.oid, 'REFERENCES')
       OR has_table_privilege(p_role, obj.oid, 'DELETE') OR has_table_privilege(p_role, obj.oid, 'TRUNCATE')
       OR has_table_privilege(p_role, obj.oid, 'TRIGGER') THEN
      v := v || ('prohibited access to ' || obj.name);
    END IF;
  END LOOP;

  FOR obj IN
    SELECT c.oid, n.nspname || '.' || c.relname AS name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  LOOP
    CONTINUE WHEN obj.oid = to_regclass(pg_get_serial_sequence('agent_bus.principal_audit_events', 'event_id'));
    IF has_sequence_privilege(p_role, obj.oid, 'USAGE') OR has_sequence_privilege(p_role, obj.oid, 'SELECT')
       OR has_sequence_privilege(p_role, obj.oid, 'UPDATE') THEN
      v := v || ('prohibited access to sequence ' || obj.name);
    END IF;
  END LOOP;

  -- Ordinary functions run with the caller's privileges and cannot exceed the grants checked above.
  -- SECURITY DEFINER functions run as their owner, so any executable one is a boundary crossing unless
  -- allowlisted. Trigger functions cannot be called directly. has_function_privilege below sees
  -- direct, inherited, and PUBLIC EXECUTE alike (OB-60208). Allowlist:
  --   muster_lock_claim: this migration's claim lock.
  --   aurora_check_gold_branch_expectations: STABLE (cannot write), returns aggregate gold row counts,
  --   already executable by every login role through PUBLIC; platform-wide PUBLIC EXECUTE review is OB-60212.
  FOR obj IN
    SELECT p.oid, n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS name
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE p.prosecdef
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
  LOOP
    CONTINUE WHEN obj.name IN ('public.muster_lock_claim(p_claim_id uuid)', 'public.aurora_check_gold_branch_expectations(target_gold_object text)');
    IF has_function_privilege(p_role, obj.oid, 'EXECUTE') THEN
      v := v || ('prohibited execute on security definer ' || obj.name);
    END IF;
  END LOOP;

  FOR obj IN
    SELECT oid, nspname AS name FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema'
  LOOP
    IF has_schema_privilege(p_role, obj.oid, 'CREATE') THEN
      v := v || ('prohibited create on schema ' || obj.name);
    END IF;
  END LOOP;
  IF has_database_privilege(p_role, current_database(), 'CREATE') THEN
    v := v || 'prohibited create on database'::TEXT;
  END IF;
  RETURN v;
END;
$fn$;

REVOKE ALL ON FUNCTION agent_bus.principal_keys_guard_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.launch_grants_guard_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.muster_lock_claim(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.muster_api_privilege_violations(TEXT) FROM PUBLIC;

DO $$
DECLARE
  audit_seq TEXT;
  violations TEXT[];
BEGIN
  REVOKE ALL ON agent_bus.messages FROM muster_api;
  REVOKE ALL ON public.operator_backlog_claims FROM muster_api;

  GRANT SELECT ON agent_bus.registry_entries TO muster_api;
  GRANT INSERT (agent_id, runtime, persistence_class, roles, may_address, addressable_by, scope,
                ttl_seconds, last_seen_at, presence_state, proxied_by)
    ON agent_bus.registry_entries TO muster_api;
  GRANT UPDATE (runtime, persistence_class, roles, may_address, addressable_by, scope,
                ttl_seconds, last_seen_at, presence_state, proxied_by, updated_at)
    ON agent_bus.registry_entries TO muster_api;

  GRANT SELECT, INSERT ON agent_bus.registration_requests TO muster_api;
  GRANT UPDATE (status, consumed_at, consumed_token_jti) ON agent_bus.registration_requests TO muster_api;

  GRANT SELECT, INSERT ON agent_bus.principal_keys TO muster_api;
  GRANT UPDATE (revoked_at) ON agent_bus.principal_keys TO muster_api;

  GRANT SELECT, INSERT ON agent_bus.issued_tokens TO muster_api;
  GRANT UPDATE (revoked_at, revoke_reason, superseded_by_jti) ON agent_bus.issued_tokens TO muster_api;

  GRANT SELECT, INSERT ON agent_bus.token_revocations TO muster_api;
  GRANT SELECT, INSERT ON agent_bus.launch_grants TO muster_api;
  GRANT UPDATE (revoked_at, revoke_reason) ON agent_bus.launch_grants TO muster_api;
  GRANT INSERT ON agent_bus.principal_audit_events TO muster_api;

  audit_seq := pg_get_serial_sequence('agent_bus.principal_audit_events', 'event_id');
  IF audit_seq IS NOT NULL THEN
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO muster_api', audit_seq);
  END IF;

  GRANT SELECT (id, runner_id, claim_status, released_at, lease_expires_at, claimed_at)
    ON public.operator_backlog_claims TO muster_api;
  GRANT EXECUTE ON FUNCTION public.muster_lock_claim(UUID) TO muster_api;

  violations := agent_bus.muster_api_privilege_violations('muster_api');
  IF cardinality(violations) > 0 THEN
    RAISE EXCEPTION 'OB-60176: muster_api privileges did not verify: %', array_to_string(violations, '; ');
  END IF;
END;
$$;

COMMENT ON TABLE agent_bus.launch_grants IS 'OB-60176 Muster launch provenance: an authenticated launcher declares the exact agent_id it launches, bound to its key, before the runner claims work (AR XA-01, XB-01). Never deleted; at most one active grant per agent_id.';
COMMENT ON FUNCTION public.muster_lock_claim(UUID) IS 'OB-60176 Muster: read one claim FOR SHARE for the rest of the caller''s transaction (AR XA-07). Execute granted to muster_api only.';
COMMENT ON FUNCTION agent_bus.muster_api_privilege_violations(TEXT) IS 'OB-60176 Muster: returns every missing required or present prohibited privilege for the API role, including inherited privileges (AR XC-01). Empty array means the role is correct.';

INSERT INTO aurora_data_objects
  (object_name, layer, object_kind, canonical_name, source_key, domain, lifecycle_state, notes)
VALUES
  ('agent_bus.launch_grants', 'registry', 'table', 'agent_bus.launch_grants', 'agent_bus', 'coordination', 'active', 'OB-60176 Muster launch grants.')
ON CONFLICT (object_name) DO UPDATE
  SET notes = EXCLUDED.notes, lifecycle_state = 'active', updated_at = now();

INSERT INTO aurora_data_object_consumers
  (object_name, column_name, consumer_kind, consumer_name, access_kind, evidence, lifecycle_state)
VALUES
  ('agent_bus.launch_grants', '*', 'migration', 'ob60176-muster-launch-grants', 'writes', 'OB-60176 creates the Muster launch grants table.', 'active'),
  ('agent_bus.launch_grants', '*', 'api_route', 'muster-api', 'writes', 'OB-60176 POST /v1/launch-grants records a launcher''s grant and revokes the grant it replaces.', 'active'),
  ('agent_bus.launch_grants', '*', 'api_route', 'muster-api', 'reads', 'OB-60176 brokered registration requires the launcher''s active grant and a claim created after it.', 'active'),
  ('agent_bus.launch_grants', '*', 'script', 'muster-admin', 'writes', 'OB-60176 muster-admin revokes grants on key rotation, key or agent revocation, break glass, and revoke-grant.', 'active')
ON CONFLICT (object_name, column_name, consumer_kind, consumer_name, access_kind)
DO UPDATE SET evidence = EXCLUDED.evidence, lifecycle_state = 'active', updated_at = now();

INSERT INTO nexus_schema_version (version, description)
VALUES (1889, 'OB-60176 Muster launch grants, claim lock, privilege verifier, and muster_api least-privilege grants')
ON CONFLICT (version) DO NOTHING;

UPDATE migration_registry
   SET status = 'applied', applied_at = now()
 WHERE version = 1889
   AND slug = 'ob60176-muster-launch-grants'
   AND status = 'reserved';

COMMIT;
