-- Migration 1895 RESERVED via migration_registry (OB-60221). Do not renumber.
-- Versioned North Star state, break-glass read-only freeze, and the exact
-- least-privilege SECURITY DEFINER grants: ordinary freeze checks to muster_api,
-- and principal-admin functions only to muster_admin. Actor attribution
-- is derived from SET LOCAL muster.actor, never from a caller-supplied argument.
--
-- 1896 may already be applied (it wraps the 1892 verifier). This rewrite updates
-- the innermost 1892 allowlist wherever it lives, so the final verifier is the
-- 1896 wrapper around the 1895-extended 1892 body — everything both require,
-- and no more.
BEGIN;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muster_admin') THEN
    RAISE EXCEPTION 'OB-60221 operator prerequisite: create LOGIN role muster_admin on this cluster and store its credential at vault secret muster/admin-database before applying 1895';
  END IF;
END $$;

CREATE TABLE agent_bus.north_star_versions (
  version BIGSERIAL PRIMARY KEY,
  mission TEXT NOT NULL CHECK (length(btrim(mission)) BETWEEN 1 AND 10000),
  updated_by TEXT NOT NULL CHECK (length(btrim(updated_by)) > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  supersedes BIGINT REFERENCES agent_bus.north_star_versions(version) ON DELETE RESTRICT
);
CREATE TABLE agent_bus.goals (
  version BIGSERIAL PRIMARY KEY,
  goal_id UUID NOT NULL,
  title TEXT NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 500),
  detail TEXT,
  domain TEXT NOT NULL CHECK (length(btrim(domain)) BETWEEN 1 AND 200),
  position INTEGER NOT NULL CHECK (position >= 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  updated_by TEXT NOT NULL CHECK (length(btrim(updated_by)) > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  supersedes BIGINT REFERENCES agent_bus.goals(version) ON DELETE RESTRICT
);
CREATE INDEX goals_current_order_idx ON agent_bus.goals (goal_id, version DESC);
ALTER TABLE agent_bus.registry_entries ADD COLUMN initiative_tier TEXT NOT NULL DEFAULT 'T0' CHECK (initiative_tier IN ('T0','T1','T2'));

CREATE TABLE agent_bus.operational_state (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  read_only BOOLEAN NOT NULL DEFAULT FALSE,
  read_only_set_at TIMESTAMPTZ,
  read_only_set_by TEXT,
  read_only_reason TEXT,
  read_only_cleared_at TIMESTAMPTZ,
  read_only_cleared_by TEXT
);
INSERT INTO agent_bus.operational_state (singleton, read_only) VALUES (TRUE, FALSE);

-- muster_api has SELECT on this table but not UPDATE, so it cannot take FOR SHARE itself
-- (PostgreSQL 16 rejects that as permission denied). Ordinary writes call this definer so
-- the freeze check and the mutation share a transaction that conflicts with break-glass
-- FOR UPDATE, without granting UPDATE on the singleton.
CREATE FUNCTION agent_bus.muster_assert_writable()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = agent_bus, pg_catalog
AS $$
BEGIN
  IF (SELECT read_only FROM operational_state WHERE singleton FOR SHARE) THEN
    RAISE EXCEPTION 'writes_frozen';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION agent_bus.muster_assert_writable() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_bus.muster_assert_writable() TO muster_api;

ALTER TABLE agent_bus.principal_audit_events DROP CONSTRAINT IF EXISTS principal_audit_events_event_type_check;
ALTER TABLE agent_bus.principal_audit_events
  ADD CONSTRAINT principal_audit_events_event_type_check CHECK (event_type IN (
    'key_issued', 'key_rotated', 'key_revoked', 'token_issued', 'token_revoked',
    'registration_requested', 'registration_approved', 'registration_rejected',
    'registration_consumed', 'session_superseded', 'launch_granted', 'launch_grant_revoked',
    'break_glass', 'writes_recovered'));

-- Internal helper: not SECURITY DEFINER and not granted to muster_api.
-- Privileged callers invoke it as the function owner and it rejects a missing,
-- forged, or non-operator session actor.
CREATE FUNCTION agent_bus.muster_session_actor()
RETURNS text
LANGUAGE plpgsql
STABLE
SET search_path = agent_bus, pg_catalog
AS $$
DECLARE
  actor text;
BEGIN
  actor := btrim(nullif(current_setting('muster.actor', true), ''));
  IF actor IS NULL THEN
    RAISE EXCEPTION 'muster_actor_missing' USING ERRCODE = '28000';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM principal_keys k
      JOIN registry_entries e ON e.agent_id = k.agent_id
     WHERE k.agent_id = actor
       AND k.revoked_at IS NULL
       AND (k.expires_at IS NULL OR k.expires_at > now())
       AND k.key_kind IN ('persistent', 'operator_interactive')
       AND e.tombstoned_at IS NULL
       AND 'operator' = ANY (e.roles)
  ) THEN
    RAISE EXCEPTION 'muster_actor_not_operator' USING ERRCODE = '42501';
  END IF;
  RETURN actor;
END;
$$;
REVOKE ALL ON FUNCTION agent_bus.muster_session_actor() FROM PUBLIC;

CREATE FUNCTION agent_bus.muster_principal_revoke(p_agent_id text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = agent_bus, pg_catalog
AS $$
DECLARE
  actor text;
  keys_revoked integer := 0;
  tokens_revoked integer := 0;
  grants_revoked integer := 0;
  rec record;
  tok record;
  g record;
BEGIN
  IF p_agent_id IS NULL OR length(btrim(p_agent_id)) = 0 OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
    RAISE EXCEPTION 'invalid_reason';
  END IF;
  actor := agent_bus.muster_session_actor();
  IF (SELECT read_only FROM operational_state WHERE singleton FOR SHARE) THEN
    RAISE EXCEPTION 'writes_frozen';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('muster:agent:' || p_agent_id, 0));

  FOR rec IN
    SELECT key_id FROM principal_keys WHERE agent_id = p_agent_id AND revoked_at IS NULL
  LOOP
    UPDATE principal_keys SET revoked_at = now() WHERE key_id = rec.key_id AND revoked_at IS NULL;
    keys_revoked := keys_revoked + 1;
    INSERT INTO principal_audit_events(event_type, agent_id, key_id, actor, detail)
      VALUES ('key_revoked', p_agent_id, rec.key_id, actor, jsonb_build_object('reason', p_reason, 'via', 'muster_principal_revoke'));
  END LOOP;

  FOR tok IN
    UPDATE issued_tokens
       SET revoked_at = now(), revoke_reason = p_reason
     WHERE agent_id = p_agent_id AND revoked_at IS NULL
    RETURNING jti, key_id, session_id, expires_at
  LOOP
    INSERT INTO token_revocations (jti, agent_id, reason, expires_at)
      VALUES (tok.jti, p_agent_id, p_reason, tok.expires_at)
      ON CONFLICT (jti) DO NOTHING;
    INSERT INTO principal_audit_events(event_type, agent_id, key_id, jti, session_id, actor, detail)
      VALUES ('token_revoked', p_agent_id, tok.key_id, tok.jti, tok.session_id, actor, jsonb_build_object('reason', p_reason));
    tokens_revoked := tokens_revoked + 1;
  END LOOP;

  FOR g IN
    UPDATE launch_grants
       SET revoked_at = now(), revoke_reason = p_reason
     WHERE revoked_at IS NULL AND (agent_id = p_agent_id OR launcher_agent_id = p_agent_id)
    RETURNING grant_id, agent_id, launcher_agent_id
  LOOP
    INSERT INTO principal_audit_events(event_type, agent_id, actor, detail)
      VALUES ('launch_grant_revoked', g.agent_id, actor,
              jsonb_build_object('grant_id', g.grant_id, 'launcher_agent_id', g.launcher_agent_id, 'reason', p_reason));
    grants_revoked := grants_revoked + 1;
  END LOOP;

  INSERT INTO registry_entries (agent_id, runtime, persistence_class, ttl_seconds, tombstoned_at)
    SELECT p_agent_id, 'worker', 'ephemeral', 60, now()
     WHERE NOT EXISTS (SELECT 1 FROM registry_entries WHERE agent_id = p_agent_id);
  UPDATE registry_entries SET tombstoned_at = now(), updated_at = now()
   WHERE agent_id = p_agent_id AND tombstoned_at IS NULL;

  RETURN jsonb_build_object(
    'agent_id', p_agent_id,
    'keys_revoked', keys_revoked,
    'tokens_revoked', tokens_revoked,
    'grants_revoked', grants_revoked
  );
END;
$$;
REVOKE ALL ON FUNCTION agent_bus.muster_principal_revoke(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_bus.muster_principal_revoke(text, text) TO muster_admin;

CREATE FUNCTION agent_bus.muster_principal_enroll(
  p_agent_id text, p_public_key text, p_key_hash text, p_days integer, p_rotate boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = agent_bus, pg_catalog
AS $$
DECLARE
  actor text;
  created_key uuid;
  created_expires timestamptz;
  reinstated boolean := false;
  rotated_ids uuid[] := '{}';
  old record;
  tok record;
  g record;
BEGIN
  actor := agent_bus.muster_session_actor();
  IF (SELECT read_only FROM operational_state WHERE singleton FOR SHARE) THEN
    RAISE EXCEPTION 'writes_frozen';
  END IF;
  IF p_days IS NULL OR p_days NOT BETWEEN 1 AND 365
     OR p_agent_id IS NULL OR length(btrim(p_agent_id)) = 0
     OR p_public_key IS NULL OR length(btrim(p_public_key)) = 0
     OR p_key_hash IS NULL OR p_key_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid_enrollment';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('muster:agent:' || p_agent_id, 0));

  IF EXISTS (
    SELECT 1 FROM principal_keys
     WHERE agent_id = p_agent_id AND key_kind = 'persistent' AND revoked_at IS NULL
  ) AND NOT COALESCE(p_rotate, false) THEN
    RAISE EXCEPTION 'active_key_exists' USING ERRCODE = '23505';
  END IF;

  INSERT INTO principal_keys (agent_id, request_id, public_key, public_key_sha256, key_kind, expires_at)
    VALUES (p_agent_id, NULL, p_public_key, p_key_hash, 'persistent', now() + make_interval(days => p_days))
    RETURNING key_id, expires_at INTO created_key, created_expires;

  UPDATE registry_entries SET tombstoned_at = NULL, updated_at = now()
   WHERE agent_id = p_agent_id AND tombstoned_at IS NOT NULL;
  IF FOUND THEN reinstated := true; END IF;

  INSERT INTO principal_audit_events(event_type, agent_id, key_id, actor, detail)
    VALUES ('key_issued', p_agent_id, created_key, actor,
            jsonb_build_object('via', 'muster_principal_enroll', 'key_kind', 'persistent',
                               'public_key_sha256', p_key_hash, 'expires_at', created_expires,
                               'reinstated', reinstated));

  FOR old IN
    SELECT key_id FROM principal_keys
     WHERE agent_id = p_agent_id AND key_kind = 'persistent' AND revoked_at IS NULL AND key_id <> created_key
  LOOP
    UPDATE principal_keys SET revoked_at = now() WHERE key_id = old.key_id AND revoked_at IS NULL;
    rotated_ids := array_append(rotated_ids, old.key_id);
    FOR tok IN
      UPDATE issued_tokens
         SET revoked_at = now(), revoke_reason = 'key_rotated'
       WHERE agent_id = p_agent_id AND key_id = old.key_id AND revoked_at IS NULL
      RETURNING jti, key_id, session_id, expires_at
    LOOP
      INSERT INTO token_revocations (jti, agent_id, reason, expires_at)
        VALUES (tok.jti, p_agent_id, 'key_rotated', tok.expires_at)
        ON CONFLICT (jti) DO NOTHING;
      INSERT INTO principal_audit_events(event_type, agent_id, key_id, jti, session_id, actor, detail)
        VALUES ('token_revoked', p_agent_id, tok.key_id, tok.jti, tok.session_id, actor, jsonb_build_object('reason', 'key_rotated'));
    END LOOP;
    FOR g IN
      UPDATE launch_grants
         SET revoked_at = now(), revoke_reason = 'key_rotated'
       WHERE revoked_at IS NULL AND launcher_key_id = old.key_id
      RETURNING grant_id, agent_id, launcher_agent_id
    LOOP
      INSERT INTO principal_audit_events(event_type, agent_id, actor, detail)
        VALUES ('launch_grant_revoked', g.agent_id, actor,
                jsonb_build_object('grant_id', g.grant_id, 'launcher_agent_id', g.launcher_agent_id, 'reason', 'key_rotated'));
    END LOOP;
    INSERT INTO principal_audit_events(event_type, agent_id, key_id, actor, detail)
      VALUES ('key_revoked', p_agent_id, old.key_id, actor, jsonb_build_object('reason', 'key_rotated'));
    INSERT INTO principal_audit_events(event_type, agent_id, key_id, actor, detail)
      VALUES ('key_rotated', p_agent_id, created_key, actor, jsonb_build_object('previous_key_id', old.key_id));
  END LOOP;

  RETURN jsonb_build_object(
    'agent_id', p_agent_id,
    'key_id', created_key,
    'public_key_sha256', p_key_hash,
    'expires_at', created_expires,
    'rotated_key_ids', to_jsonb(rotated_ids),
    'reinstated', reinstated
  );
END;
$$;
REVOKE ALL ON FUNCTION agent_bus.muster_principal_enroll(text, text, text, integer, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_bus.muster_principal_enroll(text, text, text, integer, boolean) TO muster_admin;

CREATE FUNCTION agent_bus.muster_break_glass(p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = agent_bus, pg_catalog
AS $$
DECLARE
  actor text;
  keys_revoked integer := 0;
  tokens_revoked integer := 0;
  grants_revoked integer := 0;
  rec record;
  tok record;
  g record;
BEGIN
  IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
    RAISE EXCEPTION 'invalid_reason';
  END IF;
  actor := agent_bus.muster_session_actor();
  PERFORM 1 FROM operational_state WHERE singleton FOR UPDATE;
  LOCK TABLE issued_tokens, principal_keys, launch_grants IN SHARE ROW EXCLUSIVE MODE;

  FOR rec IN
    SELECT key_id, agent_id FROM principal_keys WHERE revoked_at IS NULL
  LOOP
    UPDATE principal_keys SET revoked_at = now() WHERE key_id = rec.key_id AND revoked_at IS NULL;
    keys_revoked := keys_revoked + 1;
    INSERT INTO principal_audit_events(event_type, agent_id, key_id, actor, detail)
      VALUES ('key_revoked', rec.agent_id, rec.key_id, actor, jsonb_build_object('reason', 'break_glass: ' || p_reason));
  END LOOP;

  FOR tok IN
    UPDATE issued_tokens
       SET revoked_at = now(), revoke_reason = 'break_glass: ' || p_reason
     WHERE revoked_at IS NULL
    RETURNING jti, agent_id, key_id, session_id, expires_at
  LOOP
    INSERT INTO token_revocations (jti, agent_id, reason, expires_at)
      VALUES (tok.jti, tok.agent_id, 'break_glass: ' || p_reason, tok.expires_at)
      ON CONFLICT (jti) DO NOTHING;
    INSERT INTO principal_audit_events(event_type, agent_id, key_id, jti, session_id, actor, detail)
      VALUES ('token_revoked', tok.agent_id, tok.key_id, tok.jti, tok.session_id, actor,
              jsonb_build_object('reason', 'break_glass: ' || p_reason));
    tokens_revoked := tokens_revoked + 1;
  END LOOP;

  FOR g IN
    UPDATE launch_grants
       SET revoked_at = now(), revoke_reason = 'break_glass: ' || p_reason
     WHERE revoked_at IS NULL
    RETURNING grant_id, agent_id, launcher_agent_id
  LOOP
    INSERT INTO principal_audit_events(event_type, agent_id, actor, detail)
      VALUES ('launch_grant_revoked', g.agent_id, actor,
              jsonb_build_object('grant_id', g.grant_id, 'launcher_agent_id', g.launcher_agent_id,
                                 'reason', 'break_glass: ' || p_reason));
    grants_revoked := grants_revoked + 1;
  END LOOP;

  UPDATE operational_state
     SET read_only = TRUE,
         read_only_set_at = now(),
         read_only_set_by = actor,
         read_only_reason = p_reason,
         read_only_cleared_at = NULL,
         read_only_cleared_by = NULL
   WHERE singleton;

  INSERT INTO principal_audit_events(event_type, agent_id, actor, detail)
    VALUES ('break_glass', actor, actor,
            jsonb_build_object('reason', p_reason, 'keys_revoked', keys_revoked,
                               'tokens_revoked', tokens_revoked, 'grants_revoked', grants_revoked));

  RETURN jsonb_build_object(
    'keys_revoked', keys_revoked,
    'tokens_revoked', tokens_revoked,
    'grants_revoked', grants_revoked,
    'read_only', TRUE
  );
END;
$$;
REVOKE ALL ON FUNCTION agent_bus.muster_break_glass(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_bus.muster_break_glass(text) TO muster_admin;

CREATE FUNCTION agent_bus.muster_recover_writes(p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = agent_bus, pg_catalog
AS $$
DECLARE
  actor text;
BEGIN
  IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
    RAISE EXCEPTION 'invalid_reason';
  END IF;
  actor := agent_bus.muster_session_actor();
  PERFORM 1 FROM operational_state WHERE singleton FOR UPDATE;
  UPDATE operational_state
     SET read_only = FALSE,
         read_only_cleared_at = now(),
         read_only_cleared_by = actor
   WHERE singleton;
  INSERT INTO principal_audit_events(event_type, agent_id, actor, detail)
    VALUES ('writes_recovered', actor, actor, jsonb_build_object('reason', p_reason, 'via', 'muster_recover_writes'));
  RETURN jsonb_build_object('read_only', FALSE);
END;
$$;
REVOKE ALL ON FUNCTION agent_bus.muster_recover_writes(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_bus.muster_recover_writes(text) TO muster_admin;

-- Extend the innermost 1892 allowlist (current name, or _1892 after 1896).
DO $$
DECLARE
  target text;
  d text;
BEGIN
  IF to_regprocedure('agent_bus.muster_api_privilege_violations_1892(text)') IS NOT NULL THEN
    target := 'agent_bus.muster_api_privilege_violations_1892(text)';
  ELSE
    target := 'agent_bus.muster_api_privilege_violations(text)';
  END IF;
  SELECT pg_get_functiondef(target::regprocedure) INTO d;
  d := replace(d, $q$'agent_bus.delivery_outbox', 'agent_bus.role_mailbox', 'agent_bus.conditions', 'agent_bus.wake_queue']$q$,
                  $q$'agent_bus.delivery_outbox', 'agent_bus.role_mailbox', 'agent_bus.conditions', 'agent_bus.wake_queue', 'agent_bus.north_star_versions', 'agent_bus.goals', 'agent_bus.operational_state']$q$);
  d := replace(d, $q$'agent_bus.role_mailbox_mailbox_id_seq']$q$,
                  $q$'agent_bus.role_mailbox_mailbox_id_seq', 'agent_bus.north_star_versions_version_seq', 'agent_bus.goals_version_seq']$q$);
  d := replace(d, $q$'agent_bus.conditions:SELECT', 'agent_bus.conditions:INSERT']$q$,
                  $q$'agent_bus.conditions:SELECT', 'agent_bus.conditions:INSERT', 'agent_bus.north_star_versions:SELECT', 'agent_bus.north_star_versions:INSERT', 'agent_bus.goals:SELECT', 'agent_bus.goals:INSERT', 'agent_bus.operational_state:SELECT']$q$);
  d := replace(d, $q$ARRAY['agent_bus.messages_id_seq', 'agent_bus.wake_queue_id_seq']$q$,
                  $q$ARRAY['agent_bus.messages_id_seq', 'agent_bus.wake_queue_id_seq', 'agent_bus.north_star_versions_version_seq', 'agent_bus.goals_version_seq']$q$);
  d := replace(d, $q$('public.muster_lock_claim(p_claim_id uuid)', 'public.aurora_check_gold_branch_expectations(target_gold_object text)')$q$,
                  $q$('public.muster_lock_claim(p_claim_id uuid)', 'public.aurora_check_gold_branch_expectations(target_gold_object text)', 'agent_bus.muster_assert_writable()')$q$);
  d := replace(d, $q$    v := v || 'prohibited create on database'::TEXT;
  END IF;
  RETURN v;$q$,
                  $q$    v := v || 'prohibited create on database'::TEXT;
  END IF;
  IF NOT has_function_privilege(p_role, 'agent_bus.muster_assert_writable()', 'EXECUTE') THEN
    v := v || ('missing agent_bus.muster_assert_writable():EXECUTE'::TEXT);
  END IF;
  IF has_function_privilege(p_role, 'agent_bus.muster_principal_revoke(text, text)', 'EXECUTE') THEN
    v := v || ('prohibited agent_bus.muster_principal_revoke(text, text):EXECUTE'::TEXT);
  END IF;
  IF has_function_privilege(p_role, 'agent_bus.muster_principal_enroll(text, text, text, integer, boolean)', 'EXECUTE') THEN
    v := v || ('prohibited agent_bus.muster_principal_enroll(text, text, text, integer, boolean):EXECUTE'::TEXT);
  END IF;
  IF has_function_privilege(p_role, 'agent_bus.muster_break_glass(text)', 'EXECUTE') THEN
    v := v || ('prohibited agent_bus.muster_break_glass(text):EXECUTE'::TEXT);
  END IF;
  IF has_function_privilege(p_role, 'agent_bus.muster_recover_writes(text)', 'EXECUTE') THEN
    v := v || ('prohibited agent_bus.muster_recover_writes(text):EXECUTE'::TEXT);
  END IF;
  IF has_any_column_privilege(p_role, 'agent_bus.operational_state', 'INSERT') THEN
    v := v || ('prohibited agent_bus.operational_state:INSERT'::TEXT);
  END IF;
  IF has_any_column_privilege(p_role, 'agent_bus.operational_state', 'UPDATE') THEN
    v := v || ('prohibited agent_bus.operational_state:UPDATE'::TEXT);
  END IF;
  IF has_table_privilege(p_role, 'agent_bus.principal_keys', 'DELETE')
     OR has_table_privilege(p_role, 'agent_bus.issued_tokens', 'DELETE')
     OR has_table_privilege(p_role, 'agent_bus.launch_grants', 'DELETE') THEN
    v := v || ('prohibited direct credential-table delete'::TEXT);
  END IF;
  RETURN v;$q$);
  EXECUTE d;
END $$;

GRANT SELECT, INSERT ON agent_bus.north_star_versions, agent_bus.goals TO muster_api;
GRANT SELECT ON agent_bus.operational_state TO muster_api;
GRANT UPDATE (initiative_tier, updated_at) ON agent_bus.registry_entries TO muster_api;
GRANT USAGE ON SEQUENCE agent_bus.north_star_versions_version_seq, agent_bus.goals_version_seq TO muster_api;
GRANT USAGE ON SCHEMA agent_bus TO muster_admin;

DO $$
DECLARE violations text[];
BEGIN
  SELECT agent_bus.muster_api_privilege_violations('muster_api') INTO violations;
  IF cardinality(violations) > 0 THEN
    RAISE EXCEPTION 'OB-60221 muster_api privileges did not verify: %', array_to_string(violations, '; ');
  END IF;
END $$;

DO $$
DECLARE
  held text[];
BEGIN
  SELECT coalesce(array_agg(n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' ORDER BY p.proname), '{}')
    INTO held
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE p.prosecdef AND n.nspname = 'agent_bus'
     AND has_function_privilege('muster_admin', p.oid, 'EXECUTE');
  IF held IS DISTINCT FROM ARRAY[
    'agent_bus.muster_break_glass(p_reason text)',
    'agent_bus.muster_principal_enroll(p_agent_id text, p_public_key text, p_key_hash text, p_days integer, p_rotate boolean)',
    'agent_bus.muster_principal_revoke(p_agent_id text, p_reason text)',
    'agent_bus.muster_recover_writes(p_reason text)'
  ] THEN
    RAISE EXCEPTION 'OB-60221 muster_admin EXECUTE grants did not verify: %', array_to_string(held, '; ');
  END IF;
END $$;

INSERT INTO aurora_data_objects (object_name, layer, object_kind, canonical_name, source_key, domain, lifecycle_state, notes)
VALUES
 ('agent_bus.north_star_versions','registry','table','agent_bus.north_star_versions','agent_bus','coordination','active','Append-only shared Muster mission history.'),
 ('agent_bus.goals','registry','table','agent_bus.goals','agent_bus','coordination','active','Append-only ordered Muster goal history.'),
 ('agent_bus.operational_state','registry','table','agent_bus.operational_state','agent_bus','coordination','active','Singleton break-glass read-only flag.')
ON CONFLICT (object_name) DO UPDATE SET notes=EXCLUDED.notes, lifecycle_state='active';
INSERT INTO aurora_data_object_consumers (object_name,column_name,consumer_kind,consumer_name,access_kind,evidence,lifecycle_state)
VALUES
 ('agent_bus.north_star_versions','*','api_route','muster-api','reads','OB-60221 GET /v1/north-star and history.','active'),
 ('agent_bus.north_star_versions','*','api_route','muster-api','writes','OB-60221 POST /v1/north-star/mission appends a version.','active'),
 ('agent_bus.north_star_versions','*','mcp_tool','muster_north_star_get','reads','OB-60221 MCP management client.','active'),
 ('agent_bus.goals','*','api_route','muster-api','reads','OB-60221 GET /v1/north-star and history.','active'),
 ('agent_bus.goals','*','api_route','muster-api','writes','OB-60221 goal upserts append versions.','active'),
 ('agent_bus.goals','*','mcp_tool','muster_goal_upsert','writes','OB-60221 MCP management client.','active'),
 ('agent_bus.operational_state','*','api_route','muster-api','reads','OB-60221 mutating routes check the durable read-only flag.','active'),
 ('agent_bus.operational_state','*','script','agent_bus.muster_assert_writable','reads','OB-60221 mutating transactions take FOR SHARE on the freeze flag.','active'),
 ('agent_bus.operational_state','*','script','agent_bus.muster_break_glass','writes','OB-60221 break-glass sets the durable read-only flag.','active'),
 ('agent_bus.operational_state','*','script','agent_bus.muster_recover_writes','writes','OB-60221 recovery clears the durable read-only flag.','active')
ON CONFLICT (object_name,column_name,consumer_kind,consumer_name,access_kind) DO UPDATE SET evidence=EXCLUDED.evidence,lifecycle_state='active',updated_at=now();
INSERT INTO nexus_schema_version(version,description) VALUES (1895,'OB-60221 Muster North Star, break-glass freeze, and principal-admin SECURITY DEFINER') ON CONFLICT (version) DO NOTHING;
UPDATE migration_registry SET status='applied', applied_at=now() WHERE version=1895 AND slug='ob60221-muster-management' AND status='reserved';
COMMIT;
