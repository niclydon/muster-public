-- Migration number 1892 RESERVED via migration_registry
-- (slug 'ob60178-muster-stream-grants', reserved_by claude_code:interactive:herdr-w2). Do not renumber.
--
-- OB-60178: Muster slice 1 stream and conditions API privileges
-- (docs/projects/2026-09-14-muster-design.md sections 4.2, 4.3, 8, 20.2, 20.4).
--   * message_envelopes gains work_ref: design 4.3 carries a work_ref on every message.
--   * muster_api gains exactly what POST/GET /v1/messages, POST /v1/deliveries/{id}/ack, mailbox
--     inheritance, and GET/POST /v1/conditions use. agent_bus.messages stays INSERT and SELECT only:
--     no UPDATE, DELETE, TRUNCATE, TRIGGER, or REFERENCES.
--   * The legacy agent_bus.enqueue_message_wake trigger on messages is not SECURITY DEFINER, so an insert
--     by muster_api writes agent_bus.wake_queue as muster_api. muster_api gets INSERT on exactly the two
--     columns the trigger writes, and nothing else on wake_queue.
--   * agent_bus.muster_api_privilege_violations(role) is replaced with the widened allowlist, and the grant
--     block verifies against it and aborts on any violation (OB-60176 XD-01 pattern).
-- Additive: no existing grant is removed or widened beyond the listed tables and columns.

BEGIN;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muster_api') THEN
    RAISE EXCEPTION 'OB-60178: muster_api role is missing; migration 1889 must be applied first';
  END IF;
  IF to_regprocedure('agent_bus.muster_api_privilege_violations(text)') IS NULL THEN
    RAISE EXCEPTION 'OB-60178: agent_bus.muster_api_privilege_violations is missing; migration 1889 must be applied first';
  END IF;
END;
$$;

ALTER TABLE agent_bus.message_envelopes
  ADD COLUMN IF NOT EXISTS work_ref TEXT CHECK (work_ref IS NULL OR length(btrim(work_ref)) BETWEEN 1 AND 200);

COMMENT ON COLUMN agent_bus.message_envelopes.work_ref IS 'OB-60178: opaque typed work reference carried by the message (design 4.3), e.g. OB-60178.';

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
  -- OB-60178 stream and conditions surface.
  stream_tables CONSTANT TEXT[] := ARRAY[
    'agent_bus.messages', 'agent_bus.message_envelopes', 'agent_bus.message_routes', 'agent_bus.deliveries',
    'agent_bus.delivery_outbox', 'agent_bus.role_mailbox', 'agent_bus.conditions', 'agent_bus.wake_queue'];
  allowed_sequences CONSTANT TEXT[] := ARRAY[
    'agent_bus.messages_id_seq', 'agent_bus.wake_queue_id_seq', 'agent_bus.message_routes_route_id_seq',
    'agent_bus.role_mailbox_mailbox_id_seq'];
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
    'agent_bus.launch_grants:SELECT', 'agent_bus.launch_grants:INSERT', 'agent_bus.principal_audit_events:INSERT',
    'agent_bus.message_envelopes:SELECT', 'agent_bus.message_envelopes:INSERT',
    'agent_bus.message_routes:SELECT', 'agent_bus.message_routes:INSERT',
    'agent_bus.deliveries:SELECT', 'agent_bus.deliveries:INSERT',
    'agent_bus.delivery_outbox:SELECT', 'agent_bus.delivery_outbox:INSERT',
    'agent_bus.role_mailbox:SELECT', 'agent_bus.role_mailbox:INSERT',
    'agent_bus.conditions:SELECT', 'agent_bus.conditions:INSERT']
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
    'public.operator_backlog_claims:claimed_at:SELECT',
    'agent_bus.messages:id:SELECT', 'agent_bus.messages:body:SELECT', 'agent_bus.messages:body:INSERT',
    'agent_bus.messages:author:INSERT', 'agent_bus.wake_queue:message_id:INSERT',
    'agent_bus.wake_queue:recipients:INSERT', 'agent_bus.deliveries:state:UPDATE',
    'agent_bus.deliveries:acked_at:UPDATE', 'agent_bus.role_mailbox:inherited_at:UPDATE',
    'agent_bus.conditions:cleared_at:UPDATE']
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
  FOREACH item IN ARRAY ARRAY['agent_bus.messages_id_seq', 'agent_bus.wake_queue_id_seq'] LOOP
    IF NOT has_sequence_privilege(p_role, item, 'USAGE') THEN
      v := v || ('missing ' || item || ':USAGE');
    END IF;
  END LOOP;

  -- Column-grantable privileges are checked with has_any_column_privilege, which also sees table-level grants.
  FOREACH item IN ARRAY ARRAY[
    'agent_bus.messages:UPDATE', 'agent_bus.messages:REFERENCES',
    'agent_bus.wake_queue:SELECT', 'agent_bus.wake_queue:UPDATE', 'agent_bus.wake_queue:REFERENCES',
    'agent_bus.message_envelopes:UPDATE', 'agent_bus.message_routes:UPDATE', 'agent_bus.delivery_outbox:UPDATE',
    'public.operator_backlog_claims:INSERT', 'public.operator_backlog_claims:UPDATE',
    'public.operator_backlog_claims:REFERENCES',
    'agent_bus.principal_audit_events:SELECT', 'agent_bus.principal_audit_events:UPDATE']
  LOOP
    IF has_any_column_privilege(p_role, split_part(item, ':', 1), split_part(item, ':', 2)) THEN
      v := v || ('prohibited ' || item);
    END IF;
  END LOOP;

  -- Identity and routing columns stay immutable to the API even where the row is updatable.
  FOREACH item IN ARRAY ARRAY[
    'agent_bus.messages:author:SELECT:allowed', 'agent_bus.deliveries:recipient_agent_id:UPDATE',
    'agent_bus.deliveries:route_id:UPDATE', 'agent_bus.deliveries:message_id:UPDATE',
    'agent_bus.deliveries:adapter:UPDATE', 'agent_bus.deliveries:resolution_generation:UPDATE',
    'agent_bus.role_mailbox:route_id:UPDATE', 'agent_bus.role_mailbox:target_role:UPDATE',
    'agent_bus.role_mailbox:message_id:UPDATE', 'agent_bus.conditions:scope:UPDATE',
    'agent_bus.conditions:effect:UPDATE', 'agent_bus.conditions:ends_at:UPDATE',
    'agent_bus.conditions:owner_agent_id:UPDATE', 'agent_bus.conditions:renews_condition_id:UPDATE']
  LOOP
    CONTINUE WHEN split_part(item, ':', 4) = 'allowed';
    IF has_column_privilege(p_role, split_part(item, ':', 1), split_part(item, ':', 2), split_part(item, ':', 3)) THEN
      v := v || ('prohibited ' || item);
    END IF;
  END LOOP;

  FOREACH item IN ARRAY ARRAY['public.operator_backlog_claims'] || identity_tables || stream_tables
  LOOP
    IF has_table_privilege(p_role, item, 'DELETE') THEN v := v || ('prohibited ' || item || ':DELETE'); END IF;
    IF has_table_privilege(p_role, item, 'TRUNCATE') THEN v := v || ('prohibited ' || item || ':TRUNCATE'); END IF;
    IF has_table_privilege(p_role, item, 'TRIGGER') THEN v := v || ('prohibited ' || item || ':TRIGGER'); END IF;
  END LOOP;
  FOREACH item IN ARRAY identity_tables || stream_tables
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
    CONTINUE WHEN obj.name = ANY (identity_tables || stream_tables) OR obj.name = 'public.operator_backlog_claims';
    IF has_any_column_privilege(p_role, obj.oid, 'SELECT') OR has_any_column_privilege(p_role, obj.oid, 'INSERT')
       OR has_any_column_privilege(p_role, obj.oid, 'UPDATE') OR has_any_column_privilege(p_role, obj.oid, 'REFERENCES')
       OR has_table_privilege(p_role, obj.oid, 'DELETE') OR has_table_privilege(p_role, obj.oid, 'TRUNCATE')
       OR has_table_privilege(p_role, obj.oid, 'TRIGGER') THEN
      v := v || ('prohibited access to ' || obj.name);
    END IF;
  END LOOP;

  -- Sequences: USAGE (nextval) only, and only on the allowlisted ones.
  FOR obj IN
    SELECT c.oid, n.nspname || '.' || c.relname AS name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  LOOP
    IF obj.oid = to_regclass(pg_get_serial_sequence('agent_bus.principal_audit_events', 'event_id'))
       OR obj.name = ANY (allowed_sequences) THEN
      IF has_sequence_privilege(p_role, obj.oid, 'SELECT') OR has_sequence_privilege(p_role, obj.oid, 'UPDATE') THEN
        v := v || ('prohibited select or update on sequence ' || obj.name);
      END IF;
      CONTINUE;
    END IF;
    IF has_sequence_privilege(p_role, obj.oid, 'USAGE') OR has_sequence_privilege(p_role, obj.oid, 'SELECT')
       OR has_sequence_privilege(p_role, obj.oid, 'UPDATE') THEN
      v := v || ('prohibited access to sequence ' || obj.name);
    END IF;
  END LOOP;

  -- Ordinary functions run with the caller's privileges and cannot exceed the grants checked above.
  -- SECURITY DEFINER functions run as their owner, so any executable one is a boundary crossing unless
  -- allowlisted. Trigger functions cannot be called directly. Allowlist:
  --   muster_lock_claim: migration 1889's claim lock.
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

REVOKE ALL ON FUNCTION agent_bus.muster_api_privilege_violations(TEXT) FROM PUBLIC;

DO $$
DECLARE
  violations TEXT[];
BEGIN
  GRANT SELECT (id, ts, author, recipient, msg_type, task, body, in_reply_to),
        INSERT (author, recipient, msg_type, task, body, in_reply_to)
    ON agent_bus.messages TO muster_api;
  GRANT USAGE ON SEQUENCE agent_bus.messages_id_seq TO muster_api;
  -- The legacy wake trigger writes these two columns as the inserting role.
  GRANT INSERT (message_id, recipients) ON agent_bus.wake_queue TO muster_api;
  GRANT USAGE ON SEQUENCE agent_bus.wake_queue_id_seq TO muster_api;

  GRANT SELECT, INSERT ON agent_bus.message_envelopes TO muster_api;
  GRANT SELECT, INSERT ON agent_bus.message_routes TO muster_api;
  GRANT USAGE ON SEQUENCE agent_bus.message_routes_route_id_seq TO muster_api;
  GRANT SELECT, INSERT ON agent_bus.deliveries TO muster_api;
  GRANT UPDATE (state, version, delivered_at, acked_at, adapter_ref) ON agent_bus.deliveries TO muster_api;
  GRANT SELECT, INSERT ON agent_bus.delivery_outbox TO muster_api;
  GRANT SELECT, INSERT ON agent_bus.role_mailbox TO muster_api;
  GRANT UPDATE (inherited_by_agent_id, inherited_at) ON agent_bus.role_mailbox TO muster_api;
  GRANT USAGE ON SEQUENCE agent_bus.role_mailbox_mailbox_id_seq TO muster_api;
  GRANT SELECT, INSERT ON agent_bus.conditions TO muster_api;
  GRANT UPDATE (cleared_by, cleared_at, version) ON agent_bus.conditions TO muster_api;

  violations := agent_bus.muster_api_privilege_violations('muster_api');
  IF cardinality(violations) > 0 THEN
    RAISE EXCEPTION 'OB-60178: muster_api privileges did not verify: %', array_to_string(violations, '; ');
  END IF;
END;
$$;

-- Lineage: the legacy bus objects are registered in production already; register them only if absent
-- (never overwriting their existing metadata) so consumer rows can reference them.
INSERT INTO aurora_data_objects
  (object_name, layer, object_kind, canonical_name, source_key, domain, lifecycle_state, notes)
VALUES
  ('agent_bus.messages', 'registry', 'table', 'agent_bus.messages', 'agent_bus', 'coordination', 'active', 'CoS bus messages; Muster stream reference storage (design 12).'),
  ('agent_bus.wake_queue', 'registry', 'table', 'agent_bus.wake_queue', 'agent_bus', 'coordination', 'active', 'CoS bus wake hints enqueued by agent_bus.enqueue_message_wake.')
ON CONFLICT (object_name) DO NOTHING;

INSERT INTO aurora_data_object_consumers
  (object_name, column_name, consumer_kind, consumer_name, access_kind, evidence, lifecycle_state)
VALUES
  ('agent_bus.role_mailbox', '*', 'worker_handler', 'log-monitor.checkMusterRoleMailbox', 'reads', 'OB-60178 raises the unassigned-role mailbox platform alarm from waiting rows.', 'active'),
  ('agent_bus.role_mailbox', 'alarm_last_fired_at', 'worker_handler', 'log-monitor.checkMusterRoleMailbox', 'writes', 'OB-60178 stamps when the mailbox alarm last fired (re-fire every 2 hours).', 'active'),
  ('agent_bus.role_mailbox', '*', 'worker_handler', 'log-monitor.resolveRecoveredPositiveEvidenceAlerts', 'reads', 'OB-60178 closes a mailbox alarm only on a read showing that role''s mailbox empty.', 'active'),
  ('agent_bus.messages', '*', 'api_route', 'muster-api', 'reads', 'OB-60178 GET /v1/messages reads messages delivered to the caller; replies read the parent thread.', 'active'),
  ('agent_bus.messages', '*', 'api_route', 'muster-api', 'writes', 'OB-60178 POST /v1/messages and owner-fallback flags insert stream messages (INSERT only).', 'active'),
  ('agent_bus.wake_queue', 'message_id', 'api_route', 'muster-api', 'writes', 'OB-60178 inserts into agent_bus.messages fire enqueue_message_wake as muster_api.', 'active'),
  ('agent_bus.wake_queue', 'recipients', 'api_route', 'muster-api', 'writes', 'OB-60178 inserts into agent_bus.messages fire enqueue_message_wake as muster_api.', 'active'),
  ('agent_bus.message_envelopes', 'work_ref', 'migration', 'ob60178-muster-stream-grants', 'writes', 'OB-60178 adds the work_ref column.', 'active'),
  ('agent_bus.message_envelopes', 'work_ref', 'api_route', 'muster-api', 'writes', 'OB-60178 stores the message work_ref.', 'active')
ON CONFLICT (object_name, column_name, consumer_kind, consumer_name, access_kind)
DO UPDATE SET evidence = EXCLUDED.evidence, lifecycle_state = 'active', updated_at = now();

INSERT INTO nexus_schema_version (version, description)
VALUES (1892, 'OB-60178 Muster stream and conditions API: message_envelopes.work_ref and muster_api stream grants')
ON CONFLICT (version) DO NOTHING;

UPDATE migration_registry
   SET status = 'applied', applied_at = now()
 WHERE version = 1892
   AND slug = 'ob60178-muster-stream-grants'
   AND status = 'reserved';

COMMIT;
