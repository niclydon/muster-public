-- Migration number 1897 RESERVED via migration_registry
-- (slug 'ob60179-muster-ops-baseline', OB-60179).
-- Do not renumber.
--
-- OB-60179: Muster slice 1 operations baseline (design 20.4, 20.5).
--   * nexus-health-watchdog HTTP target on the Tailnet /health listener
--     (public edition: the production bind address is generalized).
--   * service_channel_map prefix 'muster-' → #platform, so a stopped unit
--     alarms on the platform lane. First-DOWN is not page-worthy; hold-off
--     is 4 hours (the declared RTO) before #alerts.
--   * platform_muster_slis: one-row SLI view with defined windows.
--   * Shared fail-closed kill switch (agent_bus.operational_controls) that
--     muster-api and the Nexus delivery adapters both read before claiming work.
-- Additive and reversible. The watchdog re-reads enabled rows every 60s, so
-- the target takes effect without restarting nexus-health-watchdog.

BEGIN;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muster_admin') THEN
    RAISE EXCEPTION 'OB-60179 operator prerequisite: create LOGIN role muster_admin on this cluster and store its credential at vault secret muster/admin-database before applying 1897';
  END IF;
END $$;

INSERT INTO platform_health_targets (
  service,
  display_name,
  check_type,
  endpoint,
  expected,
  timeout_ms,
  severity_on_down,
  alert_after_failures,
  escalation_holdoff_ms,
  enabled
) VALUES (
  'muster-api',
  'Muster API (agent coordination)',
  'http',
  'http://127.0.0.1:7880/health',
  '200',
  5000,
  'warning',
  2,
  14400000,
  true
)
ON CONFLICT (service) DO UPDATE SET
  display_name         = EXCLUDED.display_name,
  check_type           = EXCLUDED.check_type,
  endpoint             = EXCLUDED.endpoint,
  expected             = EXCLUDED.expected,
  timeout_ms           = EXCLUDED.timeout_ms,
  severity_on_down     = EXCLUDED.severity_on_down,
  alert_after_failures = EXCLUDED.alert_after_failures,
  escalation_holdoff_ms = EXCLUDED.escalation_holdoff_ms,
  enabled              = EXCLUDED.enabled,
  updated_at           = now();

UPDATE notification_delivery_methods
   SET config = jsonb_set(
     config,
     '{service_channel_map,muster-}',
     '"1503077948922531860"',
     true
   )
 WHERE channel = 'discord'
   AND is_enabled = true;

-- One-row SLI snapshot. Availability uses watchdog samples; delivery lag and
-- mailbox TTA are from the companion tables; reconciler freshness is the same
-- predicate as log-monitor.checkMusterDeliveryReconciler (OB-60181): quiet
-- until deliveries exist, then a completed pass in 15 minutes, independent of
-- /health (design 20.2 / 20.4 / AR S-03). Write p99 is not in this view: the
-- process-local /metrics gauge is not a durable scrape, so that objective is
-- deferred (OA-04).
CREATE OR REPLACE VIEW platform_muster_slis AS
SELECT
  (
    SELECT COALESCE(
      count(*) FILTER (WHERE status = 'ok')::numeric / NULLIF(count(*), 0),
      1
    )
      FROM platform_health_checks
     WHERE service = 'muster-api'
       AND checked_at > now() - interval '30 days'
  ) AS api_availability_30d,
  (
    SELECT percentile_cont(0.95) WITHIN GROUP (
      ORDER BY EXTRACT(EPOCH FROM (COALESCE(d.delivered_at, now()) - d.created_at))
    )
      FROM agent_bus.deliveries d
     WHERE d.created_at > now() - interval '24 hours'
       AND d.state IN ('pending', 'failed', 'delivered', 'acked')
  ) AS delivery_lag_p95_seconds,
  (
    SELECT max(EXTRACT(EPOCH FROM (now() - enqueued_at)) / 60.0)
      FROM agent_bus.role_mailbox
     WHERE inherited_at IS NULL
  ) AS mailbox_oldest_waiting_minutes,
  (
    SELECT COALESCE(
      max(EXTRACT(EPOCH FROM (alarm_last_fired_at - enqueued_at)) / 60.0)
        FILTER (WHERE alarm_last_fired_at IS NOT NULL),
      0
    )
      FROM agent_bus.role_mailbox
  ) AS mailbox_time_to_alarm_minutes,
  (
    SELECT count(*)::int
      FROM agent_bus.deliveries
     WHERE state = 'dead'
       AND updated_at > now() - interval '24 hours'
  ) AS dead_deliveries_24h,
  (
    SELECT COALESCE((
      SELECT count(*)::int FROM agent_bus.delivery_outbox WHERE claimed_at IS NULL
    ), 0)
  ) AS outbox_unclaimed,
  (
    NOT EXISTS (SELECT 1 FROM agent_bus.deliveries)
    OR EXISTS (
      SELECT 1 FROM agent_bus.reconciler_heartbeats
       WHERE reconciler_agent_id = 'muster-delivery-reconciler'
         AND pass_completed_at IS NOT NULL
         AND pass_completed_at > now() - interval '15 minutes'
    )
  ) AS reconciler_fresh,
  now() AS observed_at;

COMMENT ON VIEW platform_muster_slis IS
  'OB-60179 Muster slice 1 SLIs. api_availability_30d objective 0.995; delivery_lag_p95_seconds objective 60; mailbox_time_to_alarm_minutes objective 5; reconciler_fresh is the same predicate as log-monitor.checkMusterDeliveryReconciler (quiet until deliveries exist, then a pass in 15 min). Write p99 is deferred until a durable scrape exists.';

-- muster_api must not inherit PUBLIC grants on the SLI view or the freeze tables.
-- 1892's catch-all would otherwise fail the wrapped privilege verifier.
DO $$
BEGIN
  REVOKE ALL ON platform_muster_slis FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muster_api') THEN
    REVOKE ALL ON platform_muster_slis FROM muster_api;
  END IF;
END;
$$;

-- Shared fail-closed freeze. muster-api (SELECT) and nexus-worker adapters read this
-- row before claiming work. Toggle is admin-only (no muster_api write grant).
CREATE TABLE IF NOT EXISTS agent_bus.operational_controls (
  control_key TEXT PRIMARY KEY,
  enabled     BOOLEAN NOT NULL,
  reason      TEXT NOT NULL CHECK (length(btrim(reason)) > 0),
  actor       TEXT NOT NULL CHECK (actor IN ('operator', 'platform-ops', 'nic')),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_bus.operational_control_audit (
  audit_id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  control_key        TEXT NOT NULL,
  actor              TEXT NOT NULL CHECK (length(btrim(actor)) > 0),
  reason             TEXT NOT NULL CHECK (length(btrim(reason)) > 0),
  resulting_enabled  BOOLEAN NOT NULL,
  recorded_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS operational_control_audit_append_only ON agent_bus.operational_control_audit;
CREATE TRIGGER operational_control_audit_append_only
  BEFORE UPDATE OR DELETE ON agent_bus.operational_control_audit
  FOR EACH ROW EXECUTE FUNCTION agent_bus.reject_update();

INSERT INTO agent_bus.operational_controls (control_key, enabled, reason, actor)
VALUES ('kill_switch', false, 'slice-1 baseline: switch off', 'operator')
ON CONFLICT (control_key) DO NOTHING;

COMMENT ON TABLE agent_bus.operational_controls IS
  'OB-60179 shared Muster operational freeze. Fail-closed: missing row or a failed read is treated as enabled. muster_api may SELECT only. Toggle is SECURITY DEFINER agent_bus.muster_set_kill_switch, EXECUTE to muster_admin only.';
COMMENT ON TABLE agent_bus.operational_control_audit IS
  'OB-60179 append-only audit of kill-switch enable/disable (actor, reason, timestamp, resulting state).';

-- Actor is an argument supplied by muster-api from the authenticated operator
-- principal. muster_api cannot EXECUTE this function, so SET LOCAL muster.actor
-- (or a forged argument on a muster_api session) cannot toggle the switch.
CREATE OR REPLACE FUNCTION agent_bus.muster_set_kill_switch(
  p_enabled boolean,
  p_reason text,
  p_actor text
)
RETURNS TABLE(enabled boolean, reason text, actor text, updated_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = agent_bus, pg_catalog
AS $$
DECLARE
  trimmed_reason text;
  out_enabled boolean;
  out_reason text;
  out_actor text;
  out_updated_at timestamptz;
BEGIN
  trimmed_reason := btrim(p_reason);
  IF trimmed_reason IS NULL OR length(trimmed_reason) = 0 THEN
    RAISE EXCEPTION 'reason_required';
  END IF;
  IF p_actor IS NULL OR p_actor NOT IN ('operator', 'platform-ops', 'nic') THEN
    RAISE EXCEPTION 'kill_switch_forbidden';
  END IF;

  PERFORM 1 FROM operational_controls WHERE control_key = 'kill_switch' FOR UPDATE;

  UPDATE operational_controls
     SET enabled = p_enabled,
         reason = trimmed_reason,
         actor = p_actor,
         updated_at = now()
   WHERE control_key = 'kill_switch'
   RETURNING operational_controls.enabled, operational_controls.reason, operational_controls.actor, operational_controls.updated_at
     INTO out_enabled, out_reason, out_actor, out_updated_at;

  IF NOT FOUND THEN
    INSERT INTO operational_controls (control_key, enabled, reason, actor)
    VALUES ('kill_switch', p_enabled, trimmed_reason, p_actor)
    RETURNING operational_controls.enabled, operational_controls.reason, operational_controls.actor, operational_controls.updated_at
      INTO out_enabled, out_reason, out_actor, out_updated_at;
  END IF;

  INSERT INTO operational_control_audit (control_key, actor, reason, resulting_enabled)
  VALUES ('kill_switch', p_actor, trimmed_reason, p_enabled);

  enabled := out_enabled;
  reason := out_reason;
  actor := out_actor;
  updated_at := out_updated_at;
  RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION agent_bus.muster_set_kill_switch(boolean, text, text) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muster_api') THEN
    REVOKE ALL ON FUNCTION agent_bus.muster_set_kill_switch(boolean, text, text) FROM muster_api;
  END IF;
END;
$$;
GRANT EXECUTE ON FUNCTION agent_bus.muster_set_kill_switch(boolean, text, text) TO muster_admin;
GRANT USAGE ON SCHEMA agent_bus TO muster_admin;

REVOKE ALL ON TABLE agent_bus.operational_controls, agent_bus.operational_control_audit FROM PUBLIC;
DO $$
BEGIN
  IF to_regclass('agent_bus.operational_control_audit_audit_id_seq') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON SEQUENCE agent_bus.operational_control_audit_audit_id_seq FROM PUBLIC';
  END IF;
END;
$$;

INSERT INTO aurora_data_objects
  (object_name, layer, object_kind, canonical_name, source_key, domain, lifecycle_state, notes)
VALUES
  ('platform_muster_slis', 'analytics', 'view', 'platform_muster_slis', NULL, 'platform', 'active',
   'OB-60179 Muster slice 1 SLI snapshot (availability, delivery lag, mailbox TTA, reconciler freshness). Write p99 deferred.'),
  ('agent_bus.operational_controls', 'registry', 'table', 'agent_bus.operational_controls', 'agent_bus', 'coordination', 'active',
   'OB-60179 shared fail-closed Muster kill switch read by muster-api and nexus delivery adapters.'),
  ('agent_bus.operational_control_audit', 'registry', 'table', 'agent_bus.operational_control_audit', 'agent_bus', 'coordination', 'active',
   'OB-60179 append-only kill-switch audit.')
ON CONFLICT (object_name) DO UPDATE SET
  notes = EXCLUDED.notes, lifecycle_state = 'active', updated_at = now();

-- Pre-existing Nexus objects the consumer rows below reference. Production already
-- has these; the muster test stub only creates the tables.
INSERT INTO aurora_data_objects
  (object_name, layer, object_kind, canonical_name, source_key, domain, lifecycle_state, notes)
VALUES
  ('platform_health_targets', 'registry', 'table', 'platform_health_targets', NULL, 'platform', 'active',
   'Watchdog target registry. OB-60179 adds the muster-api /health row.'),
  ('platform_health_checks', 'registry', 'table', 'platform_health_checks', NULL, 'platform', 'active',
   'Watchdog sample history used by platform_muster_slis availability.'),
  ('notification_delivery_methods', 'registry', 'table', 'notification_delivery_methods', NULL, 'platform', 'active',
   'Discord service_channel_map. OB-60179 maps the muster- prefix to #platform.')
ON CONFLICT (object_name) DO NOTHING;

INSERT INTO aurora_data_object_consumers
  (object_name, column_name, consumer_kind, consumer_name, access_kind, evidence, lifecycle_state)
VALUES
  ('platform_health_targets', '*', 'migration', '1897-ob60179-muster-ops-baseline', 'writes',
   'OB-60179 registers muster-api HTTP /health as a warning watchdog target on the Tailnet listener.', 'active'),
  ('platform_health_checks', '*', 'database_registry', 'platform_muster_slis', 'reads',
   'OB-60179 30-day API availability SLI from watchdog samples.', 'active'),
  ('notification_delivery_methods', '*', 'migration', '1897-ob60179-muster-ops-baseline', 'writes',
   'OB-60179 maps muster- watchdog alerts to #platform.', 'active'),
  ('agent_bus.deliveries', '*', 'database_registry', 'platform_muster_slis', 'reads',
   'OB-60179 delivery lag p95 and dead-delivery count.', 'active'),
  ('agent_bus.delivery_outbox', '*', 'database_registry', 'platform_muster_slis', 'reads',
   'OB-60179 overload SLI (unclaimed outbox depth).', 'active'),
  ('agent_bus.role_mailbox', '*', 'database_registry', 'platform_muster_slis', 'reads',
   'OB-60179 mailbox time-to-alarm SLI.', 'active'),
  ('agent_bus.reconciler_heartbeats', '*', 'database_registry', 'platform_muster_slis', 'reads',
   'OB-60179 reconciler freshness, same predicate as log-monitor.checkMusterDeliveryReconciler.', 'active'),
  ('agent_bus.reconciler_heartbeats', '*', 'worker_handler', 'log-monitor.checkMusterDeliveryReconciler', 'reads',
   'OB-60181/OB-60179: alarms after 15 min once deliveries exist; no idle false positive. Referenced by the ops runbook instead of a second check.', 'active'),
  ('agent_bus.operational_controls', '*', 'api_route', 'muster-api', 'reads',
   'OB-60179 API reads the shared kill switch before mutating routes (fail-closed).', 'active'),
  ('agent_bus.operational_controls', '*', 'api_route', 'muster-api', 'writes',
   'OB-60179 operator POST /v1/admin/kill-switch calls SECURITY DEFINER agent_bus.muster_set_kill_switch as muster_admin. Actor is the authenticated principal.', 'active'),
  ('agent_bus.operational_controls', '*', 'worker_handler', 'muster-nexus-bridge', 'reads',
   'OB-60179 inbox adapter and delivery reconciler read the shared kill switch before claiming work.', 'active'),
  ('agent_bus.operational_control_audit', '*', 'api_route', 'muster-api', 'writes',
   'OB-60179 append-only audit written by agent_bus.muster_set_kill_switch (actor, reason, timestamp, resulting state).', 'active'),
  ('agent_bus.token_revocations', '*', 'worker_handler', 'log-monitor.checkMusterTokenStore', 'reads',
   'OB-60179 token-failure alarm probes the revocation store the API checks on every request.', 'active'),
  ('agent_bus.deliveries', '*', 'worker_handler', 'log-monitor.checkMusterDeliveryLag', 'reads',
   'OB-60179 delivery-lag alarm (pending/failed older than 60s).', 'active'),
  ('agent_bus.deliveries', '*', 'worker_handler', 'log-monitor.checkMusterDeadDeliveries', 'reads',
   'OB-60179 dead-delivery alarm.', 'active'),
  ('agent_bus.delivery_outbox', '*', 'worker_handler', 'log-monitor.checkMusterOverload', 'reads',
   'OB-60179 overload alarm when the outbox is at capacity.', 'active'),
  ('agent_bus.role_mailbox', '*', 'worker_handler', 'log-monitor.checkMusterOverload', 'reads',
   'OB-60179 overload alarm when a role mailbox is at capacity.', 'active'),
  ('platform_muster_slis', '*', 'doc', 'docs/runbooks/muster.md', 'reads',
   'OB-60179 runbook SLI queries.', 'active')
ON CONFLICT (object_name, column_name, consumer_kind, consumer_name, access_kind)
DO UPDATE SET evidence = EXCLUDED.evidence, lifecycle_state = 'active', updated_at = now();

DO $$
BEGIN
  IF to_regprocedure('agent_bus.muster_api_privilege_violations(text)') IS NOT NULL
     AND to_regprocedure('agent_bus.muster_api_privilege_violations_1896(text)') IS NULL THEN
    ALTER FUNCTION agent_bus.muster_api_privilege_violations(TEXT)
      RENAME TO muster_api_privilege_violations_1896;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION agent_bus.muster_api_privilege_violations(p_role TEXT)
RETURNS TEXT[]
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v TEXT[] := '{}';
  item TEXT;
BEGIN
  IF to_regprocedure('agent_bus.muster_api_privilege_violations_1896(text)') IS NOT NULL THEN
    v := agent_bus.muster_api_privilege_violations_1896(p_role);
  ELSIF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = p_role) THEN
    RETURN ARRAY[format('role %s does not exist', p_role)];
  END IF;
  v := array_remove(v, 'prohibited access to agent_bus.operational_controls');
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = p_role) THEN
    IF NOT has_table_privilege(p_role, 'agent_bus.operational_controls', 'SELECT') THEN
      v := array_append(v, 'missing agent_bus.operational_controls:SELECT');
    END IF;
    FOREACH item IN ARRAY ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER']
    LOOP
      IF has_table_privilege(p_role, 'agent_bus.operational_controls', item) THEN
        v := array_append(v, 'prohibited agent_bus.operational_controls:' || item);
      END IF;
      IF has_table_privilege(p_role, 'agent_bus.operational_control_audit', item) THEN
        v := array_append(v, 'prohibited agent_bus.operational_control_audit:' || item);
      END IF;
    END LOOP;
    IF has_any_column_privilege(p_role, 'agent_bus.operational_control_audit', 'SELECT') THEN
      v := array_append(v, 'prohibited agent_bus.operational_control_audit:SELECT');
    END IF;
    IF has_function_privilege(p_role, 'agent_bus.muster_set_kill_switch(boolean, text, text)', 'EXECUTE') THEN
      v := array_append(v, 'prohibited agent_bus.muster_set_kill_switch(boolean, text, text):EXECUTE');
    END IF;
  END IF;
  RETURN v;
END;
$fn$;

REVOKE ALL ON FUNCTION agent_bus.muster_api_privilege_violations(TEXT) FROM PUBLIC;

DO $$
DECLARE
  violations TEXT[];
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muster_api') THEN
    RETURN;
  END IF;
  GRANT SELECT ON agent_bus.operational_controls TO muster_api;
  IF has_function_privilege('muster_api', 'agent_bus.muster_set_kill_switch(boolean, text, text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'OB-60179: muster_api must not EXECUTE agent_bus.muster_set_kill_switch';
  END IF;
  IF NOT has_function_privilege('muster_admin', 'agent_bus.muster_set_kill_switch(boolean, text, text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'OB-60179: muster_admin must EXECUTE agent_bus.muster_set_kill_switch';
  END IF;
  IF to_regprocedure('agent_bus.muster_api_privilege_violations_1896(text)') IS NULL THEN
    RETURN;
  END IF;
  violations := agent_bus.muster_api_privilege_violations('muster_api');
  IF cardinality(violations) > 0 THEN
    RAISE EXCEPTION 'OB-60179: muster_api privileges did not verify: %', array_to_string(violations, '; ');
  END IF;
END;
$$;

INSERT INTO nexus_schema_version (version, description)
VALUES (
  1897,
  'OB-60179: Muster ops baseline — watchdog, SLIs, shared kill switch, operator-only SECURITY DEFINER toggle'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;

-- Rollback:
--   DELETE FROM platform_health_targets WHERE service = 'muster-api';
--   UPDATE notification_delivery_methods
--      SET config = config #- '{service_channel_map,muster-}'
--    WHERE channel = 'discord';
--   DROP VIEW IF EXISTS platform_muster_slis;
--   DROP FUNCTION IF EXISTS agent_bus.muster_set_kill_switch(boolean, text, text);
--   DROP TABLE IF EXISTS agent_bus.operational_control_audit;
--   DROP TABLE IF EXISTS agent_bus.operational_controls;
--   DELETE FROM aurora_data_object_consumers
--    WHERE consumer_name IN (
--      '1897-ob60179-muster-ops-baseline',
--      'platform_muster_slis',
--      'log-monitor.checkMusterTokenStore',
--      'log-monitor.checkMusterDeliveryLag',
--      'log-monitor.checkMusterDeadDeliveries',
--      'log-monitor.checkMusterOverload',
--      'docs/runbooks/muster.md'
--    )
--       OR object_name IN ('agent_bus.operational_controls', 'agent_bus.operational_control_audit');
--   DELETE FROM aurora_data_objects
--    WHERE object_name IN (
--      'platform_muster_slis',
--      'agent_bus.operational_controls',
--      'agent_bus.operational_control_audit'
--    );
--   DELETE FROM nexus_schema_version WHERE version = 1897;
