-- Verbatim copy of Nexus migration 1896-ob60180-muster-operator-interactive-registration.sql.
ALTER FUNCTION agent_bus.muster_api_privilege_violations(TEXT)
  RENAME TO muster_api_privilege_violations_1892;

CREATE FUNCTION agent_bus.muster_api_privilege_violations(p_role TEXT)
RETURNS TEXT[]
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v TEXT[] := agent_bus.muster_api_privilege_violations_1892(p_role);
  column_name TEXT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = p_role) THEN
    RETURN v;
  END IF;
  FOR column_name IN
    SELECT a.attname
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'agent_bus' AND c.relname = 'registration_requests'
       AND a.attnum > 0 AND NOT a.attisdropped
       AND has_column_privilege(p_role, c.oid, a.attname, 'UPDATE')
       AND a.attname NOT IN ('status', 'consumed_at', 'consumed_token_jti', 'approved_at')
  LOOP
    v := array_append(v, format('prohibited agent_bus.registration_requests:%s:UPDATE', column_name));
  END LOOP;
  IF NOT has_column_privilege(p_role, 'agent_bus.registration_requests', 'approved_at', 'UPDATE') THEN
    v := array_append(v, 'missing agent_bus.registration_requests:approved_at:UPDATE');
  END IF;
  RETURN v;
END;
$fn$;

REVOKE ALL ON FUNCTION agent_bus.muster_api_privilege_violations(TEXT) FROM PUBLIC;
GRANT UPDATE (status, approved_at) ON agent_bus.registration_requests TO muster_api;

DO $$
DECLARE violations TEXT[];
BEGIN
  violations := agent_bus.muster_api_privilege_violations('muster_api');
  IF cardinality(violations) > 0 THEN
    RAISE EXCEPTION 'OB-60180: muster_api privileges did not verify: %', array_to_string(violations, '; ');
  END IF;
END;
$$;
