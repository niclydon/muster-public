-- Migration number 1898 RESERVED via migration_registry (slug ob60221-north-star-audit-event).
-- OB-60221 acceptance 2: a refused North Star (mission or goal) edit must be audited.
-- muster-api appends principal_audit_events rows with event_type 'north_star_edit_rejected';
-- the 1895 CHECK constraint enumerates event types, so it is widened here (append-only table,
-- no grant changes: muster_api already holds INSERT on principal_audit_events from 1889).
BEGIN;
SET LOCAL lock_timeout = '5s';
ALTER TABLE agent_bus.principal_audit_events DROP CONSTRAINT IF EXISTS principal_audit_events_event_type_check;
ALTER TABLE agent_bus.principal_audit_events
  ADD CONSTRAINT principal_audit_events_event_type_check CHECK (event_type IN (
    'key_issued', 'key_rotated', 'key_revoked', 'token_issued', 'token_revoked',
    'registration_requested', 'registration_approved', 'registration_rejected',
    'registration_consumed', 'session_superseded', 'launch_granted', 'launch_grant_revoked',
    'break_glass', 'writes_recovered', 'north_star_edit_rejected'));
INSERT INTO aurora_data_object_consumers (object_name,column_name,consumer_kind,consumer_name,access_kind,evidence,lifecycle_state) VALUES
 ('agent_bus.principal_audit_events','event_type','api_route','muster-api','writes','OB-60221 refused North Star edits append north_star_edit_rejected (acceptance 2).','active')
ON CONFLICT (object_name,column_name,consumer_kind,consumer_name,access_kind) DO UPDATE SET evidence=EXCLUDED.evidence,lifecycle_state='active',updated_at=now();
INSERT INTO nexus_schema_version(version,description) VALUES (1898,'OB-60221 north_star_edit_rejected audit event type') ON CONFLICT (version) DO NOTHING;
UPDATE migration_registry SET status='applied', applied_at=now() WHERE version=1898 AND slug='ob60221-north-star-audit-event' AND status='reserved';
COMMIT;
