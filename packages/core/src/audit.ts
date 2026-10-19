import type { Queryable } from './binding.js';

export type AuditEventType =
  | 'key_issued'
  | 'key_rotated'
  | 'key_revoked'
  | 'token_issued'
  | 'token_revoked'
  | 'registration_requested'
  | 'registration_approved'
  | 'registration_rejected'
  | 'registration_consumed'
  | 'session_superseded'
  | 'launch_granted'
  | 'launch_grant_revoked'
  | 'break_glass'
  | 'writes_recovered'
  | 'north_star_edit_rejected';

export interface AuditEvent {
  eventType: AuditEventType;
  agentId: string;
  actor: string;
  keyId?: string | null;
  jti?: string | null;
  requestId?: string | null;
  sessionId?: string | null;
  detail?: Record<string, unknown>;
}

/** Appends to agent_bus.principal_audit_events, which rejects UPDATE and DELETE (OB-60175 DT-02). */
export async function audit(client: Queryable, e: AuditEvent): Promise<void> {
  await client.query(
    `INSERT INTO agent_bus.principal_audit_events
       (event_type, agent_id, key_id, jti, request_id, session_id, actor, detail)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [e.eventType, e.agentId, e.keyId ?? null, e.jti ?? null, e.requestId ?? null, e.sessionId ?? null, e.actor, JSON.stringify(e.detail ?? {})],
  );
}
