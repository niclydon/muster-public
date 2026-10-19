import type pg from 'pg';
import type { AuthContext } from './identity.js';
import { audit } from './audit.js';
import { MusterError } from './errors.js';
import { withWritableTransaction } from './db.js';

/** OB-60221 acceptance 2: a refused mission or goal edit is audited before the 403 is returned. */
async function rejectNorthStarEdit(pool: pg.Pool, auth: AuthContext, resource: 'mission' | 'goal', domain?: string): Promise<never> {
  await audit(pool, {
    eventType: 'north_star_edit_rejected',
    agentId: auth.agentId,
    actor: auth.agentId,
    sessionId: auth.sessionId ?? null,
    detail: { resource, domain: domain ?? null, roles: auth.principal.roles, persistence_class: auth.persistenceClass },
  });
  throw new MusterError(403, 'north_star_edit_forbidden');
}

type GoalInput = { title: string; detail?: string; domain: string; position: number };

export function canEditNorthStar(auth: Pick<AuthContext, 'persistenceClass' | 'principal' | 'agentId'>, resource: 'mission' | 'goal', domain?: string): boolean {
  if (auth.principal.roles.includes('operator') || auth.persistenceClass === 'operator_interactive') return true;
  return resource === 'goal' && auth.principal.roles.includes('cos') && typeof domain === 'string';
}

export function normalizeGoal(value: Record<string, unknown>): GoalInput {
  const title = typeof value.title === 'string' ? value.title.trim() : '';
  const detail = typeof value.detail === 'string' ? value.detail.trim() : undefined;
  const domain = typeof value.domain === 'string' ? value.domain.trim() : '';
  const position = value.position;
  if (!title || title.length > 500 || !domain || domain.length > 200 || !Number.isInteger(position) || (position as number) < 0) {
    throw new MusterError(400, 'invalid_goal');
  }
  return detail ? { title, detail, domain, position: position as number } : { title, domain, position: position as number };
}

export async function getNorthStar(pool: pg.Pool): Promise<unknown> {
  const { rows } = await pool.query(`
    SELECT (SELECT row_to_json(m) FROM (SELECT version, mission, updated_by, updated_at FROM agent_bus.north_star_versions ORDER BY version DESC LIMIT 1) m) AS mission,
           COALESCE((SELECT json_agg(g ORDER BY position, goal_id) FROM (
             SELECT DISTINCT ON (goal_id) goal_id, version, title, detail, domain, position, status, updated_by, updated_at
             FROM agent_bus.goals ORDER BY goal_id, version DESC
           ) g WHERE status = 'active'), '[]'::json) AS goals`);
  return rows[0] ?? { mission: null, goals: [] };
}

export async function northStarHistory(pool: pg.Pool): Promise<unknown> {
  // Both arms must be jsonb: a text mission UNIONed with a jsonb goal object is a 42804 datatype mismatch.
  const { rows } = await pool.query(`SELECT 'mission' AS kind, version, to_jsonb(mission) AS value, updated_by, updated_at FROM agent_bus.north_star_versions
    UNION ALL SELECT 'goal', version, jsonb_build_object('goal_id', goal_id, 'title', title, 'detail', detail, 'domain', domain, 'position', position, 'status', status), updated_by, updated_at FROM agent_bus.goals
    ORDER BY updated_at DESC, version DESC`);
  return { history: rows };
}

export async function setMission(pool: pg.Pool, auth: AuthContext, body: Record<string, unknown>): Promise<unknown> {
  if (!canEditNorthStar(auth, 'mission')) await rejectNorthStarEdit(pool, auth, 'mission');
  const mission = typeof body.mission === 'string' ? body.mission.trim() : '';
  if (!mission || mission.length > 10_000) throw new MusterError(400, 'invalid_mission');
  return withWritableTransaction(pool, async (client) => {
    const { rows } = await client.query(`INSERT INTO agent_bus.north_star_versions (mission, updated_by, supersedes)
    SELECT $1, $2, (SELECT version FROM agent_bus.north_star_versions ORDER BY version DESC LIMIT 1)
    RETURNING version, mission, updated_by, updated_at`, [mission, auth.agentId]);
    return rows[0];
  });
}

export async function upsertGoal(pool: pg.Pool, auth: AuthContext, goalId: string | null, body: Record<string, unknown>): Promise<unknown> {
  const goal = normalizeGoal(body);
  if (!canEditNorthStar(auth, 'goal', goal.domain)) await rejectNorthStarEdit(pool, auth, 'goal', goal.domain);
  return withWritableTransaction(pool, async (client) => {
    const { rows } = await client.query(`INSERT INTO agent_bus.goals (goal_id, title, detail, domain, position, status, updated_by, supersedes)
    SELECT COALESCE($1::uuid, gen_random_uuid()), $2, $3, $4, $5, COALESCE($6, 'active'), $7,
           (SELECT version FROM agent_bus.goals WHERE goal_id = $1::uuid ORDER BY version DESC LIMIT 1)
    RETURNING goal_id, version, title, detail, domain, position, status, updated_by, updated_at`,
    [goalId, goal.title, goal.detail ?? null, goal.domain, goal.position, typeof body.status === 'string' ? body.status : null, auth.agentId]);
    return rows[0];
  });
}
