import { withTransaction, assertWritable } from './db.js';
import { MusterError } from './errors.js';
import type { AuthContext, MusterContext } from './identity.js';
import type { PersistenceClass } from './roles.js';
import { isPrivileged, UUID_PATTERN } from './stream.js';

/**
 * Conditions (design 4.2, AR R-02, OB-60178). A condition is a declared, time-bounded platform fact.
 * Slice 1 accepts only `annotate` effects; `defer`, `suppress`, and `route_to` wait for the slice 2 shared
 * evaluator and are rejected here with a clear error (the database CHECK is the backstop). Windows are
 * server-timed and capped per declarer class; renewals are an immutable chain capped cumulatively per
 * scope, after which the scope's owner must declare afresh.
 */

export const CONDITION_KINDS: readonly string[] = [
  'experiment',
  'maintenance',
  'freeze',
  'incident',
  'blocker',
  'operator_wip',
  'budget_park',
  'quiet_hours',
];
export const MAX_CONDITION_WINDOW_SECONDS: Record<PersistenceClass, number> = {
  persistent: 12 * 3600,
  ephemeral: 2 * 3600,
  // Operator-interactive sessions may declare without a second approver, capped at 4h (design 4.2).
  operator_interactive: 4 * 3600,
};
export const MIN_CONDITION_WINDOW_SECONDS = 60;
export const RENEWAL_CHAIN_CAP_SECONDS = 12 * 3600;
const MAX_SCOPE_BYTES = 4096;
const SLICE2_EFFECTS = new Set(['defer', 'suppress', 'route_to']);
const LABEL = /^[\x20-\x7E]{1,200}$/;
const DECLARE_FIELDS = new Set(['kind', 'scope', 'effect', 'duration_seconds', 'work_ref', 'renews_condition_id']);

const CONDITION_COLUMNS = `condition_id, kind, scope, starts_at, ends_at, owner_agent_id, effect, work_ref,
  renews_condition_id, cleared_by, cleared_at, version, created_at`;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateEffect(ctx: MusterContext, effect: unknown): Record<string, 'annotate'> {
  if (!isPlainObject(effect) || Object.keys(effect).length === 0) throw new MusterError(400, 'invalid_effect');
  for (const [role, value] of Object.entries(effect)) {
    if (!ctx.roles.roles.has(role)) throw new MusterError(400, 'unknown_role');
    if (value === 'annotate') continue;
    const name = typeof value === 'string' ? value : isPlainObject(value) ? Object.keys(value)[0] : undefined;
    if (name && SLICE2_EFFECTS.has(name)) {
      throw new MusterError(400, 'effect_not_supported_in_slice_1', `effect ${name} for role ${role} is not operative until slice 2; only annotate is accepted`);
    }
    throw new MusterError(400, 'invalid_effect');
  }
  return effect as Record<string, 'annotate'>;
}

/** The declarer holds or owns every role the effect names, or holds cos or operator (design 4.2 owner rule). */
function assertAuthority(ctx: MusterContext, auth: AuthContext, roles: string[]): void {
  if (isPrivileged(auth)) return;
  for (const role of roles) {
    const held = auth.principal.roles.includes(role);
    const owned = ctx.roles.roles.get(role)?.owner === auth.agentId;
    if (!held && !owned) throw new MusterError(403, 'no_authority_over_scope');
  }
}

/** POST /v1/conditions. */
export async function declareCondition(ctx: MusterContext, auth: AuthContext, body: Record<string, unknown>): Promise<unknown> {
  for (const key of Object.keys(body)) {
    if (!DECLARE_FIELDS.has(key)) throw new MusterError(400, 'unsupported_field');
  }
  if (typeof body.kind !== 'string' || !CONDITION_KINDS.includes(body.kind)) throw new MusterError(400, 'unknown_kind');
  if (!isPlainObject(body.scope) || Buffer.byteLength(JSON.stringify(body.scope)) > MAX_SCOPE_BYTES) {
    throw new MusterError(400, 'invalid_scope');
  }
  const effect = validateEffect(ctx, body.effect);
  const maxWindow = MAX_CONDITION_WINDOW_SECONDS[auth.persistenceClass];
  const duration = body.duration_seconds;
  if (typeof duration !== 'number' || !Number.isInteger(duration) || duration < MIN_CONDITION_WINDOW_SECONDS || duration > maxWindow) {
    throw new MusterError(400, 'invalid_duration');
  }
  let workRef: string | null = null;
  if (body.work_ref !== undefined && body.work_ref !== null) {
    if (typeof body.work_ref !== 'string' || !LABEL.test(body.work_ref)) throw new MusterError(400, 'invalid_work_ref');
    workRef = body.work_ref;
  }
  let renews: string | null = null;
  if (body.renews_condition_id !== undefined && body.renews_condition_id !== null) {
    if (typeof body.renews_condition_id !== 'string' || !UUID_PATTERN.test(body.renews_condition_id)) {
      throw new MusterError(400, 'invalid_renews_condition_id');
    }
    renews = body.renews_condition_id;
  }
  assertAuthority(ctx, auth, Object.keys(effect));

  const scopeJson = JSON.stringify(body.scope);
  const effectJson = JSON.stringify(effect);
  return withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    if (renews) {
      await client.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [`muster:condition:${renews}`]);
      const { rows } = await client.query<{ owner_agent_id: string; cleared_at: Date | null; same_shape: boolean }>(
        `SELECT owner_agent_id, cleared_at, (kind = $2 AND scope = $3::jsonb AND effect = $4::jsonb) AS same_shape
           FROM agent_bus.conditions WHERE condition_id = $1`,
        [renews, body.kind, scopeJson, effectJson],
      );
      const renewed = rows[0];
      if (!renewed) throw new MusterError(404, 'condition_not_found');
      if (renewed.owner_agent_id !== auth.agentId && !isPrivileged(auth)) throw new MusterError(403, 'not_condition_owner');
      if (renewed.cleared_at) throw new MusterError(409, 'condition_cleared');
      if (!renewed.same_shape) throw new MusterError(409, 'renewal_must_match_kind_scope_effect');
      const { rowCount: renewedAlready } = await client.query(`SELECT 1 FROM agent_bus.conditions WHERE renews_condition_id = $1`, [renews]);
      if (renewedAlready) throw new MusterError(409, 'already_renewed');
      const { rows: chain } = await client.query<{ seconds: number }>(
        `WITH RECURSIVE chain AS (
           SELECT condition_id, renews_condition_id, starts_at, ends_at, 1 AS depth
             FROM agent_bus.conditions WHERE condition_id = $1
           UNION ALL
           SELECT c.condition_id, c.renews_condition_id, c.starts_at, c.ends_at, chain.depth + 1
             FROM agent_bus.conditions c JOIN chain ON c.condition_id = chain.renews_condition_id
            WHERE chain.depth < 1000
         )
         SELECT COALESCE(EXTRACT(EPOCH FROM sum(ends_at - starts_at)), 0)::float8 AS seconds FROM chain`,
        [renews],
      );
      if ((chain[0]?.seconds ?? 0) + duration > RENEWAL_CHAIN_CAP_SECONDS) throw new MusterError(400, 'renewal_cap_exceeded');
    }
    const { rows } = await client.query(
      `INSERT INTO agent_bus.conditions (kind, scope, starts_at, ends_at, owner_agent_id, effect, work_ref, renews_condition_id)
       VALUES ($1, $2::jsonb, now(), now() + make_interval(secs => $3), $4, $5::jsonb, $6, $7)
       RETURNING ${CONDITION_COLUMNS}`,
      [body.kind, scopeJson, duration, auth.agentId, effectJson, workRef, renews],
    );
    ctx.logger.log(`condition ${rows[0]?.condition_id} declared by ${auth.agentId}: ${body.kind} for ${duration}s`);
    return rows[0];
  });
}

/** GET /v1/conditions?include=active|all. Active is the default: not cleared and inside its window. */
export async function listConditions(ctx: MusterContext, params: URLSearchParams): Promise<unknown> {
  for (const key of params.keys()) {
    if (key !== 'include') throw new MusterError(400, 'unsupported_query');
  }
  const include = params.get('include') ?? 'active';
  if (include !== 'active' && include !== 'all') throw new MusterError(400, 'invalid_include');
  const where = include === 'active' ? `WHERE cleared_at IS NULL AND starts_at <= now() AND ends_at > now()` : '';
  const { rows } = await ctx.pool.query(
    `SELECT ${CONDITION_COLUMNS} FROM agent_bus.conditions ${where} ORDER BY created_at DESC LIMIT 200`,
  );
  return { conditions: rows };
}

/** POST /v1/conditions/{id}/clear. The owner, or a cos or operator holder, clears; a clear is final. */
export async function clearCondition(ctx: MusterContext, auth: AuthContext, conditionId: string): Promise<unknown> {
  if (!UUID_PATTERN.test(conditionId)) throw new MusterError(400, 'invalid_condition_id');
  return withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    const { rows } = await client.query(
      `UPDATE agent_bus.conditions
          SET cleared_by = $2, cleared_at = now(), version = version + 1
        WHERE condition_id = $1 AND cleared_at IS NULL AND (owner_agent_id = $2 OR $3::boolean)
        RETURNING ${CONDITION_COLUMNS}`,
      [conditionId, auth.agentId, isPrivileged(auth)],
    );
    if (rows[0]) return rows[0];
    const { rows: current } = await client.query<{ cleared_at: Date | null }>(
      `SELECT cleared_at FROM agent_bus.conditions WHERE condition_id = $1`,
      [conditionId],
    );
    const found = current[0];
    if (!found) throw new MusterError(404, 'condition_not_found');
    if (found.cleared_at) throw new MusterError(409, 'condition_cleared');
    throw new MusterError(403, 'not_condition_owner');
  });
}
