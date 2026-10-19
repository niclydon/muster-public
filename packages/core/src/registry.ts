import type pg from 'pg';
import type { Queryable } from './binding.js';
import { withWritableTransaction } from './db.js';
import { MusterError } from './errors.js';
import type { ResolvedPrincipal } from './roles.js';

/**
 * Creates or refreshes the registry entry from the reviewed roles file. Clients never supply runtime,
 * class, or roles (design 20.1). Registration is first-hand presence, so the entry starts live. A
 * tombstoned (revoked) entry is never revived here; only operator enrollment reinstates it (AR CA-11).
 */
export async function upsertRegistryOnRegistration(client: Queryable, principal: ResolvedPrincipal, ttlSeconds: number): Promise<void> {
  const { rowCount } = await client.query(
    `INSERT INTO agent_bus.registry_entries
       (agent_id, runtime, persistence_class, roles, may_address, addressable_by, scope,
        ttl_seconds, last_seen_at, presence_state, proxied_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), 'live', NULL)
     ON CONFLICT (agent_id) DO UPDATE SET
       runtime = EXCLUDED.runtime,
       persistence_class = EXCLUDED.persistence_class,
       roles = EXCLUDED.roles,
       may_address = EXCLUDED.may_address,
       addressable_by = EXCLUDED.addressable_by,
       scope = EXCLUDED.scope,
       ttl_seconds = EXCLUDED.ttl_seconds,
       last_seen_at = now(),
       presence_state = 'live',
       proxied_by = NULL,
       updated_at = now()
     WHERE agent_bus.registry_entries.tombstoned_at IS NULL`,
    [
      principal.agentId,
      principal.runtime,
      principal.persistenceClass,
      principal.roles,
      principal.mayAddress,
      principal.addressableBy,
      JSON.stringify(principal.scope),
      ttlSeconds,
    ],
  );
  if (rowCount !== 1) throw new MusterError(403, 'agent_revoked');
}

/**
 * First-hand presence: an upsert of last_seen at server time, never a row per tick (design 4.1, 20.5).
 * Also refreshes roles/may_address/addressable_by from the caller's freshly-resolved principal (the same
 * roles-file resolution `authenticate` just did), so a reviewed roles-file change reaches every live row
 * within one heartbeat instead of only at next registration (OB-60329).
 */
export async function touchPresence(pool: pg.Pool, principal: ResolvedPrincipal): Promise<{ agent_id: string; last_seen_at: string; ttl_seconds: number }> {
  return withWritableTransaction(pool, async (client) => {
    const { rows } = await client.query(
      `UPDATE agent_bus.registry_entries
          SET last_seen_at = now(), presence_state = 'live', proxied_by = NULL, updated_at = now(),
              roles = $2, may_address = $3, addressable_by = $4
        WHERE agent_id = $1 AND tombstoned_at IS NULL
        RETURNING agent_id, last_seen_at, ttl_seconds`,
      [principal.agentId, principal.roles, principal.mayAddress, principal.addressableBy],
    );
    if (rows.length !== 1) throw new MusterError(401, 'agent_not_registered');
    return rows[0];
  });
}

/** Presence state is computed from server time on read: live within TTL, stale within 2x TTL, then dark. */
export async function listRegistry(pool: pg.Pool): Promise<unknown[]> {
  const { rows } = await pool.query(
    `SELECT agent_id, runtime, persistence_class, roles, may_address, addressable_by, scope,
            capacity, holds, holds_projected_at, last_seen_at, ttl_seconds, proxied_by, initiative_tier,
            CASE
              WHEN last_seen_at IS NULL THEN 'stale'
              WHEN last_seen_at >= now() - make_interval(secs => ttl_seconds) THEN 'live'
              WHEN last_seen_at >= now() - make_interval(secs => 2 * ttl_seconds) THEN 'stale'
              ELSE 'dark'
            END AS presence_state
       FROM agent_bus.registry_entries
      WHERE tombstoned_at IS NULL
      ORDER BY agent_id`,
  );
  return rows;
}

export async function setInitiativeTier(pool: pg.Pool, actor: { agentId: string; principal: { roles: string[] } }, agentId: string, tier: unknown): Promise<unknown> {
  if (!actor.principal.roles.includes('operator')) throw new MusterError(403, 'tier_edit_forbidden');
  if (tier !== 'T0' && tier !== 'T1' && tier !== 'T2') throw new MusterError(400, 'invalid_initiative_tier');
  return withWritableTransaction(pool, async (client) => {
    const { rows } = await client.query(`UPDATE agent_bus.registry_entries SET initiative_tier=$2, updated_at=now() WHERE agent_id=$1 AND tombstoned_at IS NULL RETURNING agent_id, initiative_tier`, [agentId, tier]);
    if (rows.length !== 1) throw new MusterError(404, 'agent_not_registered');
    return rows[0];
  });
}
