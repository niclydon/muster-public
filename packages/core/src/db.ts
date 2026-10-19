import type pg from 'pg';
import type { Queryable } from './binding.js';
import { MusterError } from './errors.js';

export async function withTransaction<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/** Shared row lock with the freeze flag so a break-glass FOR UPDATE cannot commit under an in-flight write. */
export async function assertWritable(client: Queryable): Promise<void> {
  try {
    await client.query(`SELECT agent_bus.muster_assert_writable()`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('writes_frozen')) throw new MusterError(423, 'writes_frozen');
    throw err;
  }
}

export async function withWritableTransaction<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  return withTransaction(pool, async (client) => {
    await assertWritable(client);
    return fn(client);
  });
}

/** Serializes registration, supersession, and revocation for one agent_id inside a transaction. */
export async function lockAgent(client: Queryable, agentId: string): Promise<void> {
  await client.query(`SELECT pg_advisory_xact_lock(hashtextextended('muster:agent:' || $1, 0))`, [agentId]);
}

export function isUniqueViolation(err: unknown, constraint: string): boolean {
  const e = err as { code?: string; constraint?: string } | null;
  return e?.code === '23505' && e.constraint === constraint;
}
