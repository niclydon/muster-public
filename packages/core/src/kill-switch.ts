import type pg from 'pg';
import type { Queryable } from './binding.js';
import { MusterError } from './errors.js';

/** Singleton control_key for the shared Muster freeze. */
export const KILL_SWITCH_KEY = 'kill_switch';

/** Operator seat, platform-ops agent, and the enrolled operator principal. */
export const ALLOWED_KILL_SWITCH_ACTORS = ['operator', 'platform-ops', 'nic'] as const;
export type KillSwitchActor = (typeof ALLOWED_KILL_SWITCH_ACTORS)[number];

export interface KillSwitch {
  isOn(): boolean;
}

export interface KillSwitchState {
  enabled: boolean;
  reason: string;
  actor: string;
  updated_at: Date;
}

/** Test double. Production reads agent_bus.operational_controls. */
export function memoryKillSwitch(state: { on: boolean }): KillSwitch {
  return { isOn: () => state.on };
}

export function adaptersEnabled(killSwitch?: KillSwitch): boolean {
  return !killSwitch?.isOn();
}

export function assertSwitchWritable(killSwitch?: KillSwitch): void {
  if (killSwitch?.isOn()) throw new MusterError(503, 'read_only');
}

export function normalizeKillSwitchActor(actor: string): KillSwitchActor {
  const id = actor.trim();
  if ((ALLOWED_KILL_SWITCH_ACTORS as readonly string[]).includes(id)) return id as KillSwitchActor;
  throw new MusterError(403, 'kill_switch_forbidden');
}

export function requireKillSwitchReason(reason: string): string {
  const trimmed = reason.trim();
  if (!trimmed) throw new MusterError(400, 'reason_required');
  return trimmed;
}

/** Actor is the authenticated operator principal, never a caller-supplied --actor or GUC. */
export function killSwitchActorFromAuth(auth: { agentId: string; principal: { roles: string[] } }): KillSwitchActor {
  if (!auth.principal.roles.includes('operator')) {
    throw new MusterError(403, 'principal_admin_forbidden');
  }
  if ((ALLOWED_KILL_SWITCH_ACTORS as readonly string[]).includes(auth.agentId)) {
    return auth.agentId as KillSwitchActor;
  }
  return 'operator';
}

function mapKillSwitchWriteError(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: string }).code;
  if (message.includes('reason_required')) throw new MusterError(400, 'reason_required');
  if (message.includes('kill_switch_forbidden')) throw new MusterError(403, 'kill_switch_forbidden');
  if (code === '42501') throw new MusterError(403, 'kill_switch_forbidden');
  throw err;
}

/**
 * Shared fail-closed freeze: missing row or a failed read is ON, so adapters
 * and mutating API routes stop when the control plane cannot be observed.
 */
export async function readKillSwitch(db: Queryable): Promise<boolean> {
  try {
    const { rows } = await db.query<{ enabled: boolean }>(
      `SELECT enabled FROM agent_bus.operational_controls WHERE control_key = $1`,
      [KILL_SWITCH_KEY],
    );
    if (rows.length !== 1) return true;
    return rows[0]!.enabled === true;
  } catch {
    return true;
  }
}

export async function readKillSwitchState(db: Queryable): Promise<KillSwitchState | null> {
  try {
    const { rows } = await db.query<KillSwitchState>(
      `SELECT enabled, reason, actor, updated_at
         FROM agent_bus.operational_controls WHERE control_key = $1`,
      [KILL_SWITCH_KEY],
    );
    return rows[0] ?? null;
  } catch {
    return null;
  }
}

export async function currentKillSwitchOn(ctx: { pool: Queryable; killSwitch?: KillSwitch }): Promise<boolean> {
  if (ctx.killSwitch) return ctx.killSwitch.isOn();
  return readKillSwitch(ctx.pool);
}

export async function assertWritable(ctx: { pool: Queryable; killSwitch?: KillSwitch }): Promise<void> {
  if (await currentKillSwitchOn(ctx)) throw new MusterError(503, 'read_only');
}

/**
 * Authorized toggle through SECURITY DEFINER agent_bus.muster_set_kill_switch.
 * Only muster_admin may EXECUTE it. Actor must be operator, platform-ops, or nic.
 * Reason is required for both on and off. The function takes FOR UPDATE on the
 * control row so a concurrent adapter FOR SHARE either sees the committed freeze
 * or waits for this statement.
 */
export async function setKillSwitch(
  pool: pg.Pool,
  p: { enabled: boolean; reason: string; actor: string },
): Promise<KillSwitchState> {
  const actor = normalizeKillSwitchActor(p.actor);
  const reason = requireKillSwitchReason(p.reason);
  try {
    const { rows } = await pool.query<KillSwitchState>(
      `SELECT enabled, reason, actor, updated_at FROM agent_bus.muster_set_kill_switch($1, $2, $3)`,
      [p.enabled, reason, actor],
    );
    return rows[0]!;
  } catch (err) {
    mapKillSwitchWriteError(err);
  }
}
