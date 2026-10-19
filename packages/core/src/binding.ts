import { MusterError } from './errors.js';

export interface Queryable {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  query<R = any>(text: string, params?: unknown[]): Promise<{ rows: R[]; rowCount: number | null }>;
}

export type HoldCheck =
  | {
      ok: true;
      /** When the deployment created the hold; must not predate the launch grant. */
      claimedAt: Date;
      /** Seconds until the hold expires, used as the ephemeral presence TTL. */
      ttlSeconds: number | null;
    }
  | { ok: false; reason: 'claim_not_found' | 'claim_not_active' | 'claim_agent_mismatch' };

/**
 * The deployment binding that knows what a work hold is. The core never reads hold tables itself;
 * the Nexus binding lives in the nexus monorepo and is loaded by path at startup (design section 9).
 * Launch provenance is not the binding's job: it comes from Muster launch grants, which only an
 * authenticated launcher can write.
 */
export interface MusterBinding {
  /**
   * The hold exists, is active, and is held by exactly agentId. With `lock`, the caller is inside its
   * issuance transaction and the binding must keep the hold from being released until that transaction
   * ends (AR XA-07).
   */
  verifyHold(db: Queryable, input: { claimId: string; agentId: string; lock?: boolean }): Promise<HoldCheck>;
  /** The agent holds at least one active hold (a runner may hold a whole claim pack). */
  hasLiveHold(db: Queryable, input: { agentId: string }): Promise<boolean>;
  /**
   * The push delivery adapter for a recipient runtime, or null when the recipient pulls through the API
   * (OB-60178). Optional in a binding module; the wrapper always provides it.
   */
  deliveryAdapterFor(runtime: string): string | null;
  /**
   * Extra push recipients inserted in the same post transaction as a client-authored message
   * (OB-60291, design 12). The binding names them; core does not. Optional in a binding module;
   * the wrapper always provides it and returns [] when the method is absent or the adapter is pull.
   */
  extraPushRecipients(): Array<{ agentId: string; runtime: string }>;
}

const HOLD_REASONS = new Set(['claim_not_found', 'claim_not_active', 'claim_agent_mismatch']);
const ADAPTER_NAME = /^[a-z][a-z0-9_]{0,31}$/;

export function assertBinding(value: unknown): MusterBinding {
  const candidate = value as Partial<MusterBinding> | null;
  if (!candidate || typeof candidate.verifyHold !== 'function' || typeof candidate.hasLiveHold !== 'function') {
    throw new Error('binding module must default-export { verifyHold, hasLiveHold }');
  }
  const binding = candidate as MusterBinding;
  return {
    async verifyHold(db, input) {
      const result = (await binding.verifyHold(db, input)) as HoldCheck | undefined;
      if (result?.ok === false && HOLD_REASONS.has(result.reason)) return { ok: false, reason: result.reason };
      if (result?.ok === true) {
        const claimedAt = new Date(result.claimedAt);
        const ttl = result.ttlSeconds;
        if (!Number.isNaN(claimedAt.getTime()) && (ttl === null || (Number.isFinite(ttl) && ttl >= 0))) {
          return { ok: true, claimedAt, ttlSeconds: ttl };
        }
      }
      throw new MusterError(503, 'binding_error', 'binding returned an unrecognised hold result');
    },
    async hasLiveHold(db, input) {
      return (await binding.hasLiveHold(db, input)) === true;
    },
    deliveryAdapterFor(runtime) {
      if (typeof candidate.deliveryAdapterFor !== 'function') return null;
      const adapter: unknown = candidate.deliveryAdapterFor(runtime);
      if (adapter === null || adapter === undefined) return null;
      if (typeof adapter !== 'string' || !ADAPTER_NAME.test(adapter)) {
        throw new MusterError(503, 'binding_error', 'binding returned an invalid delivery adapter name');
      }
      return adapter;
    },
    extraPushRecipients() {
      if (typeof candidate.extraPushRecipients !== 'function') return [];
      const extra: unknown = candidate.extraPushRecipients();
      if (extra === null || extra === undefined) return [];
      if (!Array.isArray(extra)) {
        throw new MusterError(503, 'binding_error', 'binding returned an invalid extra push recipient list');
      }
      return extra.map((item) => {
        if (!item || typeof item !== 'object') {
          throw new MusterError(503, 'binding_error', 'binding returned an invalid extra push recipient');
        }
        const rec = item as { agentId?: unknown; runtime?: unknown };
        if (typeof rec.agentId !== 'string' || typeof rec.runtime !== 'string' || rec.runtime.length === 0) {
          throw new MusterError(503, 'binding_error', 'binding returned an invalid extra push recipient');
        }
        return { agentId: rec.agentId, runtime: rec.runtime };
      });
    },
  };
}
