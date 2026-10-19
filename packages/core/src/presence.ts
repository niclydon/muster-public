import type { KeyObject } from 'node:crypto';
import { publicKeySha256, signedRequest, type SignedSeatRequest } from './client.js';
import type { Logger } from './logger.js';

/**
 * First-hand presence for persistent seats that have no runtime of their own to speak Muster
 * (the Nexus agents run as worker cycles). One keeper holds a session per seat: it registers
 * with the seat key, then heartbeats `PUT /v1/presence` so the registry shows the seat live
 * from its own signature rather than a bridge projection (design 7, "proxied presence never counts").
 */
export interface PresenceSeat {
  agentId: string;
  privateKey: KeyObject;
}

export interface PresenceResponse {
  status: number;
  json: Record<string, unknown> | null;
}

export type PresenceFetch = (path: string, init: SignedSeatRequest) => Promise<PresenceResponse>;

export type SeatOutcome = 'registered' | 'live' | 'frozen' | 'retry' | 'failed';

interface Session {
  token: string;
  expiresAtMs: number | null;
}

/** Environment variable that carries a seat's private key: MUSTER_AGENT_KEY_<AGENT ID upper-cased, non-alphanumerics as _>. */
export function seatKeyEnvName(agentId: string): string {
  return `MUSTER_AGENT_KEY_${agentId.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
}

export class PresenceKeeper {
  private readonly sessions = new Map<string, Session>();
  private readonly now: () => number;

  constructor(
    private readonly p: {
      audience: string;
      seats: PresenceSeat[];
      fetch: PresenceFetch;
      logger: Logger;
      /** Heartbeat period; a session within two periods of its token expiry is re-registered instead of heartbeated. */
      intervalMs: number;
      now?: () => number;
    },
  ) {
    this.now = p.now ?? (() => Date.now());
  }

  hasSession(agentId: string): boolean {
    return this.sessions.has(agentId);
  }

  /** One pass over every seat. Seats are independent: one failure never skips the others. */
  async tick(): Promise<Record<string, SeatOutcome>> {
    const outcomes: Record<string, SeatOutcome> = {};
    for (const seat of this.p.seats) {
      try {
        outcomes[seat.agentId] = await this.keep(seat);
      } catch (err) {
        this.p.logger.logMinimal(`${seat.agentId}: presence request failed:`, err instanceof Error ? err.message : String(err));
        outcomes[seat.agentId] = 'failed';
      }
    }
    this.p.logger.logVerbose('tick', outcomes);
    return outcomes;
  }

  private async keep(seat: PresenceSeat): Promise<SeatOutcome> {
    const session = this.sessions.get(seat.agentId);
    if (session && session.expiresAtMs !== null && session.expiresAtMs - this.now() < 2 * this.p.intervalMs) {
      this.p.logger.log(`${seat.agentId}: token near expiry, re-registering`);
      this.sessions.delete(seat.agentId);
    }
    if (!this.sessions.has(seat.agentId)) return this.register(seat);

    const token = this.sessions.get(seat.agentId)!.token;
    const res = await this.p.fetch(
      '/v1/presence',
      signedRequest({ audience: this.p.audience, method: 'PUT', path: '/v1/presence', body: {}, credential: { kind: 'token', token }, privateKey: seat.privateKey }),
    );
    if (res.status === 200) {
      this.p.logger.logVerbose(`${seat.agentId}: live (last_seen_at=${String(res.json?.last_seen_at)})`);
      return 'live';
    }
    if (res.status === 401) {
      // Superseded (someone registered this seat elsewhere) or expired: start a fresh session now.
      this.p.logger.log(`${seat.agentId}: session rejected (${String(res.json?.error)}), re-registering`);
      this.sessions.delete(seat.agentId);
      return this.register(seat);
    }
    return this.refused(seat, 'heartbeat', res);
  }

  private async register(seat: PresenceSeat): Promise<SeatOutcome> {
    const res = await this.p.fetch(
      '/v1/register',
      signedRequest({
        audience: this.p.audience,
        method: 'POST',
        path: '/v1/register',
        body: { persistence_class: 'persistent', agent_id: seat.agentId },
        credential: { kind: 'key', publicKeySha256: publicKeySha256(seat.privateKey) },
        privateKey: seat.privateKey,
      }),
    );
    if (res.status === 201 && typeof res.json?.token === 'string') {
      const expires = typeof res.json.token_expires_at === 'string' ? Date.parse(res.json.token_expires_at) : NaN;
      this.sessions.set(seat.agentId, { token: res.json.token, expiresAtMs: Number.isFinite(expires) ? expires : null });
      this.p.logger.log(
        `${seat.agentId}: registered session=${String(res.json.session_id)} key=${String(res.json.key_id)} ` +
          `north_star_version=${String(res.json.north_star_version)} token_expires_at=${String(res.json.token_expires_at)}`,
      );
      return 'registered';
    }
    if (res.status === 403 && (res.json?.error === 'agent_not_enrolled' || res.json?.error === 'class_mismatch')) {
      this.p.logger.logMinimal(`${seat.agentId}: ${String(res.json?.error)}; add it to roles.yaml as a persistent principal and SIGHUP muster-api`);
      return 'failed';
    }
    if (res.status === 401) {
      this.p.logger.logMinimal(`${seat.agentId}: seat key rejected (${String(res.json?.error)}); enroll it with scripts/muster-onboard-agent.mjs`);
      return 'failed';
    }
    return this.refused(seat, 'register', res);
  }

  private refused(seat: PresenceSeat, op: string, res: PresenceResponse): SeatOutcome {
    const error = String(res.json?.error ?? '');
    if (res.status === 503 || res.status === 423) {
      // Kill switch or break-glass: writes are refused, the session (if any) stays valid for later.
      this.p.logger.log(`${seat.agentId}: ${op} refused, writes frozen (${res.status} ${error})`);
      return 'frozen';
    }
    if (res.status === 429) {
      this.p.logger.log(`${seat.agentId}: ${op} rate limited, next tick`);
      return 'retry';
    }
    this.p.logger.logMinimal(`${seat.agentId}: ${op} failed (${res.status} ${error})`);
    return 'failed';
  }
}
