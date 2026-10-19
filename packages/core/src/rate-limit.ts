import { MusterError } from './errors.js';

/**
 * Slice 1 limits (design 20.4, AR S-04, XA-06, CA-09). Proposed values until the M-03 load baseline;
 * per-agent budgets use the design's write rates with a 2x burst.
 */
export interface RateLimits {
  /** Charged only after a request's signature verifies, so invalid traffic cannot spend it (AR XB-04). */
  globalPerSecond: number;
  globalBurst: number;
  /** Per source address, charged only by requests that fail validation or authentication. */
  failuresPerSecond: number;
  failureBurst: number;
  /** Shared budget for shaped but unproven credentials from sources whose failure budget is spent (AR XD-02). */
  candidatesPerSecond: number;
  candidateBurst: number;
  persistentPerMinute: number;
  ephemeralPerMinute: number;
  launcherPerMinute: number;
  keyRegistrationPerMinute: number;
  // OB-60178 stream budgets, set from the M-03 baseline (7 days to 2026-09-14): Nexus agent inbox rows
  // peaked at 476/h (mean 42/h, p95 180/h); claims peaked at 65/h. The soak target is 10x the inbox peak
  // (about 80 writes/min).
  /** All message writes across every author (about 1.5x the soak target, 15x the observed peak). */
  messagesGlobalPerMinute: number;
  /** Message writes addressed to one role. */
  messagesPerRolePerMinute: number;
  /** Shared by every runner one launcher brokered, so many exact ephemeral ids cannot sum past it (AR S-04). */
  launcherMessagesPerMinute: number;
  /** Deliveries created per adapter. */
  deliveriesPerAdapterPerMinute: number;
  /** Waiting unassigned-mailbox entries per role before writes return 503 overloaded (design 20.4). */
  mailboxCapacityPerRole: number;
  /** Unclaimed delivery_outbox rows before writes return 503 overloaded (design 20.4). */
  outboxCapacity: number;
}

export const DEFAULT_RATE_LIMITS: RateLimits = {
  globalPerSecond: 50,
  globalBurst: 100,
  failuresPerSecond: 2,
  failureBurst: 120,
  candidatesPerSecond: 10,
  candidateBurst: 20,
  persistentPerMinute: 60,
  ephemeralPerMinute: 20,
  launcherPerMinute: 30,
  keyRegistrationPerMinute: 10,
  messagesGlobalPerMinute: 120,
  messagesPerRolePerMinute: 60,
  launcherMessagesPerMinute: 60,
  deliveriesPerAdapterPerMinute: 600,
  mailboxCapacityPerRole: 200,
  outboxCapacity: 5000,
};

interface Bucket {
  tokens: number;
  updatedMs: number;
}

/** Tokens spent by RateLimiter.reserve(); release() refunds them once, capped at each bucket's burst. */
export interface RateReservation {
  release(): void;
}

/** Token buckets keyed by principal. Rejections are 429 with Retry-After, never a shared 503. */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  /**
   * @param failClosedWhenFull for the per-source failure limiter: when the map is full, a source with no
   * bucket counts as exhausted, so a flood of distinct sources throttles only unauthenticated traffic.
   */
  constructor(
    private readonly maxKeys = 50_000,
    private readonly failClosedWhenFull = false,
  ) {}

  take(key: string, perMinute: number, burst = perMinute * 2, nowMs = Date.now()): void {
    this.takeRate(key, perMinute / 60, burst, nowMs);
  }

  takeRate(key: string, perSecond: number, burst: number, nowMs = Date.now()): void {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maxKeys) this.prune(nowMs);
      if (this.buckets.size >= this.maxKeys) throw new MusterError(503, 'overloaded', 'rate limiter is full');
      bucket = { tokens: burst, updatedMs: nowMs };
      this.buckets.set(key, bucket);
    }
    bucket.tokens = Math.min(burst, bucket.tokens + ((nowMs - bucket.updatedMs) / 1000) * perSecond);
    bucket.updatedMs = nowMs;
    if (bucket.tokens < 1) {
      throw new MusterError(429, 'rate_limited', undefined, Math.max(1, Math.ceil((1 - bucket.tokens) / perSecond)));
    }
    bucket.tokens -= 1;
  }

  /**
   * Spends `count` tokens (default 1) from every listed per-minute bucket at once, or spends nothing and throws
   * 429 with the exhausted bucket's Retry-After. Admission is atomic because the check and the spend run in one
   * synchronous step, so concurrent requests cannot all pass on the same token (AR ZB-01). Call release() when
   * the guarded write does not commit, so a replay, a refusal, or a rollback spends nothing (AR ZA-04).
   */
  reserve(items: Array<{ key: string; perMinute: number; count?: number }>, nowMs = Date.now()): RateReservation {
    const held: Array<{ bucket: Bucket; burst: number; count: number }> = [];
    for (const { key, perMinute, count = 1 } of items) {
      if (count <= 0) continue;
      const perSecond = perMinute / 60;
      const burst = perMinute * 2;
      let bucket = this.buckets.get(key);
      if (!bucket) {
        if (this.buckets.size >= this.maxKeys) this.prune(nowMs);
        if (this.buckets.size >= this.maxKeys) throw new MusterError(503, 'overloaded', 'rate limiter is full');
        bucket = { tokens: burst, updatedMs: nowMs };
        this.buckets.set(key, bucket);
      }
      bucket.tokens = Math.min(burst, bucket.tokens + ((nowMs - bucket.updatedMs) / 1000) * perSecond);
      bucket.updatedMs = nowMs;
      if (bucket.tokens < count) {
        throw new MusterError(429, 'rate_limited', undefined, Math.max(1, Math.ceil((count - bucket.tokens) / perSecond)));
      }
      held.push({ bucket, burst, count });
    }
    for (const h of held) h.bucket.tokens -= h.count;
    let released = false;
    return {
      release() {
        if (released) return;
        released = true;
        for (const h of held) h.bucket.tokens = Math.min(h.burst, h.bucket.tokens + h.count);
      },
    };
  }

  /** True when the bucket has no token left, without spending one. */
  exhausted(key: string, perSecond: number, burst: number, nowMs = Date.now()): boolean {
    const bucket = this.buckets.get(key);
    if (!bucket) {
      if (!this.failClosedWhenFull || this.buckets.size < this.maxKeys) return false;
      this.prune(nowMs);
      return this.buckets.size >= this.maxKeys;
    }
    return Math.min(burst, bucket.tokens + ((nowMs - bucket.updatedMs) / 1000) * perSecond) < 1;
  }

  /** Spends a token if one is left; never throws. Used to account for failed requests after the fact. */
  charge(key: string, perSecond: number, burst: number, nowMs = Date.now()): void {
    try {
      this.takeRate(key, perSecond, burst, nowMs);
    } catch {
      // Already exhausted or the limiter is full; the next request from this source is refused.
    }
  }

  /** Drops buckets idle long enough to be full again. */
  prune(nowMs = Date.now()): void {
    for (const [key, bucket] of this.buckets) {
      if (nowMs - bucket.updatedMs > 10 * 60_000) this.buckets.delete(key);
    }
  }
}
