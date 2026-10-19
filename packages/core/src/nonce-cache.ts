import { MusterError } from './errors.js';

/**
 * Remembers request nonces per credential for longer than the accepted timestamp window, so a
 * captured signed request cannot be replayed. Each credential has its own quota, so one principal
 * cannot exhaust the cache for others (AR XA-06, CA-09). The cache is process-local; requests
 * signed in or before the process start second are rejected by the caller, which closes the
 * restart gap.
 */
export class NonceCache {
  private readonly byCredential = new Map<string, Map<string, number>>();
  private total = 0;

  constructor(
    private readonly ttlMs: number,
    private readonly maxPerCredential = 2_000,
    private readonly maxEntries = 200_000,
  ) {}

  /** Returns false if this credential already used the nonce inside the window. */
  checkAndRemember(credential: string, nonce: string, nowMs = Date.now()): boolean {
    let seen = this.byCredential.get(credential);
    const expiresAt = seen?.get(nonce);
    if (expiresAt !== undefined && expiresAt > nowMs) return false;

    if (seen && seen.size >= this.maxPerCredential) this.pruneCredential(credential, seen, nowMs);
    if (seen && seen.size >= this.maxPerCredential) {
      throw new MusterError(429, 'rate_limited', 'nonce quota exhausted for this credential', Math.ceil(this.ttlMs / 1000));
    }
    if (this.total >= this.maxEntries) this.prune(nowMs);
    if (this.total >= this.maxEntries) throw new MusterError(503, 'overloaded', 'nonce cache is full');

    if (!seen) {
      seen = new Map();
      this.byCredential.set(credential, seen);
    }
    if (!seen.has(nonce)) this.total += 1;
    seen.set(nonce, nowMs + this.ttlMs);
    return true;
  }

  private pruneCredential(credential: string, seen: Map<string, number>, nowMs: number): void {
    for (const [nonce, expiresAt] of seen) {
      if (expiresAt <= nowMs) {
        seen.delete(nonce);
        this.total -= 1;
      }
    }
    if (seen.size === 0) this.byCredential.delete(credential);
  }

  prune(nowMs = Date.now()): void {
    for (const [credential, seen] of this.byCredential) this.pruneCredential(credential, seen, nowMs);
  }
}
