import type { KeyObject } from 'node:crypto';

export interface RecentCredential {
  /** The public key that last proved possession of this credential. */
  key: KeyObject;
  /** The nonce scope the credential's requests are replay-checked under. */
  nonceScope: string;
}

/**
 * Credentials that recently proved possession of their key, with that key. When a source has exhausted
 * its failure budget, a request skips the shared candidate budget only if its own signature verifies
 * against the remembered key (AR XD-02, XE-01); a remembered identifier alone is never enough.
 */
export class RecentCredentials {
  private readonly seen = new Map<string, RecentCredential & { expiresAt: number }>();

  constructor(
    private readonly ttlMs = 15 * 60_000,
    private readonly maxEntries = 50_000,
  ) {}

  remember(id: string, credential: RecentCredential, nowMs = Date.now()): void {
    if (this.seen.size >= this.maxEntries) this.prune(nowMs);
    if (this.seen.size >= this.maxEntries) {
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.delete(id);
    this.seen.set(id, { ...credential, expiresAt: nowMs + this.ttlMs });
  }

  get(id: string, nowMs = Date.now()): RecentCredential | undefined {
    const entry = this.seen.get(id);
    return entry && entry.expiresAt > nowMs ? entry : undefined;
  }

  prune(nowMs = Date.now()): void {
    for (const [id, entry] of this.seen) {
      if (entry.expiresAt <= nowMs) this.seen.delete(id);
    }
  }
}
