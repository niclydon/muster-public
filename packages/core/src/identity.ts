import { randomBytes, randomUUID, type KeyObject } from 'node:crypto';
import type pg from 'pg';
import { audit } from './audit.js';
import type { MusterBinding, Queryable } from './binding.js';
import { assertWritable, isUniqueViolation, lockAgent, withTransaction } from './db.js';
import { MusterError } from './errors.js';
import type { Logger } from './logger.js';
import { NonceCache } from './nonce-cache.js';
import type { RateLimiter, RateLimits } from './rate-limit.js';
import type { RecentCredential, RecentCredentials } from './recent-credentials.js';
import { upsertRegistryOnRegistration } from './registry.js';
import { isValidAgentId, type PersistenceClass, type ResolvedPrincipal, type RolesConfig } from './roles.js';
import type { KillSwitch } from './kill-switch.js';
import type { RequestMetrics } from './metrics.js';
import { MAX_CLOCK_SKEW_SECONDS, canonicalRequest, keyProofPayload, parsePublicKey, sha256Hex, verifySignature } from './signing.js';

export const PERSISTENT_TOKEN_TTL_SECONDS = 24 * 3600;
export const OPERATOR_INTERACTIVE_TOKEN_TTL_SECONDS = 60 * 60;
export const OPERATOR_INTERACTIVE_APPROVAL_TTL_SECONDS = 2 * 60;
/** Ephemeral tokens live as long as their key; liveness is enforced on every request through live holds. */
export const EPHEMERAL_KEY_TTL_SECONDS = 12 * 3600;
export const EPHEMERAL_TOKEN_TTL_SECONDS = EPHEMERAL_KEY_TTL_SECONDS;
export const PERSISTENT_PRESENCE_TTL_SECONDS = 15 * 60;
export const DEFAULT_EPHEMERAL_PRESENCE_TTL_SECONDS = 30 * 60;
export const MIN_EPHEMERAL_PRESENCE_TTL_SECONDS = 60;
export const MAX_EPHEMERAL_PRESENCE_TTL_SECONDS = 2 * 3600;
/** A runner must claim work within this long after its launcher records the launch grant. */
export const LAUNCH_GRANT_CLAIM_WINDOW_SECONDS = 30 * 60;

export interface MusterContext {
  pool: pg.Pool;
  /** Dedicated muster_admin pool for the SECURITY DEFINER admin functions (1895 management, 1897 kill switch). Absent → admin routes return 503 admin_unavailable. */
  adminPool?: pg.Pool;
  roles: RolesConfig;
  binding: MusterBinding;
  nonces: NonceCache;
  /** Authenticated budgets: global and per principal. */
  limiter: RateLimiter;
  /** Per-source budget for failed requests; a separate map that fails closed when full (AR XC-04). */
  failureLimiter: RateLimiter;
  /** Credentials that recently proved possession; they bypass the candidate budget (AR XD-02). */
  recent: RecentCredentials;
  limits: RateLimits;
  /** Deployment identity bound into every signature (MUSTER_AUDIENCE). */
  audience: string;
  /** Requests signed in or before this second are rejected, so a restart cannot reopen the replay window. */
  startedAtSeconds: number;
  logger: Logger;
  /** Delivers only the challenge digest to the operator's authenticated device path. */
  publishInteractiveApproval?: (input: { requestId: string; challengeSha256: string; expiresAt: string; agentId: string; keyFingerprint: string }) => Promise<void>;
  interactiveApprovalTtlSeconds?: number;
  /** Operator kill switch: adapters off, API read-only, legacy bus untouched (design 20.4). */
  killSwitch?: KillSwitch;
  metrics?: RequestMetrics;
}

export function createNonceCache(): NonceCache {
  return new NonceCache((2 * MAX_CLOCK_SKEW_SECONDS + 60) * 1000);
}

export interface SignedRequest {
  method: string;
  pathWithQuery: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

export interface AuthContext {
  agentId: string;
  jti: string;
  sessionId: string;
  keyId: string;
  persistenceClass: PersistenceClass;
  principal: ResolvedPrincipal;
}

export interface IssuedToken {
  agent_id: string;
  session_id: string;
  token: string;
  token_expires_at: string;
  key_id: string;
  north_star_version?: number | null;
}

const TOKEN = /^mst_[A-Za-z0-9_-]{43}$/;
const NONCE = /^[A-Za-z0-9_-]{16,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY_HASH = /^[0-9a-f]{64}$/;

/** Tokens are stored only as their sha256 (AR CA-07); the hash is the jti. */
export function tokenJti(token: string): string {
  return sha256Hex(token);
}

function singleHeader(req: SignedRequest, name: string): string | undefined {
  const value = req.headers[name];
  return typeof value === 'string' ? value : undefined;
}

interface Envelope {
  timestamp: string;
  nonce: string;
  signature: string | undefined;
}

/** Cheap checks that need no database: header shape and the server-time window. */
function preflightEnvelope(ctx: MusterContext, req: SignedRequest): Envelope {
  const timestamp = singleHeader(req, 'muster-timestamp');
  const nonce = singleHeader(req, 'muster-nonce');
  if (!timestamp || !/^\d{1,12}$/.test(timestamp)) throw new MusterError(401, 'invalid_timestamp');
  if (!nonce || !NONCE.test(nonce)) throw new MusterError(401, 'invalid_nonce');
  const signedAt = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);
  // `<=`: a request signed in the start second may predate the restart (AR XA-04, CA-08).
  if (Math.abs(now - signedAt) > MAX_CLOCK_SKEW_SECONDS || signedAt <= ctx.startedAtSeconds) {
    throw new MusterError(401, 'stale_timestamp');
  }
  return { timestamp, nonce, signature: singleHeader(req, 'muster-signature') };
}

/**
 * Proof of possession: the request is signed by the registered key. Only then is the principal's
 * rate budget charged and its nonce spent, so an unauthenticated caller cannot drain either.
 */
function verifyEnvelope(ctx: MusterContext, req: SignedRequest, env: Envelope, credential: string, key: KeyObject, budget: { key: string; perMinute: number }): void {
  const payload = canonicalRequest({
    audience: ctx.audience,
    method: req.method,
    pathWithQuery: req.pathWithQuery,
    timestamp: env.timestamp,
    nonce: env.nonce,
    body: req.body,
    credential,
  });
  if (!verifySignature(key, payload, env.signature)) throw new MusterError(401, 'bad_signature');
  ctx.limiter.takeRate('global', ctx.limits.globalPerSecond, ctx.limits.globalBurst);
  ctx.limiter.take(budget.key, budget.perMinute);
  if (!ctx.nonces.checkAndRemember(budget.key, env.nonce)) throw new MusterError(401, 'replayed_nonce');
}

/**
 * Admission check for a source whose failure budget is spent (AR XE-01): the request is inside the time
 * window, signed by the key that recently proved this credential, and its nonce has not passed this gate
 * before. No database access. A pass only skips the candidate budget; the request is still fully
 * authenticated afterwards, which charges the principal's own budget.
 */
export function provesRecentPossession(ctx: MusterContext, req: SignedRequest, canonicalCredential: string, recent: RecentCredential): boolean {
  const timestamp = singleHeader(req, 'muster-timestamp');
  const nonce = singleHeader(req, 'muster-nonce');
  if (!timestamp || !/^\d{1,12}$/.test(timestamp) || !nonce || !NONCE.test(nonce)) return false;
  const signedAt = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - signedAt) > MAX_CLOCK_SKEW_SECONDS || signedAt <= ctx.startedAtSeconds) return false;
  const payload = canonicalRequest({
    audience: ctx.audience,
    method: req.method,
    pathWithQuery: req.pathWithQuery,
    timestamp,
    nonce,
    body: req.body,
    credential: canonicalCredential,
  });
  if (!verifySignature(recent.key, payload, singleHeader(req, 'muster-signature'))) return false;
  return ctx.nonces.checkAndRemember(`gate:${recent.nonceScope}`, nonce);
}

function storedKey(publicKeyB64: string): KeyObject {
  try {
    return parsePublicKey(publicKeyB64).key;
  } catch {
    throw new MusterError(503, 'stored_key_invalid');
  }
}

interface TokenRow {
  jti: string;
  agent_id: string;
  key_id: string;
  session_id: string;
  token_expired: boolean;
  token_revoked: boolean;
  revoke_reason: string | null;
  revocation_listed: boolean;
  public_key: string;
  key_kind: PersistenceClass;
  key_revoked: boolean;
  key_expired: boolean;
  registered: boolean;
  tombstoned: boolean;
  launcher_revoked: boolean;
}

/**
 * Authenticates a token request against live state on every call (design 20.1): signature by the
 * token's key, revocation, token and key expiry, registry entry, the launcher that brokered the
 * token (AR CA-03), roles file enrollment, and for ephemeral runners at least one live hold.
 */
export async function authenticate(ctx: MusterContext, req: SignedRequest): Promise<AuthContext> {
  const authorization = singleHeader(req, 'authorization');
  const token = authorization?.startsWith('Muster-PoP ') ? authorization.slice('Muster-PoP '.length) : undefined;
  if (!token || !TOKEN.test(token)) throw new MusterError(401, 'missing_credentials');
  const env = preflightEnvelope(ctx, req);
  const jti = tokenJti(token);

  const { rows } = await ctx.pool.query<TokenRow>(
    `SELECT t.jti, t.agent_id, t.key_id, t.session_id,
            t.expires_at <= now() AS token_expired,
            t.revoked_at IS NOT NULL AS token_revoked,
            t.revoke_reason,
            EXISTS (SELECT 1 FROM agent_bus.token_revocations tr WHERE tr.jti = t.jti) AS revocation_listed,
            k.public_key, k.key_kind,
            k.revoked_at IS NOT NULL AS key_revoked,
            (k.expires_at IS NOT NULL AND k.expires_at <= now()) AS key_expired,
            e.agent_id IS NOT NULL AS registered,
            e.tombstoned_at IS NOT NULL AS tombstoned,
            COALESCE(le.tombstoned_at IS NOT NULL, false) AS launcher_revoked
       FROM agent_bus.issued_tokens t
       JOIN agent_bus.principal_keys k ON k.key_id = t.key_id AND k.agent_id = t.agent_id
       LEFT JOIN agent_bus.registry_entries e ON e.agent_id = t.agent_id
       LEFT JOIN agent_bus.registration_requests r ON r.request_id = t.request_id
       LEFT JOIN agent_bus.registry_entries le ON le.agent_id = r.launcher_agent_id
      WHERE t.jti = $1`,
    [jti],
  );
  const row = rows[0];
  if (!row) throw new MusterError(401, 'token_unknown');

  // Signature first, so a caller without the key learns nothing about the token's state.
  const perMinute = row.key_kind === 'persistent' ? ctx.limits.persistentPerMinute : ctx.limits.ephemeralPerMinute;
  const tokenKey = storedKey(row.public_key);
  verifyEnvelope(ctx, req, env, token, tokenKey, { key: `agent:${row.agent_id}`, perMinute });

  if (row.token_revoked || row.revocation_listed) {
    throw new MusterError(401, row.revoke_reason === 'session_superseded' ? 'session_superseded' : 'token_revoked');
  }
  if (row.token_expired) throw new MusterError(401, 'token_expired');
  if (row.key_revoked || row.key_expired) throw new MusterError(401, 'key_revoked');
  if (!row.registered || row.tombstoned) throw new MusterError(401, 'agent_not_registered');
  if (row.launcher_revoked) throw new MusterError(401, 'launcher_revoked');

  const principal = ctx.roles.resolve(row.agent_id);
  if (principal.persistenceClass !== row.key_kind) throw new MusterError(403, 'class_mismatch');
  if (row.key_kind === 'ephemeral' && !(await ctx.binding.hasLiveHold(ctx.pool, { agentId: row.agent_id }))) {
    throw new MusterError(401, 'claim_not_live');
  }

  ctx.recent.remember(jti, { key: tokenKey, nonceScope: `agent:${row.agent_id}` });
  return {
    agentId: row.agent_id,
    jti,
    sessionId: row.session_id,
    keyId: row.key_id,
    persistenceClass: row.key_kind,
    principal,
  };
}

function requireAgentId(value: unknown): string {
  if (!isValidAgentId(value)) throw new MusterError(400, 'invalid_agent_id');
  return value;
}

async function assertNotRevoked(q: Queryable, agentId: string): Promise<void> {
  const { rowCount } = await q.query(
    `SELECT 1 FROM agent_bus.registry_entries WHERE agent_id = $1 AND tombstoned_at IS NOT NULL`,
    [agentId],
  );
  if (rowCount) throw new MusterError(403, 'agent_revoked');
}

/** The launcher's own token is still usable; re-read inside the issuance transaction (AR CA-14, XA-07). */
async function assertLauncherLive(q: Queryable, launcher: AuthContext): Promise<void> {
  const { rowCount } = await q.query(
    `SELECT 1
       FROM agent_bus.issued_tokens t
       JOIN agent_bus.principal_keys k ON k.key_id = t.key_id
       JOIN agent_bus.registry_entries e ON e.agent_id = t.agent_id
      WHERE t.jti = $1 AND t.revoked_at IS NULL AND t.expires_at > now()
        AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())
        AND e.tombstoned_at IS NULL`,
    [launcher.jti],
  );
  if (!rowCount) throw new MusterError(401, 'token_revoked');
}

/** Revokes matching active tokens, lists each in token_revocations, and audits each. */
export async function revokeTokens(
  client: Queryable,
  filter: { agentId: string; jti?: string; keyId?: string },
  reason: string,
  actor: string,
): Promise<number> {
  const { rows } = await client.query<{ jti: string; session_id: string; key_id: string; expires_at: Date }>(
    `UPDATE agent_bus.issued_tokens
        SET revoked_at = now(), revoke_reason = $2
      WHERE agent_id = $1 AND revoked_at IS NULL
        AND ($3::text IS NULL OR jti = $3)
        AND ($4::uuid IS NULL OR key_id = $4)
      RETURNING jti, session_id, key_id, expires_at`,
    [filter.agentId, reason, filter.jti ?? null, filter.keyId ?? null],
  );
  for (const old of rows) {
    await client.query(
      `INSERT INTO agent_bus.token_revocations (jti, agent_id, reason, expires_at)
       VALUES ($1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING`,
      [old.jti, filter.agentId, reason, old.expires_at],
    );
    await audit(client, {
      eventType: 'token_revoked',
      agentId: filter.agentId,
      actor,
      keyId: old.key_id,
      jti: old.jti,
      sessionId: old.session_id,
      detail: { reason },
    });
  }
  return rows.length;
}

/**
 * Issues a token bound to keyId in a new session, then supersedes every other active session of the
 * agent (delta 19, M-16): older tokens are revoked with superseded_by_jti and older non-persistent keys
 * are revoked. Must run inside a transaction holding lockAgent.
 */
async function issueSessionToken(
  client: pg.PoolClient,
  p: { agentId: string; keyId: string; requestId: string | null; claimId: string | null; ttlSeconds: number; actor: string; path: string },
): Promise<IssuedToken> {
  const token = `mst_${randomBytes(32).toString('base64url')}`;
  const jti = tokenJti(token);
  const sessionId = randomUUID();
  const { rows } = await client.query<{ expires_at: Date }>(
    `INSERT INTO agent_bus.issued_tokens (jti, agent_id, key_id, request_id, session_id, claim_id, expires_at)
     SELECT $1, $2, k.key_id, $4, $5, $6,
            LEAST(now() + make_interval(secs => $7), COALESCE(k.expires_at, 'infinity'::timestamptz))
       FROM agent_bus.principal_keys k
      WHERE k.key_id = $3
     RETURNING expires_at`,
    [jti, p.agentId, p.keyId, p.requestId, sessionId, p.claimId, p.ttlSeconds],
  );
  const issued = rows[0];
  if (!issued) throw new Error('key vanished during token issuance');
  await audit(client, {
    eventType: 'token_issued',
    agentId: p.agentId,
    actor: p.actor,
    keyId: p.keyId,
    jti,
    requestId: p.requestId,
    sessionId,
    detail: { path: p.path, claim_id: p.claimId, expires_at: issued.expires_at.toISOString() },
  });

  const superseded = await client.query<{ jti: string; session_id: string; key_id: string; expires_at: Date }>(
    `UPDATE agent_bus.issued_tokens
        SET revoked_at = now(), revoke_reason = 'session_superseded', superseded_by_jti = $1
      WHERE agent_id = $2 AND jti <> $1 AND revoked_at IS NULL
      RETURNING jti, session_id, key_id, expires_at`,
    [jti, p.agentId],
  );
  for (const old of superseded.rows) {
    await client.query(
      `INSERT INTO agent_bus.token_revocations (jti, agent_id, reason, expires_at)
       VALUES ($1, $2, 'session_superseded', $3) ON CONFLICT (jti) DO NOTHING`,
      [old.jti, p.agentId, old.expires_at],
    );
    await audit(client, {
      eventType: 'token_revoked',
      agentId: p.agentId,
      actor: p.actor,
      keyId: old.key_id,
      jti: old.jti,
      sessionId: old.session_id,
      detail: { reason: 'session_superseded', superseded_by_session: sessionId },
    });
    await audit(client, {
      eventType: 'session_superseded',
      agentId: p.agentId,
      actor: p.actor,
      jti: old.jti,
      sessionId: old.session_id,
      detail: { superseded_by_session: sessionId },
    });
  }

  const oldKeys = await client.query<{ key_id: string }>(
    `UPDATE agent_bus.principal_keys
        SET revoked_at = now()
      WHERE agent_id = $1 AND key_id <> $2 AND key_kind <> 'persistent' AND revoked_at IS NULL
      RETURNING key_id`,
    [p.agentId, p.keyId],
  );
  for (const old of oldKeys.rows) {
    await audit(client, {
      eventType: 'key_revoked',
      agentId: p.agentId,
      actor: p.actor,
      keyId: old.key_id,
      detail: { reason: 'session_superseded', superseded_by_session: sessionId },
    });
  }

  return {
    agent_id: p.agentId,
    session_id: sessionId,
    token,
    token_expires_at: issued.expires_at.toISOString(),
    key_id: p.keyId,
  };
}

/**
 * Persistent seat registration. The request is signed by the seat's operator-enrolled key and names
 * the key by hash (`Authorization: Muster-Key <sha256>`); no token exists yet.
 */
export async function registerPersistent(ctx: MusterContext, req: SignedRequest, body: Record<string, unknown>): Promise<IssuedToken> {
  const authorization = singleHeader(req, 'authorization');
  const keyHash = authorization?.startsWith('Muster-Key ') ? authorization.slice('Muster-Key '.length) : undefined;
  if (!keyHash || !KEY_HASH.test(keyHash)) throw new MusterError(401, 'missing_credentials');
  const agentId = requireAgentId(body.agent_id);
  const env = preflightEnvelope(ctx, req);

  const { rows } = await ctx.pool.query<{
    key_id: string;
    agent_id: string;
    public_key: string;
    key_kind: PersistenceClass;
    unusable: boolean;
  }>(
    `SELECT key_id, agent_id, public_key, key_kind,
            (revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= now())) AS unusable
       FROM agent_bus.principal_keys
      WHERE public_key_sha256 = $1`,
    [keyHash],
  );
  const key = rows[0];
  if (!key) throw new MusterError(401, 'key_unknown');
  const seatKey = storedKey(key.public_key);
  verifyEnvelope(ctx, req, env, `key:${keyHash}`, seatKey, {
    key: `key:${keyHash}`,
    perMinute: ctx.limits.keyRegistrationPerMinute,
  });
  if (key.key_kind !== 'persistent') throw new MusterError(403, 'wrong_key_kind');
  if (key.unusable) throw new MusterError(401, 'key_revoked');
  if (key.agent_id !== agentId) throw new MusterError(403, 'agent_key_mismatch');
  const principal = ctx.roles.resolve(agentId);
  if (principal.persistenceClass !== 'persistent') throw new MusterError(403, 'class_mismatch');

  const issuedSeat = await withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    await lockAgent(client, agentId);
    await assertNotRevoked(client, agentId);
    const live = await client.query(
      `SELECT 1 FROM agent_bus.principal_keys
        WHERE key_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
      [key.key_id],
    );
    if (live.rowCount !== 1) throw new MusterError(401, 'key_revoked');
    const issued = await issueSessionToken(client, {
      agentId,
      keyId: key.key_id,
      requestId: null,
      claimId: null,
      ttlSeconds: PERSISTENT_TOKEN_TTL_SECONDS,
      actor: agentId,
      path: 'persistent_key',
    });
    await upsertRegistryOnRegistration(client, principal, PERSISTENT_PRESENCE_TTL_SECONDS);
    const northStar = await client.query<{ version: number }>(`SELECT version FROM agent_bus.north_star_versions ORDER BY version DESC LIMIT 1`);
    return { ...issued, north_star_version: northStar.rows[0]?.version ?? null };
  });
  ctx.recent.remember(`key:${keyHash}`, { key: seatKey, nonceScope: `key:${keyHash}` });
  ctx.recent.remember(tokenJti(issuedSeat.token), { key: seatKey, nonceScope: `agent:${agentId}` });
  return issuedSeat;
}

/** Creates an approval-gated enrollment request. The raw challenge never leaves the server. */
export async function registerOperatorInteractive(ctx: MusterContext, body: Record<string, unknown>): Promise<{ request_id: string; approval_expires_at: string }> {
  const agentId = requireAgentId(body.agent_id);
  const principal = ctx.roles.resolve(agentId);
  if (principal.persistenceClass !== 'operator_interactive') throw new MusterError(403, 'persistence_class_not_enrolled');
  if (typeof body.nonce !== 'string' || !NONCE.test(body.nonce)) throw new MusterError(400, 'invalid_nonce');
  const key = parsePublicKey(body.public_key);
  const proof = keyProofPayload({ audience: ctx.audience, agentId, claimId: 'operator_interactive', nonce: body.nonce, publicKeySha256: key.sha256 });
  if (!verifySignature(key.key, proof, body.key_proof)) throw new MusterError(401, 'bad_key_proof');
  if (!ctx.publishInteractiveApproval) throw new MusterError(503, 'approval_channel_unavailable');
  const challengeSha256 = sha256Hex(randomBytes(32));
  const created = await withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    await lockAgent(client, agentId);
    let request: { request_id: string; approval_expires_at: Date };
    try {
      const { rows } = await client.query<{ request_id: string; approval_expires_at: Date }>(
        `INSERT INTO agent_bus.registration_requests
           (nonce, public_key_sha256, requested_agent_id, persistence_class, approval_challenge_sha256, approval_expires_at)
         VALUES ($1, $2, $3, 'operator_interactive', $4, now() + make_interval(secs => $5))
         RETURNING request_id, approval_expires_at`,
        [body.nonce, key.sha256, agentId, challengeSha256, ctx.interactiveApprovalTtlSeconds ?? OPERATOR_INTERACTIVE_APPROVAL_TTL_SECONDS],
      );
      request = rows[0] as { request_id: string; approval_expires_at: Date };
    } catch (err) {
      if (isUniqueViolation(err, 'registration_requests_nonce_key')) throw new MusterError(409, 'nonce_reused');
      throw err;
    }
    await audit(client, { eventType: 'registration_requested', agentId, actor: 'operator_interactive', requestId: request.request_id, detail: { path: 'operator_interactive' } });
    return request;
  });
  try {
    await ctx.publishInteractiveApproval({
      requestId: created.request_id,
      challengeSha256,
      expiresAt: created.approval_expires_at.toISOString(),
      agentId,
      keyFingerprint: key.sha256,
    });
  } catch {
    // The request stays unusable without approval; do not offer a local fallback.
    throw new MusterError(503, 'approval_channel_unavailable');
  }
  return { request_id: created.request_id, approval_expires_at: created.approval_expires_at.toISOString() };
}

/** Called only by the separately authenticated device-approval bridge. */
export async function approveInteractiveRegistration(ctx: MusterContext, input: { requestId: string; challengeSha256: string }): Promise<void> {
  if (!UUID.test(input.requestId) || !KEY_HASH.test(input.challengeSha256)) throw new MusterError(400, 'invalid_approval');
  return withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    const updated = await client.query<{ requested_agent_id: string }>(
      `UPDATE agent_bus.registration_requests
          SET status = 'approved', approved_at = now()
        WHERE request_id = $1 AND persistence_class = 'operator_interactive' AND status = 'pending'
          AND approval_challenge_sha256 = $2 AND approval_expires_at > now()
        RETURNING requested_agent_id`,
      [input.requestId, input.challengeSha256],
    );
    if (updated.rowCount !== 1) {
      const { rows } = await client.query<{ expired: boolean }>(
        `SELECT approval_expires_at <= now() AS expired
           FROM agent_bus.registration_requests WHERE request_id = $1 AND approval_challenge_sha256 = $2`,
        [input.requestId, input.challengeSha256],
      );
      if (rows[0]?.expired) throw new MusterError(409, 'approval_expired');
      throw new MusterError(409, 'approval_not_pending');
    }
    await audit(client, { eventType: 'registration_approved', agentId: updated.rows[0]!.requested_agent_id, actor: 'operator_device', requestId: input.requestId, detail: { path: 'operator_interactive' } });
  });
}

/** Exchanges one approved request for a token after the submitted key signs this exact HTTP request. */
export async function exchangeOperatorInteractive(ctx: MusterContext, req: SignedRequest, requestId: string, body: Record<string, unknown>): Promise<IssuedToken> {
  const authorization = singleHeader(req, 'authorization');
  const keyHash = authorization?.startsWith('Muster-Key ') ? authorization.slice('Muster-Key '.length) : undefined;
  if (!keyHash || !KEY_HASH.test(keyHash)) throw new MusterError(401, 'missing_credentials');
  const suppliedKey = parsePublicKey(body.public_key);
  if (suppliedKey.sha256 !== keyHash) throw new MusterError(401, 'key_mismatch');
  const env = preflightEnvelope(ctx, req);
  verifyEnvelope(ctx, req, env, `key:${keyHash}`, suppliedKey.key, { key: `interactive:${requestId}`, perMinute: ctx.limits.keyRegistrationPerMinute });
  return withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    const { rows } = await client.query<{ requested_agent_id: string; public_key_sha256: string; status: string; expired: boolean }>(
      `SELECT requested_agent_id, public_key_sha256, status, approval_expires_at <= now() AS expired
         FROM agent_bus.registration_requests WHERE request_id = $1 AND persistence_class = 'operator_interactive' FOR UPDATE`, [requestId],
    );
    const request = rows[0];
    if (!request) throw new MusterError(404, 'registration_not_found');
    if (request.public_key_sha256 !== suppliedKey.sha256) throw new MusterError(401, 'key_mismatch');
    if (request.status === 'consumed') throw new MusterError(409, 'approval_consumed');
    if (request.expired) {
      if (request.status !== 'expired') await client.query(`UPDATE agent_bus.registration_requests SET status = 'expired' WHERE request_id = $1`, [requestId]);
      throw new MusterError(409, 'approval_expired');
    }
    if (request.status !== 'approved') throw new MusterError(403, 'approval_required');
    const principal = ctx.roles.resolve(request.requested_agent_id);
    if (principal.persistenceClass !== 'operator_interactive') throw new MusterError(403, 'persistence_class_not_enrolled');
    await lockAgent(client, request.requested_agent_id);
    const { rows: keyRows } = await client.query<{ key_id: string }>(
      `INSERT INTO agent_bus.principal_keys (agent_id, request_id, public_key, public_key_sha256, key_kind, expires_at)
       VALUES ($1, $2, $3, $4, 'operator_interactive', now() + make_interval(secs => $5)) RETURNING key_id`,
      [request.requested_agent_id, requestId, body.public_key, suppliedKey.sha256, OPERATOR_INTERACTIVE_TOKEN_TTL_SECONDS],
    );
    const keyId = keyRows[0]!.key_id;
    await audit(client, { eventType: 'key_issued', agentId: request.requested_agent_id, actor: 'operator_interactive', keyId, requestId, detail: { key_kind: 'operator_interactive' } });
    const issued = await issueSessionToken(client, { agentId: request.requested_agent_id, keyId, requestId, claimId: null, ttlSeconds: OPERATOR_INTERACTIVE_TOKEN_TTL_SECONDS, actor: 'operator_interactive', path: 'operator_interactive' });
    // clock_timestamp is wall-clock time, unlike transaction-start now(); this is the final authority
    // after lockAgent can have waited past the two-minute approval window. A failed transition rolls
    // back the just-created key and token with this transaction.
    const consumed = await client.query(
      `UPDATE agent_bus.registration_requests
          SET status = 'consumed', consumed_at = clock_timestamp(), consumed_token_jti = $2
        WHERE request_id = $1 AND status = 'approved' AND approval_expires_at > clock_timestamp()`,
      [requestId, tokenJti(issued.token)],
    );
    if (consumed.rowCount !== 1) throw new MusterError(409, 'approval_expired');
    await audit(client, { eventType: 'registration_consumed', agentId: request.requested_agent_id, actor: 'operator_interactive', keyId, requestId, jti: tokenJti(issued.token), sessionId: issued.session_id, detail: { path: 'operator_interactive' } });
    await upsertRegistryOnRegistration(client, principal, OPERATOR_INTERACTIVE_TOKEN_TTL_SECONDS);
    ctx.recent.remember(tokenJti(issued.token), { key: suppliedKey.key, nonceScope: `agent:${request.requested_agent_id}` });
    return issued;
  });
}

function requireLauncherFor(ctx: MusterContext, launcher: AuthContext, agentId: string): ResolvedPrincipal {
  if (launcher.persistenceClass !== 'persistent') throw new MusterError(403, 'launcher_not_persistent');
  const principal = ctx.roles.resolve(agentId);
  if (principal.persistenceClass !== 'ephemeral') throw new MusterError(403, 'class_mismatch');
  if (!principal.launchedBy.includes(launcher.agentId)) throw new MusterError(403, 'launcher_not_authorized');
  return principal;
}

/** Rejected brokered requests are audited outside the failed transaction (AR CA-10). */
async function withRejectionAudit<T>(ctx: MusterContext, launcher: AuthContext, body: Record<string, unknown>, path: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof MusterError && err.status < 500 && err.status !== 429) {
      const requested = isValidAgentId(body.agent_id) ? body.agent_id : null;
      try {
        await audit(ctx.pool, {
          eventType: 'registration_rejected',
          agentId: requested ?? launcher.agentId,
          actor: launcher.agentId,
          detail: {
            path,
            code: err.code,
            requested_agent_id: requested,
            claim_id: typeof body.claim_id === 'string' && UUID.test(body.claim_id) ? body.claim_id : null,
            launcher_session_id: launcher.sessionId,
          },
        });
      } catch (auditErr) {
        ctx.logger.logMinimal('registration_rejected audit failed:', (auditErr as { code?: string }).code ?? 'unknown');
      }
    }
    throw err;
  }
}

/** A brokered registration made by the grant's launcher after the grant was created. */
const REGISTERED_UNDER_GRANT_SQL = `EXISTS (
  SELECT 1 FROM agent_bus.registration_requests r
   WHERE r.requested_agent_id = g.agent_id
     AND r.launcher_agent_id = g.launcher_agent_id
     AND r.status = 'consumed'
     AND r.created_at >= g.created_at)`;

/** Revokes active launch grants matching every given filter and audits each. Grants are never deleted. */
export async function revokeLaunchGrants(
  client: Queryable,
  filter: { grantId?: string; agentId?: string; launcherAgentId?: string; launcherKeyId?: string },
  reason: string,
  actor: string,
): Promise<number> {
  const { rows } = await client.query<{ grant_id: string; agent_id: string; launcher_agent_id: string }>(
    `UPDATE agent_bus.launch_grants
        SET revoked_at = now(), revoke_reason = $1
      WHERE revoked_at IS NULL
        AND ($2::uuid IS NULL OR grant_id = $2)
        AND ($3::text IS NULL OR agent_id = $3)
        AND ($4::text IS NULL OR launcher_agent_id = $4)
        AND ($5::uuid IS NULL OR launcher_key_id = $5)
      RETURNING grant_id, agent_id, launcher_agent_id`,
    [reason, filter.grantId ?? null, filter.agentId ?? null, filter.launcherAgentId ?? null, filter.launcherKeyId ?? null],
  );
  for (const g of rows) {
    await audit(client, {
      eventType: 'launch_grant_revoked',
      agentId: g.agent_id,
      actor,
      detail: { grant_id: g.grant_id, launcher_agent_id: g.launcher_agent_id, reason },
    });
  }
  return rows.length;
}

/**
 * Launch provenance (AR XA-01, CA-01, CA-02, XB-01, XB-02). Before spawning a runner, its launcher records
 * the exact agent_id it launches. Only an authenticated persistent launcher allowed by the roles file can
 * write a grant, and the grant is bound to that launcher's key. At most one grant per agent_id is active.
 * A new grant replaces the active one only when it is the same launcher's, the old launcher's key is no
 * longer usable, or the old grant expired unused; otherwise it is refused, so a co-launcher cannot take a
 * live runner and cannot squat an id for longer than one claim window. Operators can revoke any grant.
 */
export async function createLaunchGrant(ctx: MusterContext, launcher: AuthContext, body: Record<string, unknown>) {
  return withRejectionAudit(ctx, launcher, body, 'launch_grant', async () => {
    const agentId = requireAgentId(body.agent_id);
    requireLauncherFor(ctx, launcher, agentId);
    ctx.limiter.take(`launcher:${launcher.agentId}`, ctx.limits.launcherPerMinute);
    return withTransaction(ctx.pool, async (client) => {
      await assertWritable(client);
      await lockAgent(client, agentId);
      await assertLauncherLive(client, launcher);
      await assertNotRevoked(client, agentId);

      const { rows: active } = await client.query<{ grant_id: string; launcher_agent_id: string; launcher_key_live: boolean; window_open: boolean; registered_under: boolean }>(
        `SELECT g.grant_id, g.launcher_agent_id,
                (k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())) AS launcher_key_live,
                now() <= g.claim_window_ends_at AS window_open,
                ${REGISTERED_UNDER_GRANT_SQL} AS registered_under
           FROM agent_bus.launch_grants g
           JOIN agent_bus.principal_keys k ON k.key_id = g.launcher_key_id
          WHERE g.agent_id = $1 AND g.revoked_at IS NULL
          FOR UPDATE OF g`,
        [agentId],
      );
      const current = active[0];
      if (current) {
        let reason: string | null = null;
        if (current.launcher_agent_id === launcher.agentId) reason = 'replaced_by_same_launcher';
        else if (!current.launcher_key_live) reason = 'launcher_key_unusable';
        else if (!current.registered_under && !current.window_open) reason = 'expired_unused';
        if (!reason) throw new MusterError(409, 'launch_grant_exists');
        await revokeLaunchGrants(client, { grantId: current.grant_id }, reason, launcher.agentId);
      }

      let grant: { grant_id: string; claim_window_ends_at: Date };
      try {
        const { rows } = await client.query<{ grant_id: string; claim_window_ends_at: Date }>(
          `INSERT INTO agent_bus.launch_grants (agent_id, launcher_agent_id, launcher_key_id, launcher_session_id, claim_window_ends_at)
           VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))
           RETURNING grant_id, claim_window_ends_at`,
          [agentId, launcher.agentId, launcher.keyId, launcher.sessionId, LAUNCH_GRANT_CLAIM_WINDOW_SECONDS],
        );
        grant = rows[0] as { grant_id: string; claim_window_ends_at: Date };
      } catch (err) {
        if (isUniqueViolation(err, 'launch_grants_one_active')) throw new MusterError(409, 'launch_grant_exists');
        throw err;
      }
      await audit(client, {
        eventType: 'launch_granted',
        agentId,
        actor: launcher.agentId,
        sessionId: launcher.sessionId,
        detail: { grant_id: grant.grant_id, claim_window_ends_at: grant.claim_window_ends_at.toISOString() },
      });
      return { grant_id: grant.grant_id, agent_id: agentId, claim_window_ends_at: grant.claim_window_ends_at.toISOString() };
    });
  });
}

/**
 * The registering launcher holds the agent's active launch grant, made with the launcher key it is using
 * now (a rotated, revoked, or reinstated launcher needs a fresh grant, AR XB-01), and the claim was created
 * after the grant. A first registration under the grant must happen, with its claim created, inside the
 * claim window; later re-registrations under the same grant (runner restart, a new claim pack) may use any
 * claim created after the grant.
 */
async function assertLaunchGrant(q: Queryable, agentId: string, launcher: AuthContext, claimedAt: Date): Promise<void> {
  const { rows } = await q.query<{ launcher_agent_id: string; launcher_key_id: string; launcher_key_live: boolean; created_at: Date; claim_window_ends_at: Date; window_open: boolean; registered_before: boolean }>(
    `SELECT g.launcher_agent_id, g.launcher_key_id, g.created_at, g.claim_window_ends_at,
            (k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())) AS launcher_key_live,
            now() <= g.claim_window_ends_at AS window_open,
            ${REGISTERED_UNDER_GRANT_SQL} AS registered_before
       FROM agent_bus.launch_grants g
       JOIN agent_bus.principal_keys k ON k.key_id = g.launcher_key_id
      WHERE g.agent_id = $1 AND g.revoked_at IS NULL`,
    [agentId],
  );
  const grant = rows[0];
  if (!grant) throw new MusterError(403, 'launch_grant_missing');
  if (grant.launcher_agent_id !== launcher.agentId) throw new MusterError(403, 'launch_grant_launcher_mismatch');
  if (grant.launcher_key_id !== launcher.keyId || !grant.launcher_key_live) throw new MusterError(403, 'launch_grant_stale');
  if (claimedAt.getTime() < grant.created_at.getTime()) throw new MusterError(403, 'claim_predates_launch_grant');
  if (!grant.registered_before && (!grant.window_open || claimedAt.getTime() > grant.claim_window_ends_at.getTime())) {
    throw new MusterError(403, 'launch_grant_window_closed');
  }
}

function presenceTtl(ttlSeconds: number | null): number {
  const ttl = ttlSeconds ?? DEFAULT_EPHEMERAL_PRESENCE_TTL_SECONDS;
  return Math.min(MAX_EPHEMERAL_PRESENCE_TTL_SECONDS, Math.max(MIN_EPHEMERAL_PRESENCE_TTL_SECONDS, Math.floor(ttl)));
}

/**
 * Brokered registration of an ephemeral runner (design 20.1, AR R-01). The launcher authenticates with
 * its own proof-of-possession token and names the exact agent_id and claim. Muster requires the roles
 * file to allow this launcher, the launcher's launch grant for that agent_id, the runner's proof that it
 * holds the new key, and the binding's confirmation that the claim is active, held by that agent_id, and
 * created after the grant. Every check is repeated inside the issuance transaction. Launchers never mint
 * tokens. A launcher necessarily can act for runners it launched itself; it cannot act for another
 * launcher's runners, because it holds no grant for them.
 */
export async function registerEphemeral(ctx: MusterContext, launcher: AuthContext, body: Record<string, unknown>): Promise<IssuedToken & { request_id: string }> {
  return withRejectionAudit(ctx, launcher, body, 'brokered_registration', async () => {
    const agentId = requireAgentId(body.agent_id);
    if (typeof body.claim_id !== 'string' || !UUID.test(body.claim_id)) throw new MusterError(400, 'invalid_claim_id');
    const claimId = body.claim_id;
    if (typeof body.nonce !== 'string' || !NONCE.test(body.nonce)) throw new MusterError(400, 'invalid_nonce');
    const nonce = body.nonce;
    const runnerKey = parsePublicKey(body.public_key);
    const principal = requireLauncherFor(ctx, launcher, agentId);
    ctx.limiter.take(`launcher:${launcher.agentId}`, ctx.limits.launcherPerMinute);

    const proof = keyProofPayload({ audience: ctx.audience, agentId, claimId, nonce, publicKeySha256: runnerKey.sha256 });
    if (!verifySignature(runnerKey.key, proof, body.key_proof)) throw new MusterError(401, 'bad_key_proof');

    const checkHoldAndGrant = async (q: Queryable, lock: boolean) => {
      await assertNotRevoked(q, agentId);
      const hold = await ctx.binding.verifyHold(q, { claimId, agentId, lock });
      if (!hold.ok) throw new MusterError(403, hold.reason);
      await assertLaunchGrant(q, agentId, launcher, hold.claimedAt);
      return hold;
    };
    await checkHoldAndGrant(ctx.pool, false);

    const registered = await withTransaction(ctx.pool, async (client) => {
      await assertWritable(client);
      await lockAgent(client, agentId);
      await assertLauncherLive(client, launcher);
      // The locked re-read holds the claim until this transaction commits, so it cannot be released
      // between this check and the token (AR XA-07).
      const hold = await checkHoldAndGrant(client, true);

      let requestId: string;
      try {
        const { rows } = await client.query<{ request_id: string }>(
          `INSERT INTO agent_bus.registration_requests
             (nonce, public_key_sha256, requested_agent_id, persistence_class, claim_id, launcher_agent_id)
           VALUES ($1, $2, $3, 'ephemeral', $4, $5)
           RETURNING request_id`,
          [nonce, runnerKey.sha256, agentId, claimId, launcher.agentId],
        );
        requestId = (rows[0] as { request_id: string }).request_id;
      } catch (err) {
        if (isUniqueViolation(err, 'registration_requests_nonce_key')) throw new MusterError(409, 'nonce_reused');
        throw err;
      }
      await audit(client, {
        eventType: 'registration_requested',
        agentId,
        actor: launcher.agentId,
        requestId,
        detail: { claim_id: claimId, launcher_agent_id: launcher.agentId, launcher_session_id: launcher.sessionId },
      });

      let keyId: string;
      try {
        const { rows } = await client.query<{ key_id: string }>(
          `INSERT INTO agent_bus.principal_keys (agent_id, request_id, public_key, public_key_sha256, key_kind, expires_at)
           VALUES ($1, $2, $3, $4, 'ephemeral', now() + make_interval(secs => $5))
           RETURNING key_id`,
          [agentId, requestId, body.public_key, runnerKey.sha256, EPHEMERAL_KEY_TTL_SECONDS],
        );
        keyId = (rows[0] as { key_id: string }).key_id;
      } catch (err) {
        if (isUniqueViolation(err, 'principal_keys_public_key_sha256_key')) throw new MusterError(409, 'public_key_in_use');
        throw err;
      }
      await audit(client, { eventType: 'key_issued', agentId, actor: launcher.agentId, keyId, requestId, detail: { key_kind: 'ephemeral' } });

      const issued = await issueSessionToken(client, {
        agentId,
        keyId,
        requestId,
        claimId,
        ttlSeconds: EPHEMERAL_TOKEN_TTL_SECONDS,
        actor: launcher.agentId,
        path: 'brokered_registration',
      });
      const jti = tokenJti(issued.token);

      const consumed = await client.query(
        `UPDATE agent_bus.registration_requests
            SET status = 'consumed', consumed_at = now(), consumed_token_jti = $2
          WHERE request_id = $1 AND status = 'pending'`,
        [requestId, jti],
      );
      if (consumed.rowCount !== 1) throw new Error('registration request was not pending at consumption');
      await audit(client, {
        eventType: 'registration_consumed',
        agentId,
        actor: launcher.agentId,
        keyId,
        jti,
        requestId,
        sessionId: issued.session_id,
        detail: { claim_id: claimId },
      });

      await upsertRegistryOnRegistration(client, principal, presenceTtl(hold.ttlSeconds));
      const northStar = await client.query<{ version: number }>(`SELECT version FROM agent_bus.north_star_versions ORDER BY version DESC LIMIT 1`);
      return { ...issued, request_id: requestId, north_star_version: northStar.rows[0]?.version ?? null };
    });
    ctx.recent.remember(tokenJti(registered.token), { key: runnerKey.key, nonceScope: `agent:${agentId}` });
    return registered;
  });
}
