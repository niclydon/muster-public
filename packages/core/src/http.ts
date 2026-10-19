import http from 'node:http';
import { clearCondition, declareCondition, listConditions } from './conditions.js';
import { MusterError } from './errors.js';
import {
  authenticate,
  createLaunchGrant,
  provesRecentPossession,
  registerEphemeral,
  registerOperatorInteractive,
  exchangeOperatorInteractive,
  registerPersistent,
  tokenJti,
  type MusterContext,
  type SignedRequest,
} from './identity.js';
import { listRegistry, setInitiativeTier, touchPresence } from './registry.js';
import {
  assertWritable,
  currentKillSwitchOn,
  killSwitchActorFromAuth,
  requireKillSwitchReason,
  setKillSwitch,
} from './kill-switch.js';
import { runWithSpan } from './tracing.js';
import { getNorthStar, northStarHistory, setMission, upsertGoal } from './north-star.js';
import { parsePublicKey } from './signing.js';
import { ackDelivery, deliveryStatus, inheritMailbox, listMessages, listRoleMailbox, postMessage } from './stream.js';
import { withTransaction } from './db.js';
import type pg from 'pg';

export const MAX_BODY_BYTES = 64 * 1024;

const CREDENTIAL = /^Muster-(PoP mst_[A-Za-z0-9_-]{43}|Key [0-9a-f]{64})$/;

/**
 * The credential of a request shaped like a signed request, or null: `id` keys the recent-credential
 * cache, `canonical` is what the client signed. When a source's failure budget is spent, shaped requests
 * still reach verification so clients sharing an address with a flooder keep working (AR XC-03), but only
 * a request that re-proves possession skips the bounded candidate budget (AR XD-02, XE-01).
 */
function signedCredential(req: http.IncomingMessage): { id: string; canonical: string } | null {
  const h = req.headers;
  const authorization = h.authorization;
  if (
    typeof authorization !== 'string' ||
    !CREDENTIAL.test(authorization) ||
    typeof h['muster-timestamp'] !== 'string' ||
    typeof h['muster-nonce'] !== 'string' ||
    typeof h['muster-signature'] !== 'string'
  ) {
    return null;
  }
  if (authorization.startsWith('Muster-PoP ')) {
    const token = authorization.slice('Muster-PoP '.length);
    return { id: tokenJti(token), canonical: token };
  }
  const keyCredential = `key:${authorization.slice('Muster-Key '.length)}`;
  return { id: keyCredential, canonical: keyCredential };
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let rejected = false;
    req.on('data', (chunk: Buffer) => {
      if (rejected) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        rejected = true;
        reject(new MusterError(413, 'body_too_large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!rejected) resolve(Buffer.concat(chunks));
    });
    req.on('error', (err) => {
      if (!rejected) reject(err);
    });
  });
}

function parseJsonObject(body: Buffer): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(body.toString('utf8'));
  } catch {
    throw new MusterError(400, 'invalid_json');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new MusterError(400, 'invalid_json');
  return value as Record<string, unknown>;
}

/** Presence carries no client fields: timestamps are server time and entries come from the roles file. */
function requireEmptyObjectBody(body: Buffer): void {
  if (body.length === 0) return;
  const value = parseJsonObject(body);
  if (Object.keys(value).length > 0) throw new MusterError(400, 'unsupported_field');
}

function requireMethod(req: http.IncomingMessage, method: string): void {
  if (req.method !== method) throw new MusterError(405, 'method_not_allowed');
}

function send(res: http.ServerResponse, status: number, payload: unknown, extraHeaders: Record<string, string> = {}): void {
  const contentType = extraHeaders['content-type'] ?? 'application/json';
  const body = typeof payload === 'string' && contentType.startsWith('text/plain') ? payload : JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

/** Never logs raw error messages: database and trigger messages can carry identifiers (AR CA-12). */
function describeError(err: unknown): string {
  const e = err as { code?: unknown; constraint?: unknown; name?: unknown } | null;
  const parts = [typeof e?.name === 'string' ? e.name : 'Error'];
  if (typeof e?.code === 'string') parts.push(`code=${e.code}`);
  if (typeof e?.constraint === 'string') parts.push(`constraint=${e.constraint}`);
  return parts.join(' ');
}

function searchParams(signed: SignedRequest): URLSearchParams {
  return new URL(signed.pathWithQuery, 'http://muster.invalid').searchParams;
}

/** Mailbox inheritance never fails the presence or registration write that triggered it. */
async function inheritQuietly(ctx: MusterContext, agentId: string): Promise<void> {
  try {
    await inheritMailbox(ctx, agentId);
  } catch (err) {
    ctx.logger.logMinimal(`mailbox inheritance for ${agentId} failed:`, describeError(err));
  }
}

function requireOperator(auth: { principal: { roles: string[] } }): void {
  if (!auth.principal.roles.includes('operator')) throw new MusterError(403, 'principal_admin_forbidden');
}

async function requireWritable(pool: pg.Pool): Promise<void> {
  const { rows } = await pool.query<{ read_only: boolean }>(
    `SELECT read_only FROM agent_bus.operational_state WHERE singleton`,
  );
  if (rows[0]?.read_only) throw new MusterError(423, 'writes_frozen');
}

function mapPrivilegedError(err: unknown): unknown {
  const message = err instanceof Error ? err.message : String(err);
  if (message.includes('writes_frozen')) return new MusterError(423, 'writes_frozen');
  if (message.includes('active_key_exists')) return new MusterError(409, 'active_key_exists');
  if (message.includes('muster_actor_missing') || message.includes('muster_actor_not_operator')) {
    return new MusterError(403, 'forged_actor');
  }
  if (message.includes('invalid_enrollment') || message.includes('invalid_expiry')) {
    return new MusterError(400, 'invalid_enrollment');
  }
  if (message.includes('invalid_reason')) return new MusterError(400, 'invalid_reason');
  return err;
}

async function callPrivileged<T>(
  ctx: MusterContext,
  actor: string,
  sql: string,
  params: unknown[],
): Promise<T> {
  if (!ctx.adminPool) throw new MusterError(503, 'admin_unavailable');
  try {
    return await withTransaction(ctx.adminPool, async (client) => {
      await client.query(`SELECT set_config('muster.actor', $1, true)`, [actor]);
      const { rows } = await client.query<{ result: T }>(sql, params);
      return rows[0]!.result;
    });
  } catch (err) {
    throw mapPrivilegedError(err);
  }
}

const DELIVERY_ACK = /^\/v1\/deliveries\/([0-9a-f-]{36})\/ack$/;
const CONDITION_CLEAR = /^\/v1\/conditions\/([0-9a-f-]{36})\/clear$/;
const INTERACTIVE_EXCHANGE = /^\/v1\/register\/([0-9a-f-]{36})\/exchange$/;
const GOAL = /^\/v1\/goals\/([0-9a-f-]{36})$/;
const TIER = /^\/v1\/registry\/([^/]+)\/tier$/;
const DELIVERY_STATUS = /^\/v1\/messages\/([0-9]+)\/deliveries$/;
const PRINCIPAL_REVOKE = /^\/v1\/principals\/([^/]+)\/revoke$/;

async function route(
  ctx: MusterContext,
  req: http.IncomingMessage,
  path: string,
  signed: SignedRequest,
  note: { agent: string },
): Promise<{ status: number; payload: unknown; headers?: Record<string, string> }> {
  if (path === '/health') {
    requireMethod(req, 'GET');
    const killSwitchOn = await currentKillSwitchOn(ctx);
    try {
      await ctx.pool.query('SELECT 1');
      return {
        status: 200,
        payload: {
          status: 'ok',
          kill_switch: killSwitchOn,
          mode: killSwitchOn ? 'read_only' : 'read_write',
          adapters: killSwitchOn ? 'off' : 'on',
        },
      };
    } catch (err) {
      ctx.logger.logMinimal('health check failed:', describeError(err));
      return { status: 503, payload: { status: 'unavailable', kill_switch: killSwitchOn } };
    }
  }

  if (path === '/metrics') {
    requireMethod(req, 'GET');
    const killSwitchOn = await currentKillSwitchOn(ctx);
    const body = (ctx.metrics ?? { render: () => '# no metrics\n' }).render({ killSwitchOn });
    return { status: 200, payload: body, headers: { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' } };
  }

  // Exempt from the freeze: this is how an operator turns the switch off.
  if (path === '/v1/admin/kill-switch') {
    requireMethod(req, 'POST');
    const auth = await authenticate(ctx, signed);
    note.agent = auth.agentId;
    requireOperator(auth);
    if (!ctx.adminPool) throw new MusterError(503, 'admin_unavailable');
    const body = parseJsonObject(signed.body);
    if (typeof body.enabled !== 'boolean') throw new MusterError(400, 'invalid_enabled');
    if (typeof body.reason !== 'string') throw new MusterError(400, 'reason_required');
    const state = await setKillSwitch(ctx.adminPool, {
      enabled: body.enabled,
      reason: requireKillSwitchReason(body.reason),
      actor: killSwitchActorFromAuth(auth),
    });
    return {
      status: 200,
      payload: {
        kill_switch: state.enabled,
        actor: state.actor,
        reason: state.reason,
        updated_at: state.updated_at instanceof Date ? state.updated_at.toISOString() : state.updated_at,
        adapters: state.enabled ? 'off' : 'on',
        api: state.enabled ? 'read_only' : 'read_write',
      },
    };
  }

  if (req.method !== 'GET') await assertWritable(ctx);

  if (path === '/v1/register') {
    requireMethod(req, 'POST');
    const body = parseJsonObject(signed.body);
    switch (body.persistence_class) {
      case 'persistent': {
        await requireWritable(ctx.pool);
        const issued = await registerPersistent(ctx, signed, body);
        note.agent = issued.agent_id;
        await inheritQuietly(ctx, issued.agent_id);
        return { status: 201, payload: issued };
      }
      case 'ephemeral': {
        const launcher = await authenticate(ctx, signed);
        note.agent = launcher.agentId;
        await requireWritable(ctx.pool);
        const issued = await registerEphemeral(ctx, launcher, body);
        note.agent = `${launcher.agentId}->${issued.agent_id}`;
        await inheritQuietly(ctx, issued.agent_id);
        return { status: 201, payload: issued };
      }
      case 'operator_interactive': {
        await requireWritable(ctx.pool);
        const requested = await registerOperatorInteractive(ctx, body);
        return { status: 202, payload: requested };
      }
      default:
        throw new MusterError(400, 'invalid_persistence_class');
    }
  }

  if (path === '/v1/launch-grants') {
    requireMethod(req, 'POST');
    const body = parseJsonObject(signed.body);
    const launcher = await authenticate(ctx, signed);
    note.agent = launcher.agentId;
    await requireWritable(ctx.pool);
    const grant = await createLaunchGrant(ctx, launcher, body);
    note.agent = `${launcher.agentId}->${grant.agent_id}`;
    return { status: 201, payload: grant };
  }

  const interactiveExchange = INTERACTIVE_EXCHANGE.exec(path);
  if (interactiveExchange) {
    requireMethod(req, 'POST');
    await requireWritable(ctx.pool);
    const issued = await exchangeOperatorInteractive(ctx, signed, interactiveExchange[1] as string, parseJsonObject(signed.body));
    note.agent = issued.agent_id;
    await inheritQuietly(ctx, issued.agent_id);
    return { status: 201, payload: issued };
  }

  if (path === '/v1/presence') {
    requireMethod(req, 'PUT');
    const auth = await authenticate(ctx, signed);
    note.agent = auth.agentId;
    requireEmptyObjectBody(signed.body);
    await requireWritable(ctx.pool);
    const presence = await touchPresence(ctx.pool, auth.principal);
    await inheritQuietly(ctx, auth.agentId);
    return { status: 200, payload: presence };
  }

  if (path === '/v1/registry') {
    requireMethod(req, 'GET');
    const auth = await authenticate(ctx, signed);
    note.agent = auth.agentId;
    return { status: 200, payload: { entries: await listRegistry(ctx.pool) } };
  }
  if (path === '/v1/role-mailbox') {
    requireMethod(req, 'GET'); const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    return { status: 200, payload: await listRoleMailbox(ctx, auth) };
  }
  const deliveryStatusMatch = DELIVERY_STATUS.exec(path);
  if (deliveryStatusMatch) {
    requireMethod(req, 'GET'); const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    return { status: 200, payload: await deliveryStatus(ctx, auth, deliveryStatusMatch[1] as string) };
  }
  const tier = TIER.exec(path);
  if (tier) {
    requireMethod(req, 'POST'); const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireOperator(auth);
    await requireWritable(ctx.pool);
    return { status: 200, payload: await setInitiativeTier(ctx.pool, auth, decodeURIComponent(tier[1] as string), parseJsonObject(signed.body).tier) };
  }
  const revoke = PRINCIPAL_REVOKE.exec(path);
  if (revoke) {
    requireMethod(req, 'POST'); const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireOperator(auth);
    await requireWritable(ctx.pool);
    const body = parseJsonObject(signed.body); const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
    if (!reason) throw new MusterError(400, 'invalid_reason');
    const result = await callPrivileged(
      ctx,
      auth.agentId,
      `SELECT agent_bus.muster_principal_revoke($1,$2) AS result`,
      [decodeURIComponent(revoke[1] as string), reason],
    );
    return { status: 200, payload: result };
  }
  if (path === '/v1/principals/enroll') {
    requireMethod(req, 'POST'); const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireOperator(auth);
    await requireWritable(ctx.pool);
    const body = parseJsonObject(signed.body); const agentId = typeof body.agent_id === 'string' ? body.agent_id : '';
    const keyText = typeof body.public_key === 'string' ? body.public_key : '';
    const days = typeof body.expires_in_days === 'number' ? body.expires_in_days : 90;
    const rotate = body.rotate === true;
    const principal = ctx.roles.resolve(agentId); if (principal.persistenceClass !== 'persistent') throw new MusterError(403, 'class_mismatch');
    const key = parsePublicKey(keyText);
    const result = await callPrivileged(
      ctx,
      auth.agentId,
      `SELECT agent_bus.muster_principal_enroll($1,$2,$3,$4,$5) AS result`,
      [agentId, keyText, key.sha256, days, rotate],
    );
    return { status: 201, payload: result };
  }
  if (path === '/v1/break-glass') {
    requireMethod(req, 'POST'); const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireOperator(auth);
    const body = parseJsonObject(signed.body); const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
    if (!reason) throw new MusterError(400, 'invalid_reason');
    const result = await callPrivileged(
      ctx,
      auth.agentId,
      `SELECT agent_bus.muster_break_glass($1) AS result`,
      [reason],
    );
    return { status: 200, payload: result };
  }
  if (path === '/v1/break-glass/recover') {
    requireMethod(req, 'POST'); const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireOperator(auth);
    const body = parseJsonObject(signed.body); const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
    if (!reason) throw new MusterError(400, 'invalid_reason');
    const result = await callPrivileged(
      ctx,
      auth.agentId,
      `SELECT agent_bus.muster_recover_writes($1) AS result`,
      [reason],
    );
    return { status: 200, payload: result };
  }

  if (path === '/v1/north-star') {
    const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireMethod(req, 'GET');
    return { status: 200, payload: await getNorthStar(ctx.pool) };
  }
  if (path === '/v1/north-star/history') {
    const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireMethod(req, 'GET');
    return { status: 200, payload: await northStarHistory(ctx.pool) };
  }
  if (path === '/v1/north-star/mission') {
    const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireMethod(req, 'POST');
    await requireWritable(ctx.pool);
    return { status: 201, payload: await setMission(ctx.pool, auth, parseJsonObject(signed.body)) };
  }
  if (path === '/v1/goals') {
    const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireMethod(req, 'POST');
    await requireWritable(ctx.pool);
    return { status: 201, payload: await upsertGoal(ctx.pool, auth, null, parseJsonObject(signed.body)) };
  }
  const goal = GOAL.exec(path);
  if (goal) {
    const auth = await authenticate(ctx, signed); note.agent = auth.agentId;
    requireMethod(req, 'POST');
    await requireWritable(ctx.pool);
    return { status: 200, payload: await upsertGoal(ctx.pool, auth, goal[1] as string, parseJsonObject(signed.body)) };
  }

  // Stream (design 4.3, 8; OB-60178).
  if (path === '/v1/messages') {
    if (req.method !== 'POST' && req.method !== 'GET') throw new MusterError(405, 'method_not_allowed');
    const auth = await authenticate(ctx, signed);
    note.agent = auth.agentId;
    if (req.method === 'POST') {
      await requireWritable(ctx.pool);
      // OB-60178: the message write path emits nexus.muster.* spans. Design 20.4 override: tracing
      // only, still no Langfuse path in the core (see tracing.ts).
      return runWithSpan(
        'nexus.muster.stream.post',
        { 'muster.http.route': '/v1/messages', 'muster.http.method': 'POST' },
        async (span) => {
          const result = await postMessage(ctx, auth, parseJsonObject(signed.body), span);
          span.setAttribute('muster.result', result.status === 201 ? 'created' : 'replay');
          return result;
        },
      );
    }
    // Pull advances pending → delivered. Other GETs are SELECT-only (registry, conditions, mailbox,
    // delivery-status, north-star, health). Nonce/recent-credential caches are process-local, not
    // durable freeze state. Presence refresh and ACK are already behind requireWritable + in-tx
    // FOR SHARE; inheritMailbox is the same and runs only after those mutating routes.
    await requireWritable(ctx.pool);
    return { status: 200, payload: await listMessages(ctx, auth, searchParams(signed)) };
  }

  const ack = DELIVERY_ACK.exec(path);
  if (ack) {
    requireMethod(req, 'POST');
    const auth = await authenticate(ctx, signed);
    note.agent = auth.agentId;
    requireEmptyObjectBody(signed.body);
    await requireWritable(ctx.pool);
    return { status: 200, payload: await ackDelivery(ctx, auth, ack[1] as string) };
  }

  // Conditions (design 4.2; OB-60178). Slice 1 effects are annotate-only.
  if (path === '/v1/conditions') {
    if (req.method !== 'POST' && req.method !== 'GET') throw new MusterError(405, 'method_not_allowed');
    const auth = await authenticate(ctx, signed);
    note.agent = auth.agentId;
    if (req.method === 'POST') {
      await requireWritable(ctx.pool);
      return runWithSpan(
        'nexus.muster.conditions.declare',
        { 'muster.http.route': '/v1/conditions', 'muster.http.method': 'POST' },
        async () => ({ status: 201, payload: await declareCondition(ctx, auth, parseJsonObject(signed.body)) }),
      );
    }
    return { status: 200, payload: await listConditions(ctx, searchParams(signed)) };
  }

  const clear = CONDITION_CLEAR.exec(path);
  if (clear) {
    requireMethod(req, 'POST');
    const auth = await authenticate(ctx, signed);
    note.agent = auth.agentId;
    requireEmptyObjectBody(signed.body);
    await requireWritable(ctx.pool);
    return runWithSpan(
      'nexus.muster.conditions.clear',
      { 'muster.http.route': '/v1/conditions/{id}/clear', 'muster.http.method': 'POST' },
      async () => ({ status: 200, payload: await clearCondition(ctx, auth, clear[1] as string) }),
    );
  }

  throw new MusterError(404, 'not_found');
}

export function createMusterServer(ctx: MusterContext): http.Server {
  return http.createServer((req, res) => {
    const started = Date.now();
    const url = req.url ?? '/';
    const path = url.split('?')[0] ?? '/';
    const logPath = /^\/[A-Za-z0-9/_-]{0,64}$/.test(path) ? path : '<invalid-path>';
    const method = /^[A-Z]{1,10}$/.test(req.method ?? '') ? req.method : '<invalid-method>';
    const note = { agent: '-' };
    let status = 500;
    // Unauthenticated failures spend a per-source budget, never the global one (AR XB-04).
    const failureKey = `failures:${req.socket.remoteAddress ?? 'unknown'}`;

    readBody(req)
      .then((body) => {
        const signed: SignedRequest = { method: req.method ?? 'GET', pathWithQuery: url, headers: req.headers, body };
        if (path !== '/health' && ctx.failureLimiter.exhausted(failureKey, ctx.limits.failuresPerSecond, ctx.limits.failureBurst)) {
          const credential = signedCredential(req);
          if (!credential) {
            throw new MusterError(429, 'rate_limited', undefined, Math.max(1, Math.ceil(1 / ctx.limits.failuresPerSecond)));
          }
          const recent = ctx.recent.get(credential.id);
          if (!recent || !provesRecentPossession(ctx, signed, credential.canonical, recent)) {
            ctx.limiter.takeRate('candidates', ctx.limits.candidatesPerSecond, ctx.limits.candidateBurst);
          }
        }
        return route(ctx, req, path, signed, note);
      })
      .then((result) => {
        status = result.status;
        send(res, status, result.payload, result.headers ?? {});
      })
      .catch((err: unknown) => {
        if (err instanceof MusterError) {
          status = err.status;
          if ([400, 401, 404, 405, 413].includes(status)) {
            ctx.failureLimiter.charge(failureKey, ctx.limits.failuresPerSecond, ctx.limits.failureBurst);
          }
          if (err.code === 'read_only') ctx.logger.log(`${method} ${logPath} kill-switch read-only`);
          else if (status >= 500) ctx.logger.logMinimal(`${method} ${logPath} failed: ${err.code}`);
          else ctx.logger.logVerbose(`${method} ${logPath} rejected: ${err.code}`);
          const headers: Record<string, string> = {};
          if (err.retryAfterSeconds !== undefined) headers['retry-after'] = String(err.retryAfterSeconds);
          if (status === 413) headers.connection = 'close';
          send(res, status, { error: err.code }, headers);
          return;
        }
        // Anything unexpected, including a database or revocation-store failure, fails closed.
        status = 503;
        ctx.logger.logMinimal(`${method} ${logPath} failed closed: ${describeError(err)}`);
        send(res, status, { error: 'unavailable' });
      })
      .finally(() => {
        const durationMs = Date.now() - started;
        ctx.metrics?.observe(method === '<invalid-method>' ? 'other' : (req.method ?? 'other'), path, status, durationMs);
        ctx.logger.log(`${method} ${logPath} ${status} agent=${note.agent} ${durationMs}ms`);
      });
  });
}
