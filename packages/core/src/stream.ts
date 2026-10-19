import type { Span } from '@opentelemetry/api';
import type pg from 'pg';
import type { Queryable } from './binding.js';
import { isUniqueViolation, withTransaction, assertWritable } from './db.js';
import { MusterError } from './errors.js';
import type { AuthContext, MusterContext } from './identity.js';
import type { RateReservation } from './rate-limit.js';
import { isValidAgentId } from './roles.js';
import { runWithSpan } from './tracing.js';

/**
 * The stream (design 4.3, 8, 20.2; OB-60178). A message is a row in agent_bus.messages plus a companion
 * envelope. Every addressed role or named agent is a durable, append-only route (AR S-01), and delivery
 * rows are the obligation ledger. Role resolution follows the normative slice 1 order (AR R-07):
 *   1. every live holder of the role;
 *   2. else the live owner, plus a system-authored flag recording the fallback;
 *   3. else the role's unassigned mailbox, whose platform alarm is raised by Nexus log-monitor (AR R-04);
 *   4. the next live holder, or the owner when no holder is live, inherits the mailbox in order.
 * Slice 1 is advisory: nothing here releases a hold or transfers authority.
 */

export const MESSAGE_TYPES = ['status', 'intent', 'done', 'ask', 'flag'] as const;
export type MessageType = (typeof MESSAGE_TYPES)[number];
/** Specified by the design but not client-writable in slice 1: `dark` is system-authored (delta 12). */
const RESERVED_TYPES = new Set(['dark', 'delegate', 'decide']);
export const SPEC_VERSION = 'muster-stream/1';
/** Author of system messages (owner-fallback flags). Never an enrollable principal. */
export const SYSTEM_AUTHOR = 'muster';
/** Cap on binding-declared extra pushes per client message (OB-60291). */
const MAX_EXTRA_PUSHES = 8;
/** Roles that may address a named agent that is dark or not registered (design 4.3). */
export const PRIVILEGED_ROLES: readonly string[] = ['cos', 'operator'];
/**
 * Roles that may stamp message_envelopes.alert_class. The Muster stream design does not name a
 * #alerts routing allowlist, so this is the production writer allowlist: platform-health,
 * platform-ops, and security. Body JSON never classifies alerts.
 */
export const ALERT_CLASS_ROLES: readonly string[] = ['platform-health', 'platform-ops', 'security'];
export const ALERT_CLASSES = ['high', 'critical'] as const;
export type AlertClass = (typeof ALERT_CLASSES)[number];
export const MAX_MESSAGE_BODY_CHARS = 16_000;
export const MAX_TARGETS = 16;
export const MAX_READ_LIMIT = 200;
export const MAILBOX_INHERIT_BATCH = 100;

const IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:@-]{8,128}$/;
const LABEL = /^[\x20-\x7E]{1,200}$/;
const ROLE_NAME = /^[a-z][a-z0-9-]{0,63}$/;
const MESSAGE_ID = /^[0-9]{1,18}$/;
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Presence computed from server time on every read, the same rule GET /v1/registry uses (design 4.1). */
const LIVE = `tombstoned_at IS NULL AND last_seen_at IS NOT NULL
  AND last_seen_at >= now() - make_interval(secs => ttl_seconds)`;
const NOT_DARK = `tombstoned_at IS NULL AND last_seen_at IS NOT NULL
  AND last_seen_at >= now() - make_interval(secs => 2 * ttl_seconds)`;

export type Resolution = 'holders' | 'owner' | 'mailbox' | 'agent';

export interface PostedRoute {
  target_kind: 'role' | 'agent';
  target: string;
  route_id: string;
  resolution?: Resolution;
  recipients: string[];
}

export interface PostInput {
  type: MessageType;
  toRoles: string[];
  toAgents: string[];
  body: string;
  task: string | null;
  workRef: string | null;
  inReplyTo: string | null;
  idempotencyKey: string;
  alertClass: AlertClass | null;
}

interface Recipient {
  agentId: string;
  runtime: string;
}

const POST_FIELDS = new Set(['type', 'to_roles', 'to_agents', 'body', 'task', 'work_ref', 'in_reply_to', 'idempotency_key', 'alert_class']);

function optionalLabel(value: unknown, code: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !LABEL.test(value)) throw new MusterError(400, code);
  return value;
}

function targetList(value: unknown, check: (s: string) => boolean, code: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_TARGETS) throw new MusterError(400, code);
  const out = new Set<string>();
  for (const item of value) {
    if (typeof item !== 'string' || !check(item)) throw new MusterError(400, code);
    out.add(item);
  }
  return [...out];
}

/**
 * Validates a client message. The server sets author, sequence, and timestamp (delta 1), so those fields
 * are rejected, as are unknown types (delta 4). The body is stored as data and never interpreted (delta 3).
 */
export function parsePostBody(body: Record<string, unknown>): PostInput {
  for (const key of Object.keys(body)) {
    if (!POST_FIELDS.has(key)) throw new MusterError(400, 'unsupported_field');
  }
  const type = body.type;
  if (typeof type !== 'string') throw new MusterError(400, 'invalid_type');
  if (RESERVED_TYPES.has(type)) throw new MusterError(400, 'reserved_type');
  if (!(MESSAGE_TYPES as readonly string[]).includes(type)) throw new MusterError(400, 'unknown_type');
  const toRoles = targetList(body.to_roles, (s) => ROLE_NAME.test(s), 'invalid_to_roles');
  const toAgents = targetList(body.to_agents, isValidAgentId, 'invalid_to_agents');
  if (toRoles.length + toAgents.length === 0) throw new MusterError(400, 'no_recipients');
  if (toRoles.length + toAgents.length > MAX_TARGETS) throw new MusterError(400, 'too_many_recipients');
  if (typeof body.body !== 'string' || body.body.length === 0 || body.body.length > MAX_MESSAGE_BODY_CHARS) {
    throw new MusterError(400, 'invalid_body');
  }
  if (typeof body.idempotency_key !== 'string' || !IDEMPOTENCY_KEY.test(body.idempotency_key)) {
    throw new MusterError(400, 'invalid_idempotency_key');
  }
  let inReplyTo: string | null = null;
  if (body.in_reply_to !== undefined && body.in_reply_to !== null) {
    if (typeof body.in_reply_to !== 'number' || !Number.isSafeInteger(body.in_reply_to) || body.in_reply_to <= 0) {
      throw new MusterError(400, 'invalid_in_reply_to');
    }
    inReplyTo = String(body.in_reply_to);
  }
  let alertClass: AlertClass | null = null;
  if (body.alert_class !== undefined && body.alert_class !== null) {
    if (typeof body.alert_class !== 'string' || !(ALERT_CLASSES as readonly string[]).includes(body.alert_class)) {
      throw new MusterError(400, 'invalid_alert_class');
    }
    alertClass = body.alert_class as AlertClass;
  }
  return {
    type: type as MessageType,
    toRoles,
    toAgents,
    body: body.body,
    task: optionalLabel(body.task, 'invalid_task'),
    workRef: optionalLabel(body.work_ref, 'invalid_work_ref'),
    inReplyTo,
    idempotencyKey: body.idempotency_key,
    alertClass,
  };
}

export function isPrivileged(auth: AuthContext): boolean {
  return auth.principal.roles.some((r) => PRIVILEGED_ROLES.includes(r));
}

export function canStampAlertClass(auth: AuthContext): boolean {
  return auth.principal.roles.some((r) => ALERT_CLASS_ROLES.includes(r));
}

export async function listRoleMailbox(ctx: MusterContext, auth: AuthContext): Promise<unknown> {
  if (!isPrivileged(auth)) throw new MusterError(403, 'management_forbidden');
  const { rows } = await ctx.pool.query(`SELECT mailbox_id, target_role, message_id, created_at, inherited_by_agent_id, inherited_at
    FROM agent_bus.role_mailbox WHERE inherited_at IS NULL ORDER BY created_at LIMIT 200`);
  return { entries: rows };
}

export async function deliveryStatus(ctx: MusterContext, auth: AuthContext, messageId: string): Promise<unknown> {
  if (!isPrivileged(auth)) throw new MusterError(403, 'management_forbidden');
  if (!MESSAGE_ID.test(messageId)) throw new MusterError(400, 'invalid_message_id');
  const { rows } = await ctx.pool.query(`SELECT delivery_id, recipient_agent_id, adapter, state, delivered_at, acked_at
    FROM agent_bus.deliveries WHERE message_id = $1::bigint ORDER BY recipient_agent_id`, [messageId]);
  return { message_id: messageId, deliveries: rows };
}

/**
 * Design 6 rule 3: both sides must allow it. The sender's roles must list the target role in may_address,
 * and the target role's addressable_by must include one of the sender's roles.
 */
export function roleAddressable(ctx: MusterContext, auth: AuthContext, role: string): boolean {
  const spec = ctx.roles.roles.get(role);
  if (!spec) return false;
  return auth.principal.mayAddress.includes(role) && spec.addressableBy.some((r) => auth.principal.roles.includes(r));
}

/**
 * The delivery adapter for a recipient runtime. Push adapters are deployment knowledge, so the binding
 * names them (design section 9); without one, every recipient pulls through the API.
 */
export function adapterFor(ctx: MusterContext, runtime: string): string {
  return ctx.binding.deliveryAdapterFor(runtime) ?? PULL_ADAPTER;
}

/** Recipients read these through GET /v1/messages; reading marks them delivered. */
export const PULL_ADAPTER = 'api';

async function lockKey(client: Queryable, key: string): Promise<void> {
  await client.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [key]);
}

/** Every live holder of the role; `excludeAgentId` only for the inheritance "is another holder live" check. */
async function liveHolders(client: Queryable, role: string, excludeAgentId: string | null = null): Promise<Recipient[]> {
  const { rows } = await client.query<{ agent_id: string; runtime: string }>(
    `SELECT agent_id, runtime FROM agent_bus.registry_entries
      WHERE $1 = ANY (roles) AND ($2::text IS NULL OR agent_id <> $2) AND ${LIVE}
      ORDER BY agent_id`,
    [role, excludeAgentId],
  );
  return rows.map((r) => ({ agentId: r.agent_id, runtime: r.runtime }));
}

async function liveEntry(client: Queryable, agentId: string): Promise<Recipient | null> {
  const { rows } = await client.query<{ agent_id: string; runtime: string }>(
    `SELECT agent_id, runtime FROM agent_bus.registry_entries WHERE agent_id = $1 AND ${LIVE}`,
    [agentId],
  );
  return rows[0] ? { agentId: rows[0].agent_id, runtime: rows[0].runtime } : null;
}

interface AgentTarget {
  runtime: string;
  roles: string[];
  notDark: boolean;
}

async function loadAgentTargets(client: Queryable, agentIds: string[]): Promise<Map<string, AgentTarget>> {
  if (agentIds.length === 0) return new Map();
  const { rows } = await client.query<{ agent_id: string; runtime: string; roles: string[]; not_dark: boolean }>(
    `SELECT agent_id, runtime, roles, (${NOT_DARK}) AS not_dark
       FROM agent_bus.registry_entries
      WHERE agent_id = ANY ($1::text[]) AND tombstoned_at IS NULL`,
    [agentIds],
  );
  return new Map(rows.map((r) => [r.agent_id, { runtime: r.runtime, roles: r.roles, notDark: r.not_dark === true }]));
}

async function launcherOf(client: Queryable, jti: string): Promise<string | null> {
  const { rows } = await client.query<{ launcher_agent_id: string | null }>(
    `SELECT r.launcher_agent_id
       FROM agent_bus.issued_tokens t
       JOIN agent_bus.registration_requests r ON r.request_id = t.request_id
      WHERE t.jti = $1`,
    [jti],
  );
  return rows[0]?.launcher_agent_id ?? null;
}

interface MessageRow {
  id: string;
  ts: Date;
}

async function insertMessage(
  client: Queryable,
  m: { author: string; type: MessageType; recipientLabel: string; task: string | null; body: string; inReplyTo: string | null; idempotencyKey: string; threadId: string | null; workRef: string | null; alertClass?: AlertClass | null },
): Promise<MessageRow> {
  const { rows } = await client.query<MessageRow>(
    `INSERT INTO agent_bus.messages (author, recipient, msg_type, task, body, in_reply_to)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id::text AS id, ts`,
    [m.author, m.recipientLabel, m.type, m.task, m.body, m.inReplyTo],
  );
  const message = rows[0] as MessageRow;
  await client.query(
    `INSERT INTO agent_bus.message_envelopes (message_id, author_agent_id, idempotency_key, spec_version, thread_id, work_ref, alert_class)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [message.id, m.author, m.idempotencyKey, SPEC_VERSION, m.threadId, m.workRef, m.alertClass ?? null],
  );
  return message;
}

async function insertRoute(client: Queryable, messageId: string, kind: 'role' | 'agent', target: string): Promise<string> {
  const { rows } = await client.query<{ route_id: string }>(
    `INSERT INTO agent_bus.message_routes (message_id, target_kind, target_role, target_agent_id)
     VALUES ($1, $2, $3, $4)
     RETURNING route_id::text AS route_id`,
    [messageId, kind, kind === 'role' ? target : null, kind === 'agent' ? target : null],
  );
  return (rows[0] as { route_id: string }).route_id;
}

/** Extra-push routes reuse a client-addressed agent route instead of failing the unique target constraint. */
async function insertAgentRoute(client: Queryable, messageId: string, agentId: string): Promise<string> {
  const { rows } = await client.query<{ route_id: string }>(
    `INSERT INTO agent_bus.message_routes (message_id, target_kind, target_role, target_agent_id)
     VALUES ($1, 'agent', NULL, $2)
     ON CONFLICT ON CONSTRAINT message_routes_target_unique DO NOTHING
     RETURNING route_id::text AS route_id`,
    [messageId, agentId],
  );
  if (rows[0]) return rows[0].route_id;
  const existing = await client.query<{ route_id: string }>(
    `SELECT route_id::text AS route_id FROM agent_bus.message_routes
      WHERE message_id = $1::bigint AND target_kind = 'agent' AND target_agent_id = $2`,
    [messageId, agentId],
  );
  const routeId = existing.rows[0]?.route_id;
  if (!routeId) throw new MusterError(503, 'unavailable');
  return routeId;
}

/** What a post's transaction created, checked against capacity and reserved from the adapter budgets before commit (AR ZA-03, ZB-01). */
interface WriteTally {
  pushes: number;
  adapters: Map<string, number>;
}

/**
 * A pending delivery, plus its outbox row in the same transaction for push adapters (design 20.2). Pull
 * deliveries have no outbox row. With a tally, the delivery is counted toward the post's capacity and budgets.
 */
async function insertDelivery(ctx: MusterContext, client: Queryable, routeId: string, messageId: string, recipient: Recipient, tally?: WriteTally): Promise<string | null> {
  const adapter = adapterFor(ctx, recipient.runtime);
  const { rows } = await client.query<{ delivery_id: string }>(
    `INSERT INTO agent_bus.deliveries (route_id, message_id, recipient_agent_id, adapter)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (route_id, recipient_agent_id, adapter, resolution_generation) DO NOTHING
     RETURNING delivery_id`,
    [routeId, messageId, recipient.agentId, adapter],
  );
  const deliveryId = rows[0]?.delivery_id ?? null;
  if (deliveryId && tally) tally.adapters.set(adapter, (tally.adapters.get(adapter) ?? 0) + 1);
  if (deliveryId && adapter !== PULL_ADAPTER) {
    await client.query(`INSERT INTO agent_bus.delivery_outbox (delivery_id, adapter) VALUES ($1, $2)`, [deliveryId, adapter]);
    if (tally) tally.pushes += 1;
  }
  return deliveryId;
}

function extraPushAgentIds(ctx: MusterContext): Set<string> {
  return new Set(ctx.binding.extraPushRecipients().map((e) => e.agentId));
}

async function findReplay(
  ctx: MusterContext,
  client: Queryable,
  author: string,
  idempotencyKey: string,
): Promise<Record<string, unknown> | null> {
  const { rows } = await client.query<{ message_id: string; ts: Date; author: string; type: string }>(
    `SELECT m.id::text AS message_id, m.ts, m.author, m.msg_type AS type
       FROM agent_bus.message_envelopes e
       JOIN agent_bus.messages m ON m.id = e.message_id
      WHERE e.author_agent_id = $1 AND e.idempotency_key = $2`,
    [author, idempotencyKey],
  );
  const message = rows[0];
  if (!message) return null;
  const extras = extraPushAgentIds(ctx);
  const { rows: routes } = await client.query<{ route_id: string; target_kind: 'role' | 'agent'; target: string; recipients: string[] | null }>(
    `SELECT r.route_id::text AS route_id, r.target_kind, COALESCE(r.target_role, r.target_agent_id) AS target,
            array_remove(array_agg(DISTINCT d.recipient_agent_id), NULL) AS recipients
       FROM agent_bus.message_routes r
       LEFT JOIN agent_bus.deliveries d ON d.route_id = r.route_id AND d.message_id = r.message_id
      WHERE r.message_id = $1
      GROUP BY r.route_id, r.target_kind, r.target_role, r.target_agent_id
      ORDER BY r.route_id`,
    [message.message_id],
  );
  return {
    ...message,
    idempotent_replay: true,
    routes: routes
      .filter((r) => !(r.target_kind === 'agent' && extras.has(r.target)))
      .map((r) => ({ target_kind: r.target_kind, target: r.target, route_id: r.route_id, recipients: r.recipients ?? [] })),
  };
}

/**
 * Binding-declared extra pushes for a client-authored message (OB-60291, design 12). System-authored
 * owner-fallback flags are not mirrored. Pull extras are skipped so an unwired binding is a no-op.
 * These routes are not returned in the client `routes` payload.
 */
async function insertBindingPushes(
  ctx: MusterContext,
  client: Queryable,
  messageId: string,
  author: string,
  tally: WriteTally,
): Promise<void> {
  if (author === SYSTEM_AUTHOR) return;
  const seen = new Set<string>();
  for (const extra of ctx.binding.extraPushRecipients().slice(0, MAX_EXTRA_PUSHES)) {
    if (!isValidAgentId(extra.agentId)) {
      throw new MusterError(503, 'binding_error', 'binding returned an invalid extra push recipient');
    }
    if (seen.has(extra.agentId)) continue;
    seen.add(extra.agentId);
    if (adapterFor(ctx, extra.runtime) === PULL_ADAPTER) continue;
    const routeId = await insertAgentRoute(client, messageId, extra.agentId);
    await insertDelivery(ctx, client, routeId, messageId, extra, tally);
  }
}

async function insertOwnerFallbackFlag(ctx: MusterContext, client: Queryable, messageId: string, role: string, owner: Recipient, tally: WriteTally): Promise<void> {
  const flag = await insertMessage(client, {
    author: SYSTEM_AUTHOR,
    type: 'flag',
    recipientLabel: `agent:${owner.agentId}`,
    task: null,
    body: `No live holder for role ${role}; message ${messageId} was delivered to you as the role owner.`,
    inReplyTo: messageId,
    idempotencyKey: `owner-fallback:${messageId}:${role}`,
    threadId: messageId,
    workRef: null,
  });
  const routeId = await insertRoute(client, flag.id, 'agent', owner.agentId);
  await insertDelivery(ctx, client, routeId, flag.id, owner, tally);
}

/** POST /v1/messages. 201 with the resolved routes; an idempotent replay returns the original with 200. */
export async function postMessage(
  ctx: MusterContext,
  auth: AuthContext,
  raw: Record<string, unknown>,
  parentSpan?: Span,
): Promise<{ status: number; payload: unknown }> {
  const input = parsePostBody(raw);
  const author = auth.agentId;
  parentSpan?.setAttribute('muster.message.type', input.type);
  if (author === SYSTEM_AUTHOR) throw new MusterError(403, 'reserved_author');
  if (input.alertClass && (input.type !== 'flag' || !canStampAlertClass(auth))) {
    throw new MusterError(403, 'alert_class_not_permitted');
  }

  const replay = await findReplay(ctx, ctx.pool, author, input.idempotencyKey);
  if (replay) return { status: 200, payload: replay };

  for (const role of input.toRoles) {
    if (!ctx.roles.roles.has(role)) throw new MusterError(400, 'unknown_role');
    if (!roleAddressable(ctx, auth, role)) throw new MusterError(403, 'not_addressable');
  }
  const privileged = isPrivileged(auth);
  const agentTargets = await loadAgentTargets(ctx.pool, input.toAgents);
  for (const agentId of input.toAgents) {
    const target = agentTargets.get(agentId);
    if (!target) {
      if (!privileged) throw new MusterError(403, 'recipient_not_registered');
      continue;
    }
    if (!target.roles.some((r) => roleAddressable(ctx, auth, r))) throw new MusterError(403, 'not_addressable');
    if (!target.notDark && !privileged) throw new MusterError(403, 'recipient_dark');
  }

  // Layered write budgets (design 20.4, AR S-04); the per-agent budget was spent in authenticate(). All of them
  // are reserved in one synchronous step, so a concurrent burst cannot pass on the same token (AR ZB-01), and
  // the reservation is refunded unless the write commits, so a replay or a refused (429 or 503) write spends
  // nothing (AR ZA-04).
  const budgets: Array<[string, number]> = [['messages:global', ctx.limits.messagesGlobalPerMinute]];
  for (const role of input.toRoles) budgets.push([`messages:role:${role}`, ctx.limits.messagesPerRolePerMinute]);
  if (auth.persistenceClass === 'ephemeral') {
    // Every runner one launcher brokered shares one budget, so many exact ephemeral ids cannot sum past it.
    const launcher = await launcherOf(ctx.pool, auth.jti);
    if (launcher) budgets.push([`messages:launcher:${launcher}`, ctx.limits.launcherMessagesPerMinute]);
  }
  const reservations: RateReservation[] = [ctx.limiter.reserve(budgets.map(([key, perMinute]) => ({ key, perMinute })))];

  const recipientLabel = [...input.toRoles.map((r) => `role:${r}`), ...input.toAgents.map((a) => `agent:${a}`)].join(',');
  const tally: WriteTally = { pushes: 0, adapters: new Map() };

  try {
    const result = await runWithSpan(
      'nexus.muster.stream.write',
      { 'muster.message.type': input.type, 'muster.author': author },
      async (span) => {
        const inner = await withTransaction(ctx.pool, async (client) => {
          await assertWritable(client);
          await lockKey(client, `muster:author:${author}`);
          const again = await findReplay(ctx, client, author, input.idempotencyKey);
          if (again) return { status: 200, payload: again };

          // Lock order, shared with inheritMailbox so they can never deadlock: the outbox, then every addressed
          // role in sorted order. The outbox lock makes the capacity count and this post's pushed deliveries one
          // serialized unit (AR ZA-03); the role locks serialize resolution and mailbox insertion with a
          // concurrent presence write's inheritance, and resolution below reads presence after taking them (AR ZA-02).
          await lockKey(client, 'muster:outbox');
          for (const role of [...input.toRoles].sort()) await lockKey(client, `muster:mailbox:${role}`);

          // Bounded outbox, partitioned per adapter (OB-60413): a stalled adapter must only block writes
          // that would push through THAT adapter, not every post — including pull-only traffic, which never
          // touches delivery_outbox at all (insertDelivery skips the outbox insert for PULL_ADAPTER). This
          // post's own target adapters are not known until routing/tally below, so the capacity check happens
          // once, after the tally, scoped per adapter (see below) — a single global pre-check here would 503
          // posts that end up touching no saturated adapter at all, which was exactly the bug (design 20.4's
          // original global count 503'd unrelated-adapter posts whenever any one adapter's queue backed up).

          let threadId: string | null = null;
          if (input.inReplyTo) {
            const { rows } = await client.query<{ thread_id: string }>(
              `SELECT COALESCE(e.thread_id, m.id)::text AS thread_id
                 FROM agent_bus.messages m
                 LEFT JOIN agent_bus.message_envelopes e ON e.message_id = m.id
                WHERE m.id = $1`,
              [input.inReplyTo],
            );
            const parent = rows[0];
            if (!parent) throw new MusterError(400, 'in_reply_to_not_found');
            threadId = parent.thread_id;
          }

          const message = await insertMessage(client, {
            author,
            type: input.type,
            recipientLabel,
            task: input.task,
            body: input.body,
            inReplyTo: input.inReplyTo,
            idempotencyKey: input.idempotencyKey,
            threadId,
            workRef: input.workRef,
            alertClass: input.alertClass,
          });

          const routes: PostedRoute[] = [];
          const ownerFlags: Array<{ role: string; owner: Recipient }> = [];
          for (const role of input.toRoles) {
            const routeId = await insertRoute(client, message.id, 'role', role);
            // Every live holder, the author included: the design has no self-holder exception (AR ZA-01).
            const holders = await liveHolders(client, role);
            if (holders.length > 0) {
              for (const holder of holders) await insertDelivery(ctx, client, routeId, message.id, holder, tally);
              routes.push({ target_kind: 'role', target: role, route_id: routeId, resolution: 'holders', recipients: holders.map((h) => h.agentId) });
              continue;
            }
            const ownerId = (ctx.roles.roles.get(role) as { owner: string }).owner;
            const owner = await liveEntry(client, ownerId);
            if (owner) {
              await insertDelivery(ctx, client, routeId, message.id, owner, tally);
              ownerFlags.push({ role, owner });
              routes.push({ target_kind: 'role', target: role, route_id: routeId, resolution: 'owner', recipients: [owner.agentId] });
              continue;
            }
            const { rows: waiting } = await client.query<{ n: number }>(
              `SELECT count(*)::int AS n FROM agent_bus.role_mailbox WHERE target_role = $1 AND inherited_at IS NULL`,
              [role],
            );
            if ((waiting[0]?.n ?? 0) >= ctx.limits.mailboxCapacityPerRole) {
              ctx.logger.logMinimal(`overloaded: unassigned mailbox for role ${role} has ${waiting[0]?.n} waiting (capacity ${ctx.limits.mailboxCapacityPerRole})`);
              throw new MusterError(503, 'overloaded');
            }
            await client.query(`INSERT INTO agent_bus.role_mailbox (route_id, message_id, target_role) VALUES ($1, $2, $3)`, [routeId, message.id, role]);
            ctx.logger.log(`role ${role} has no live holder or owner; message ${message.id} held in its mailbox`);
            routes.push({ target_kind: 'role', target: role, route_id: routeId, resolution: 'mailbox', recipients: [] });
          }
          for (const agentId of input.toAgents) {
            const routeId = await insertRoute(client, message.id, 'agent', agentId);
            const runtime = agentTargets.get(agentId)?.runtime ?? 'unknown';
            await insertDelivery(ctx, client, routeId, message.id, { agentId, runtime }, tally);
            routes.push({ target_kind: 'agent', target: agentId, route_id: routeId, resolution: 'agent', recipients: [agentId] });
          }
          for (const { role, owner } of ownerFlags) await insertOwnerFallbackFlag(ctx, client, message.id, role, owner, tally);
          await insertBindingPushes(ctx, client, message.id, author, tally);

          // Capacity counts this post's own pushed deliveries before it commits (AR ZA-03), partitioned per
          // adapter (OB-60413): the count below is taken after this transaction's own inserts above, so it
          // already reflects them — a plain per-adapter read of the same table this post just wrote to, still
          // inside the `muster:outbox` lock, so no concurrent post can race it (AR ZA-03 still holds, now
          // per adapter instead of globally). Gated on tally.pushes (not tally.adapters.size): insertDelivery
          // records every successful delivery in tally.adapters regardless of adapter, but only increments
          // tally.pushes for a push adapter (PULL_ADAPTER rows never reach delivery_outbox at all) — a post
          // that pushed nothing (pull-only recipients) skips this entirely, and PULL_ADAPTER is excluded from
          // the loop below on the same principle, so a future change to that guard cannot silently make this
          // check start comparing a pull adapter's (always-zero) backlog against capacity.
          if (tally.pushes > 0) {
            const { rows: perAdapterBacklog } = await client.query<{ adapter: string; n: number }>(
              `SELECT adapter, count(*)::int AS n FROM agent_bus.delivery_outbox WHERE claimed_at IS NULL GROUP BY adapter`,
            );
            const backlogByAdapter = new Map(perAdapterBacklog.map((r) => [r.adapter, r.n]));
            for (const adapter of tally.adapters.keys()) {
              if (adapter === PULL_ADAPTER) continue;
              const adapterCount = backlogByAdapter.get(adapter) ?? 0;
              if (adapterCount > ctx.limits.outboxCapacity) {
                ctx.logger.logMinimal(`overloaded: post would raise the ${adapter} delivery outbox to ${adapterCount} (capacity ${ctx.limits.outboxCapacity})`);
                throw new MusterError(503, 'overloaded');
              }
            }
          }
          // Reserved while the outbox lock serializes posts, so the per-adapter budget also admits atomically (AR ZB-01).
          reservations.push(
            ctx.limiter.reserve(
              [...tally.adapters].map(([adapter, count]) => ({
                key: `deliveries:adapter:${adapter}`,
                perMinute: ctx.limits.deliveriesPerAdapterPerMinute,
                count,
              })),
            ),
          );

          return { status: 201, payload: { message_id: message.id, ts: message.ts, author, type: input.type, routes } };
        });
        if (inner.status === 201) {
          const payload = inner.payload as { message_id: string; routes: PostedRoute[] };
          span.setAttribute('muster.route.count', payload.routes.length);
          span.setAttribute('muster.recipient.count', payload.routes.reduce((n, r) => n + r.recipients.length, 0));
        }
        span.setAttribute('muster.result', inner.status === 201 ? 'created' : 'replay');
        return inner;
      },
      parentSpan,
    );
    if (result.status !== 201) for (const reservation of reservations) reservation.release();
    return result;
  } catch (err) {
    for (const reservation of reservations) reservation.release();
    // A concurrent identical write that slipped past the author lock returns the stored original.
    if (isUniqueViolation(err, 'message_envelopes_author_agent_id_idempotency_key_key')) {
      const winner = await findReplay(ctx, ctx.pool, author, input.idempotencyKey);
      if (winner) return { status: 200, payload: winner };
    }
    throw err;
  }
}

function parseSince(value: string | null): string {
  if (value === null) return '0';
  if (!MESSAGE_ID.test(value)) throw new MusterError(400, 'invalid_since');
  return value;
}

function parseLimit(value: string | null): number {
  if (value === null) return 100;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_READ_LIMIT) throw new MusterError(400, 'invalid_limit');
  return n;
}

/**
 * GET /v1/messages?since=&limit=. The caller's delivery rows are its cursor (design 20.2): it sees only
 * messages delivered to it. Reading marks its pull (`api` adapter) deliveries delivered. Serving without
 * that transition would duplicate processing after recovery, so a freeze returns 423 and transitions
 * nothing. The FOR SHARE check is in the same transaction as the UPDATE so a pull that began before
 * break-glass cannot commit after the freeze.
 */
export async function listMessages(ctx: MusterContext, auth: AuthContext, params: URLSearchParams): Promise<unknown> {
  for (const key of params.keys()) {
    if (key !== 'since' && key !== 'limit') throw new MusterError(400, 'unsupported_query');
  }
  const since = parseSince(params.get('since'));
  const limit = parseLimit(params.get('limit'));
  return withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    const { rows } = await client.query<{ message_id: string; delivery_id: string; adapter: string; state: string } & Record<string, unknown>>(
      `SELECT m.id::text AS message_id, m.ts, m.author, m.msg_type AS type, m.task, m.body,
              m.in_reply_to::text AS in_reply_to, e.work_ref, e.thread_id::text AS thread_id,
              d.delivery_id, d.state, d.adapter, r.target_kind, COALESCE(r.target_role, r.target_agent_id) AS target
         FROM agent_bus.deliveries d
         JOIN agent_bus.messages m ON m.id = d.message_id
         JOIN agent_bus.message_routes r ON r.route_id = d.route_id AND r.message_id = d.message_id
         LEFT JOIN agent_bus.message_envelopes e ON e.message_id = m.id
        WHERE d.recipient_agent_id = $1 AND d.message_id > $2 AND d.state IN ('pending', 'delivered', 'acked')
        ORDER BY d.message_id, d.delivery_id
        LIMIT $3`,
      [auth.agentId, since, limit],
    );
    const pending = rows.filter((r) => r.adapter === PULL_ADAPTER && r.state === 'pending').map((r) => r.delivery_id);
    if (pending.length > 0) {
      const { rows: marked } = await client.query<{ delivery_id: string }>(
        `UPDATE agent_bus.deliveries
            SET state = 'delivered', delivered_at = now(), adapter_ref = 'api:read', version = version + 1
          WHERE delivery_id = ANY ($1::uuid[]) AND recipient_agent_id = $2 AND adapter = $3 AND state = 'pending'
          RETURNING delivery_id`,
        [pending, auth.agentId, PULL_ADAPTER],
      );
      const delivered = new Set(marked.map((m) => m.delivery_id));
      for (const row of rows) if (delivered.has(row.delivery_id)) row.state = 'delivered';
    }
    return { messages: rows, next_since: rows.length > 0 ? (rows[rows.length - 1] as { message_id: string }).message_id : since };
  });
}

/** POST /v1/deliveries/{id}/ack. Recipient only; delivered -> acked; a repeat ack is idempotent. */
export async function ackDelivery(ctx: MusterContext, auth: AuthContext, deliveryId: string): Promise<unknown> {
  if (!UUID_PATTERN.test(deliveryId)) throw new MusterError(400, 'invalid_delivery_id');
  return withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    const { rows } = await client.query(
      `UPDATE agent_bus.deliveries SET state = 'acked', acked_at = now(), version = version + 1
        WHERE delivery_id = $1 AND recipient_agent_id = $2 AND state = 'delivered'
        RETURNING delivery_id`,
      [deliveryId, auth.agentId],
    );
    if (rows[0]) return { delivery_id: deliveryId, state: 'acked' };
    const { rows: current } = await client.query<{ state: string }>(
      `SELECT state FROM agent_bus.deliveries WHERE delivery_id = $1 AND recipient_agent_id = $2`,
      [deliveryId, auth.agentId],
    );
    const found = current[0];
    if (!found) throw new MusterError(404, 'delivery_not_found');
    if (found.state === 'acked') return { delivery_id: deliveryId, state: 'acked' };
    throw new MusterError(409, 'delivery_not_ackable');
  });
}

/**
 * Hands waiting mailbox messages to a live agent, in enqueue order (design 20.2, AR R-04). A holder of the
 * role inherits; the role owner inherits only while no holder is live. Called after first-hand presence
 * and registration. Returns the number of mailbox entries inherited.
 */
export async function inheritMailbox(ctx: MusterContext, agentId: string): Promise<number> {
  let held: string[];
  try {
    held = ctx.roles.resolve(agentId).roles;
  } catch {
    return 0;
  }
  const owned = [...ctx.roles.roles.entries()].filter(([, spec]) => spec.owner === agentId).map(([name]) => name);
  const candidates = [...new Set([...held, ...owned])];
  if (candidates.length === 0) return 0;

  // Per-adapter delivery tokens reserved for inherited pushes, refunded if the transaction does not commit (AR ZC-01).
  const reservations: RateReservation[] = [];
  return withTransaction(ctx.pool, async (client) => {
    await assertWritable(client);
    // Same lock order as postMessage (the outbox, then roles sorted), so a concurrent post and this inheritance
    // serialize per role and cannot deadlock. A post that resolved "no live holder" before this agent's presence
    // committed holds these locks until its mailbox row commits, so the row is visible here (AR ZA-02).
    await lockKey(client, 'muster:outbox');
    const roles = [...candidates].sort();
    for (const role of roles) await lockKey(client, `muster:mailbox:${role}`);
    const me = await liveEntry(client, agentId);
    if (!me) return 0;
    // Inheritance creates pushed deliveries too, so it respects the same outbox bound as a post, under the same
    // lock: it stops before exceeding capacity and leaves the rest waiting for a later presence write (AR ZB-02).
    // Partitioned per adapter (OB-60413): this agent has exactly one adapter, so room is scoped to that
    // adapter's own backlog — a stalled queue on one adapter must not stop an agent on a different adapter
    // from inheriting.
    const adapter = adapterFor(ctx, me.runtime);
    const pushes = adapter !== PULL_ADAPTER;
    let room = Number.POSITIVE_INFINITY;
    if (pushes) {
      const { rows: backlog } = await client.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM agent_bus.delivery_outbox WHERE claimed_at IS NULL AND adapter = $1`,
        [adapter],
      );
      room = ctx.limits.outboxCapacity - (backlog[0]?.n ?? 0);
    }
    let inherited = 0;
    let atCapacity = false;
    for (const role of roles) {
      if (atCapacity) break;
      if (!held.includes(role) && (await liveHolders(client, role, agentId)).length > 0) continue;
      const { rows } = await client.query<{ mailbox_id: string; route_id: string; message_id: string }>(
        `SELECT mailbox_id::text AS mailbox_id, route_id::text AS route_id, message_id::text AS message_id
           FROM agent_bus.role_mailbox
          WHERE target_role = $1 AND inherited_at IS NULL
          ORDER BY enqueued_at, mailbox_id
          LIMIT ${MAILBOX_INHERIT_BATCH}`,
        [role],
      );
      for (const row of rows) {
        if (room <= 0) {
          atCapacity = true;
          ctx.logger.logMinimal(`overloaded: ${agentId} stopped inheriting at the ${adapter} delivery outbox capacity (${ctx.limits.outboxCapacity}); the rest stay in the mailbox`);
          break;
        }
        // A pushed delivery spends the same per-adapter budget as a post's; when it is exhausted the admitted prefix
        // is inherited in enqueue order and the rest wait for a later presence write (AR ZC-01).
        let reservation: RateReservation | null = null;
        if (pushes) {
          try {
            reservation = ctx.limiter.reserve([{ key: `deliveries:adapter:${adapter}`, perMinute: ctx.limits.deliveriesPerAdapterPerMinute }]);
          } catch {
            atCapacity = true;
            ctx.logger.logMinimal(`rate_limited: ${agentId} stopped inheriting at the ${adapter} delivery budget; the rest stay in the mailbox`);
            break;
          }
          reservations.push(reservation);
        }
        if (await insertDelivery(ctx, client, row.route_id, row.message_id, me)) {
          if (pushes) room -= 1;
        } else {
          reservation?.release();
        }
        await client.query(
          `UPDATE agent_bus.role_mailbox SET inherited_by_agent_id = $1, inherited_at = now()
            WHERE mailbox_id = $2 AND inherited_at IS NULL`,
          [agentId, row.mailbox_id],
        );
        inherited += 1;
      }
    }
    if (inherited > 0) ctx.logger.log(`${agentId} inherited ${inherited} mailbox message(s)`);
    return inherited;
  }).catch((err: unknown) => {
    for (const reservation of reservations) reservation.release();
    throw err;
  });
}

export type StreamPool = pg.Pool;
