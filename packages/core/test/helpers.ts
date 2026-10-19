import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import pg from 'pg';
import { expect } from 'vitest';
import { enrollPersistentKey } from '../src/admin.js';
import type { HoldCheck, MusterBinding, Queryable } from '../src/binding.js';
import { createMusterServer } from '../src/http.js';
import { createNonceCache, type MusterContext } from '../src/identity.js';
import type { KillSwitch } from '../src/kill-switch.js';
import { createLogger } from '../src/logger.js';
import { RequestMetrics } from '../src/metrics.js';
import { RateLimiter, type RateLimits } from '../src/rate-limit.js';
import { RecentCredentials } from '../src/recent-credentials.js';
import { parseRolesConfig } from '../src/roles.js';
import { canonicalRequest, generateSigningKeyPair, keyProofPayload, parsePublicKey, signPayload } from '../src/signing.js';

export const TEST_DB_URL = process.env.MUSTER_TEST_DATABASE_URL;
// resetDatabase drops agent_bus, and the prerequisite sets a well-known muster_api password. On 2026-09-15 that
// password reached the production nexus cluster and took muster-api down, so only a dedicated test database may run.
if (TEST_DB_URL) {
  const dbName = decodeURIComponent(new URL(TEST_DB_URL).pathname.replace(/^\//, ''));
  if (!/^(muster_test|[A-Za-z0-9_]+_test)$/.test(dbName)) {
    throw new Error(`MUSTER_TEST_DATABASE_URL must name a dedicated test database (muster_test or *_test), not "${dbName}"`);
  }
}
if (!TEST_DB_URL && process.env.MUSTER_REQUIRE_DB_TESTS === '1') {
  throw new Error('MUSTER_TEST_DATABASE_URL is required when MUSTER_REQUIRE_DB_TESTS=1');
}
export const hasDb = Boolean(TEST_DB_URL);
export const AUDIENCE = 'muster:test';

/** The API runs as the least-privilege muster_api role, exactly as in production (review CA-07). */
export function apiDatabaseUrl(): string {
  const url = new URL(TEST_DB_URL as string);
  url.username = 'muster_api';
  url.password = 'muster_api';
  return url.toString();
}

/** Admin routes run as muster_admin, which holds EXECUTE on the 1895 SECURITY DEFINER functions and the 1897 toggle. */
export function apiAdminDatabaseUrl(): string {
  const url = new URL(TEST_DB_URL as string);
  url.username = 'muster_admin';
  url.password = 'muster_admin';
  return url.toString();
}

// Minimal stand-ins for the Nexus objects migrations 1884, 1889, and 1892 touch, so the verbatim migrations run.
// agent_bus.messages and wake_queue carry their production columns, sequences, and legacy wake trigger, so the
// stream API's inserts exercise the same privileges as production (OB-60178).
const NEXUS_STUBS = `
CREATE SCHEMA IF NOT EXISTS agent_bus;
-- In production the schema owner grants this out of band; migration 1889 requires it as a precondition.
GRANT USAGE ON SCHEMA agent_bus TO muster_api;
CREATE TABLE agent_bus.messages (
  id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(), author TEXT NOT NULL, recipient TEXT,
  msg_type TEXT NOT NULL CHECK (msg_type = ANY (ARRAY['status', 'intent', 'done', 'ask', 'flag'])),
  task TEXT, body TEXT NOT NULL, in_reply_to BIGINT REFERENCES agent_bus.messages (id));
CREATE UNLOGGED TABLE agent_bus.wake_queue (
  id BIGSERIAL PRIMARY KEY, message_id BIGINT NOT NULL, recipients JSONB NOT NULL DEFAULT '[]'::jsonb,
  queued_at TIMESTAMPTZ NOT NULL DEFAULT now(), notified_at TIMESTAMPTZ);
-- Like production, not SECURITY DEFINER: it writes wake_queue as the inserting role.
CREATE FUNCTION agent_bus.enqueue_message_wake() RETURNS trigger LANGUAGE plpgsql
  SET search_path TO 'agent_bus', 'pg_catalog' AS $fn$
BEGIN
  INSERT INTO agent_bus.wake_queue (message_id, recipients)
  VALUES (NEW.id, CASE WHEN NEW.recipient IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(NEW.recipient) END);
  RETURN NEW;
END;
$fn$;
CREATE TRIGGER agent_bus_messages_enqueue_wake AFTER INSERT ON agent_bus.messages
  FOR EACH ROW EXECUTE FUNCTION agent_bus.enqueue_message_wake();
CREATE TABLE aurora_data_objects (
  object_name TEXT PRIMARY KEY, layer TEXT, object_kind TEXT, canonical_name TEXT, source_key TEXT,
  domain TEXT, lifecycle_state TEXT, notes TEXT, updated_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE aurora_data_object_consumers (
  object_name TEXT REFERENCES aurora_data_objects, column_name TEXT, consumer_kind TEXT, consumer_name TEXT,
  access_kind TEXT, evidence TEXT, lifecycle_state TEXT, updated_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE (object_name, column_name, consumer_kind, consumer_name, access_kind));
CREATE TABLE nexus_schema_version (version INTEGER PRIMARY KEY, description TEXT);
CREATE TABLE migration_registry (version INTEGER, slug TEXT, status TEXT, applied_at TIMESTAMPTZ);
CREATE TABLE operator_backlog_claims (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), ob_id BIGINT, claim_status TEXT NOT NULL DEFAULT 'active',
  runner_id TEXT NOT NULL, claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(), heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_expires_at TIMESTAMPTZ NOT NULL, released_at TIMESTAMPTZ, metadata JSONB NOT NULL DEFAULT '{}');
CREATE TABLE platform_health_targets (
  service TEXT PRIMARY KEY, display_name TEXT, check_type TEXT, endpoint TEXT, expected TEXT,
  timeout_ms INT, severity_on_down TEXT, alert_after_failures INT, escalation_holdoff_ms BIGINT,
  enabled BOOLEAN, updated_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE platform_health_checks (service TEXT, status TEXT, checked_at TIMESTAMPTZ);
CREATE TABLE notification_delivery_methods (channel TEXT, is_enabled BOOLEAN, config JSONB DEFAULT '{}');
`;

const MIGRATIONS = [
  '1884-ob60175-muster-companion-schema.sql',
  '1889-ob60176-muster-launch-grants.sql',
  '1892-ob60178-muster-stream-grants.sql',
  '1896-ob60180-muster-operator-interactive-registration.sql',
  // Production applied 1896 before 1895 (1895 shipped later); 1897 wraps the verifier chain last.
  '1895-ob60221-muster-management.sql',
  '1897-ob60179-muster-ops-baseline.sql',
  '1898-ob60221-north-star-audit-event.sql',
];

/** Rebuilds the test database from verbatim copies of nexus migrations 1884, 1889, 1892, 1896, 1895, and 1897 (fixtures/). */
export async function resetDatabase(): Promise<void> {
  const client = new pg.Client({ connectionString: TEST_DB_URL });
  await client.connect();
  try {
    // The suite never creates, alters, or drops cluster roles (review XD-04); provision muster_api and muster_admin first.
    const role = await client.query(`SELECT rolname FROM pg_roles WHERE rolname IN ('muster_api', 'muster_admin')`);
    const names = new Set(role.rows.map((r: { rolname: string }) => r.rolname));
    if (!names.has('muster_api')) {
      throw new Error(
        "Test prerequisite: create the muster_api role in a disposable test cluster, never a production cluster (CREATE ROLE muster_api LOGIN PASSWORD 'muster_api'). The suite does not create cluster roles.",
      );
    }
    if (!names.has('muster_admin')) {
      throw new Error(
        "Test prerequisite: create the muster_admin role in a disposable test cluster, never a production cluster (CREATE ROLE muster_admin LOGIN PASSWORD 'muster_admin'). The suite does not create cluster roles.",
      );
    }
    await client.query(`DROP SCHEMA IF EXISTS agent_bus CASCADE;
      DROP TABLE IF EXISTS aurora_data_object_consumers, aurora_data_objects, nexus_schema_version,
        migration_registry, operator_backlog_claims, platform_health_targets, platform_health_checks,
        notification_delivery_methods CASCADE;`);
    await client.query(NEXUS_STUBS);
    for (const file of MIGRATIONS) {
      await client.query(readFileSync(new URL(`./fixtures/${file}`, import.meta.url), 'utf8'));
    }
    // Nexus 1894 (OB-60182) adds the immutable envelope class the stream writer stamps.
    // The full migration also registers nexus jobs; the stream suite only needs the column.
    await client.query(`
      ALTER TABLE agent_bus.message_envelopes ADD COLUMN IF NOT EXISTS alert_class TEXT;
      ALTER TABLE agent_bus.message_envelopes DROP CONSTRAINT IF EXISTS message_envelopes_alert_class_check;
      ALTER TABLE agent_bus.message_envelopes
        ADD CONSTRAINT message_envelopes_alert_class_check
        CHECK (alert_class IS NULL OR alert_class IN ('info','low','medium','high','critical'));
    `);
  } finally {
    await client.end();
  }
}

export async function truncateIdentity(pool: pg.Pool): Promise<void> {
  await pool.query(`TRUNCATE agent_bus.principal_audit_events, agent_bus.token_revocations,
    agent_bus.registration_requests, agent_bus.issued_tokens, agent_bus.principal_keys,
    agent_bus.registry_entries, agent_bus.launch_grants, agent_bus.north_star_versions,
    agent_bus.goals, operator_backlog_claims RESTART IDENTITY CASCADE`);
  await pool.query(`UPDATE agent_bus.operational_state
     SET read_only = FALSE, read_only_set_at = NULL, read_only_set_by = NULL,
         read_only_reason = NULL, read_only_cleared_at = NULL, read_only_cleared_by = NULL
   WHERE singleton`);
}

export const ROLES_YAML = `
version: 1
roles:
  fleet-ops:
    owner: launcher-a
    may_address: [pmo]
    addressable_by: [pmo]
  pmo:
    owner: project-manager
    may_address: [fleet-ops]
    addressable_by: [fleet-ops]
  operator:
    owner: operator-console
    may_address: [pmo, fleet-ops]
    addressable_by: [pmo]
principals:
  - agent_id_pattern: "claude_code:interactive:session_*"
    runtime: claude_code
    persistence_class: operator_interactive
    roles: [fleet-ops]
  - agent_id: operator-console
    runtime: claude_code
    persistence_class: persistent
    roles: [operator]
  - agent_id: launcher-a
    runtime: claude_code
    persistence_class: persistent
    roles: [fleet-ops]
  - agent_id: launcher-b
    runtime: claude_code
    persistence_class: persistent
    roles: [fleet-ops]
  - agent_id: launcher-c
    runtime: deploy
    persistence_class: persistent
    roles: [fleet-ops]
  - agent_id: project-manager
    runtime: nexus_agent
    persistence_class: persistent
    roles: [pmo]
  - agent_id_pattern: "codex:furnace:runner-*"
    runtime: codex
    persistence_class: ephemeral
    roles: [fleet-ops]
    launched_by: [launcher-a, launcher-c]
  - agent_id_pattern: "kimi:furnace:runner-*"
    runtime: kimi
    persistence_class: ephemeral
    roles: [fleet-ops]
    launched_by: [launcher-b]
`;

export const GENEROUS_LIMITS: RateLimits = {
  globalPerSecond: 10_000,
  globalBurst: 10_000,
  failuresPerSecond: 10_000,
  failureBurst: 10_000,
  candidatesPerSecond: 10_000,
  candidateBurst: 10_000,
  persistentPerMinute: 10_000,
  ephemeralPerMinute: 10_000,
  launcherPerMinute: 10_000,
  keyRegistrationPerMinute: 10_000,
  messagesGlobalPerMinute: 10_000,
  messagesPerRolePerMinute: 10_000,
  launcherMessagesPerMinute: 10_000,
  deliveriesPerAdapterPerMinute: 10_000,
  mailboxCapacityPerRole: 10_000,
  outboxCapacity: 100_000,
};

/** In-memory claims standing in for the deployment binding. */
export class FakeBinding implements MusterBinding {
  readonly claims = new Map<string, { agentId: string; active: boolean; claimedAt: Date }>();

  add(agentId: string, claimedAt = new Date()): string {
    const id = randomUUID();
    this.claims.set(id, { agentId, active: true, claimedAt });
    return id;
  }

  async verifyHold(_db: Queryable, input: { claimId: string; agentId: string }): Promise<HoldCheck> {
    const claim = this.claims.get(input.claimId);
    if (!claim) return { ok: false, reason: 'claim_not_found' };
    if (!claim.active) return { ok: false, reason: 'claim_not_active' };
    if (claim.agentId !== input.agentId) return { ok: false, reason: 'claim_agent_mismatch' };
    return { ok: true, claimedAt: claim.claimedAt, ttlSeconds: 600 };
  }

  async hasLiveHold(_db: Queryable, input: { agentId: string }): Promise<boolean> {
    return [...this.claims.values()].some((c) => c.active && c.agentId === input.agentId);
  }

  /** Same mapping as the Nexus binding: inbox for Nexus agents, Discord for the #agents mirror. */
  deliveryAdapterFor(runtime: string): string | null {
    if (runtime === 'nexus_agent') return 'agent_inbox';
    if (runtime === 'discord') return 'discord';
    return null;
  }

  extraPushRecipients(): Array<{ agentId: string; runtime: string }> {
    return [{ agentId: 'discord:agents', runtime: 'discord' }];
  }
}

export interface Harness {
  /** The API's pool, connected as muster_api. */
  pool: pg.Pool;
  /** Owner pool for admin commands, fixtures, and assertions. */
  adminPool: pg.Pool;
  ctx: MusterContext;
  binding: FakeBinding;
  baseUrl: string;
  close(): Promise<void>;
}

export async function startHarness(
  opts: {
    pool?: pg.Pool;
    limits?: RateLimits;
    binding?: MusterBinding;
    failureLimiter?: RateLimiter;
    rolesYaml?: string;
    publishInteractiveApproval?: (input: { requestId: string; challengeSha256: string; expiresAt: string; agentId: string; keyFingerprint: string }) => Promise<void>;
    interactiveApprovalTtlSeconds?: number;
    killSwitch?: KillSwitch;
  } = {},
): Promise<Harness> {
  const pool = opts.pool ?? new pg.Pool({ connectionString: apiDatabaseUrl(), max: 5 });
  const adminPool = new pg.Pool({ connectionString: TEST_DB_URL, max: 3 });
  const privilegedPool = new pg.Pool({ connectionString: apiAdminDatabaseUrl(), max: 3 });
  const binding = new FakeBinding();
  const ctx: MusterContext = {
    pool,
    adminPool: privilegedPool,
    roles: parseRolesConfig(opts.rolesYaml ?? ROLES_YAML),
    binding: opts.binding ?? binding,
    nonces: createNonceCache(),
    limiter: new RateLimiter(),
    failureLimiter: opts.failureLimiter ?? new RateLimiter(20_000, true),
    recent: new RecentCredentials(),
    limits: opts.limits ?? GENEROUS_LIMITS,
    audience: AUDIENCE,
    startedAtSeconds: Math.floor(Date.now() / 1000) - 5,
    logger: createLogger('muster-test', 'minimal'),
    publishInteractiveApproval: opts.publishInteractiveApproval,
    interactiveApprovalTtlSeconds: opts.interactiveApprovalTtlSeconds,
    killSwitch: opts.killSwitch,
    metrics: new RequestMetrics(),
  };
  const server = createMusterServer(ctx);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    pool,
    adminPool,
    ctx,
    binding,
    baseUrl: `http://127.0.0.1:${port}`,
    async close() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await pool.end();
      await privilegedPool.end();
      await adminPool.end();
    },
  };
}

export class TestPrincipal {
  readonly publicKeyB64: string;
  readonly privateKeyPem: string;
  readonly keyHash: string;
  token = '';

  constructor(readonly agentId: string) {
    const pair = generateSigningKeyPair();
    this.publicKeyB64 = pair.publicKeyB64;
    this.privateKeyPem = pair.privateKeyPem;
    this.keyHash = parsePublicKey(pair.publicKeyB64).sha256;
  }
}

export type Auth =
  | { kind: 'token'; token: string; signer: string }
  | { kind: 'key'; keyHash: string; signer: string }
  | { kind: 'none' };

export const tokenAuth = (p: TestPrincipal, signer: TestPrincipal = p): Auth => ({ kind: 'token', token: p.token, signer: signer.privateKeyPem });

export interface SendOptions {
  method: string;
  path: string;
  body?: unknown;
  auth: Auth;
  timestamp?: number;
  nonce?: string;
  /** Sent instead of the signed body, to prove the signature covers the body. */
  sendBodyInstead?: string;
  /** Sent instead of the signed path, to prove the signature covers path and query. */
  sendPathInstead?: string;
  /** Signs for a different deployment, to prove the audience is bound. */
  audience?: string;
}

export interface Response {
  status: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
}

export async function sendFull(baseUrl: string, o: SendOptions): Promise<Response & { headers: Headers }> {
  const bodyText = o.body === undefined ? '' : JSON.stringify(o.body);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (o.auth.kind !== 'none') {
    const credential = o.auth.kind === 'token' ? o.auth.token : `key:${o.auth.keyHash}`;
    const timestamp = String(o.timestamp ?? Math.floor(Date.now() / 1000));
    const nonce = o.nonce ?? randomBytes(18).toString('base64url');
    const payload = canonicalRequest({
      audience: o.audience ?? AUDIENCE,
      method: o.method,
      pathWithQuery: o.path,
      timestamp,
      nonce,
      body: Buffer.from(bodyText),
      credential,
    });
    headers.authorization = o.auth.kind === 'token' ? `Muster-PoP ${o.auth.token}` : `Muster-Key ${o.auth.keyHash}`;
    headers['muster-timestamp'] = timestamp;
    headers['muster-nonce'] = nonce;
    headers['muster-signature'] = signPayload(o.auth.signer, payload);
  }
  const res = await fetch(baseUrl + (o.sendPathInstead ?? o.path), {
    method: o.method,
    headers,
    body: o.method === 'GET' ? undefined : (o.sendBodyInstead ?? bodyText),
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null, headers: res.headers };
}

export async function send(baseUrl: string, o: SendOptions): Promise<Response> {
  const { status, json } = await sendFull(baseUrl, o);
  return { status, json };
}

export async function enrollAndRegisterPersistent(h: Harness, agentId: string): Promise<TestPrincipal> {
  const p = new TestPrincipal(agentId);
  await enrollPersistentKey(h.adminPool, h.ctx.roles, { agentId, publicKeyB64: p.publicKeyB64, actor: 'operator:test' });
  await registerPersistentWithKey(h, p);
  return p;
}

export async function registerPersistentWithKey(h: Harness, p: TestPrincipal): Promise<void> {
  const res = await send(h.baseUrl, {
    method: 'POST',
    path: '/v1/register',
    body: { persistence_class: 'persistent', agent_id: p.agentId },
    auth: { kind: 'key', keyHash: p.keyHash, signer: p.privateKeyPem },
  });
  expect(res.status, JSON.stringify(res.json)).toBe(201);
  p.token = res.json.token;
}

export function grantLaunch(h: Harness, launcher: TestPrincipal, agentId: string) {
  return send(h.baseUrl, { method: 'POST', path: '/v1/launch-grants', body: { agent_id: agentId }, auth: tokenAuth(launcher) });
}

export function ephemeralBody(runner: TestPrincipal, claimId: string, nonce = randomBytes(18).toString('base64url'), proofSigner: TestPrincipal = runner) {
  return {
    persistence_class: 'ephemeral',
    agent_id: runner.agentId,
    claim_id: claimId,
    public_key: runner.publicKeyB64,
    nonce,
    key_proof: signPayload(
      proofSigner.privateKeyPem,
      keyProofPayload({ audience: AUDIENCE, agentId: runner.agentId, claimId, nonce, publicKeySha256: runner.keyHash }),
    ),
  };
}

export function interactiveBody(runner: TestPrincipal, nonce = randomBytes(18).toString('base64url'), proofSigner: TestPrincipal = runner) {
  return {
    persistence_class: 'operator_interactive',
    agent_id: runner.agentId,
    public_key: runner.publicKeyB64,
    nonce,
    key_proof: signPayload(proofSigner.privateKeyPem, keyProofPayload({ audience: AUDIENCE, agentId: runner.agentId, claimId: 'operator_interactive', nonce, publicKeySha256: runner.keyHash })),
  };
}

export function registerRunner(h: Harness, launcher: TestPrincipal, body: Record<string, unknown>) {
  return send(h.baseUrl, { method: 'POST', path: '/v1/register', body, auth: tokenAuth(launcher) });
}

export function putPresence(h: Harness, p: TestPrincipal, signer: TestPrincipal = p) {
  return send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(p, signer) });
}

export async function auditEvents(pool: pg.Pool, agentId: string): Promise<string[]> {
  const { rows } = await pool.query<{ event_type: string }>(
    `SELECT event_type FROM agent_bus.principal_audit_events WHERE agent_id = $1 ORDER BY event_id`,
    [agentId],
  );
  return rows.map((r) => r.event_type);
}
