import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { withTransaction } from '../src/db.js';
import { RateLimiter } from '../src/rate-limit.js';
import { memoryKillSwitch, readKillSwitch, setKillSwitch } from '../src/kill-switch.js';
import {
  enrollAndRegisterPersistent,
  GENEROUS_LIMITS,
  hasDb,
  resetDatabase,
  send,
  startHarness,
  tokenAuth,
  type Harness,
  type TestPrincipal,
} from './helpers.js';

const STREAM_ROLES_YAML = `
version: 1
roles:
  operator:
    owner: nic
    may_address: [pmo, fleet-ops, platform-health]
    addressable_by: [pmo, fleet-ops, platform-health]
  pmo:
    owner: project-manager
    may_address: [fleet-ops, platform-health, operator]
    addressable_by: [fleet-ops, platform-health, operator]
  fleet-ops:
    owner: fleet-controller
    may_address: [pmo, platform-health]
    addressable_by: [pmo, platform-health, operator]
  platform-health:
    owner: platform-ops
    may_address: [pmo, fleet-ops, operator]
    addressable_by: [pmo, fleet-ops, operator]
principals:
  - { agent_id: nic, runtime: claude_code, persistence_class: persistent, roles: [operator] }
  - { agent_id: project-manager, runtime: nexus_agent, persistence_class: persistent, roles: [pmo] }
  - { agent_id: fleet-controller, runtime: claude_code, persistence_class: persistent, roles: [fleet-ops] }
  - { agent_id: platform-ops, runtime: nexus_agent, persistence_class: persistent, roles: [platform-health] }
`;

const AGENTS = ['nic', 'project-manager', 'fleet-controller', 'platform-ops'] as const;
type AgentName = (typeof AGENTS)[number];

describe.skipIf(!hasDb)('Muster operations baseline (OB-60179)', () => {
  let h: Harness;
  const p = {} as Record<AgentName, TestPrincipal>;
  const kill = { on: false };
  let seq = 0;

  const post = (from: TestPrincipal, body: Record<string, unknown> = {}) =>
    send(h.baseUrl, {
      method: 'POST',
      path: '/v1/messages',
      body: { type: 'status', body: 'ops test', to_roles: ['fleet-ops'], idempotency_key: `ops-test-${++seq}`, ...body },
      auth: tokenAuth(from),
    });

  beforeAll(async () => {
    await resetDatabase();
    h = await startHarness({ rolesYaml: STREAM_ROLES_YAML, killSwitch: memoryKillSwitch(kill) });
    for (const agent of AGENTS) p[agent] = await enrollAndRegisterPersistent(h, agent);
  }, 60_000);

  beforeEach(async () => {
    kill.on = false;
    h.ctx.limits = { ...GENEROUS_LIMITS };
    h.ctx.limiter = new RateLimiter();
    await h.adminPool.query(
      `TRUNCATE agent_bus.role_mailbox, agent_bus.delivery_outbox, agent_bus.deliveries, agent_bus.message_routes,
        agent_bus.message_envelopes, agent_bus.conditions, agent_bus.wake_queue, agent_bus.messages,
        agent_bus.reconciler_heartbeats, agent_bus.operational_control_audit RESTART IDENTITY CASCADE`,
    );
    await h.adminPool.query(
      `INSERT INTO agent_bus.operational_controls (control_key, enabled, reason, actor)
       VALUES ('kill_switch', false, 'test reset', 'operator')
       ON CONFLICT (control_key) DO UPDATE SET enabled = false, reason = 'test reset', actor = 'operator', updated_at = now()`,
    );
    await h.adminPool.query(`UPDATE agent_bus.registry_entries SET last_seen_at = now()`);
  }, 60_000);

  afterAll(async () => {
    await h?.close();
  }, 20_000);

  it('kill switch: adapters stop, API goes read-only, legacy agent_bus.messages writes still succeed', async () => {
    const first = await post(p['project-manager']);
    expect(first.status, JSON.stringify(first.json)).toBe(201);
    kill.on = true;

    const health = await fetch(`${h.baseUrl}/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ status: 'ok', kill_switch: true, mode: 'read_only', adapters: 'off' });

    const blocked = await post(p['project-manager']);
    expect(blocked.status).toBe(503);
    expect(blocked.json.error).toBe('read_only');

    const registry = await send(h.baseUrl, { method: 'GET', path: '/v1/registry', auth: tokenAuth(p.nic) });
    expect(registry.status).toBe(200);

    const presence = await send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(p.nic) });
    expect(presence.status).toBe(503);
    expect(presence.json.error).toBe('read_only');

    const legacy = await h.adminPool.query(
      `INSERT INTO agent_bus.messages (author, msg_type, body) VALUES ('legacy-helper', 'status', 'still writable') RETURNING id`,
    );
    expect(Number(legacy.rows[0].id)).toBeGreaterThan(0);
    expect((await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages WHERE author = 'legacy-helper'`)).rows[0].n).toBe(1);
  });

  it('GET /metrics reports the kill switch and does not require a token', async () => {
    kill.on = true;
    const res = await fetch(`${h.baseUrl}/metrics`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/text\/plain/);
    expect(await res.text()).toContain('muster_kill_switch 1');
  });

  it('adapter/outbox partial failure rolls back the message (M-10)', async () => {
    await h.adminPool.query(`
      CREATE OR REPLACE FUNCTION agent_bus.test_fail_outbox() RETURNS trigger LANGUAGE plpgsql AS $fn$
      BEGIN RAISE EXCEPTION 'injected outbox failure'; END;
      $fn$;
      DROP TRIGGER IF EXISTS test_fail_outbox ON agent_bus.delivery_outbox;
      CREATE TRIGGER test_fail_outbox BEFORE INSERT ON agent_bus.delivery_outbox
        FOR EACH ROW EXECUTE FUNCTION agent_bus.test_fail_outbox();
    `);
    try {
      const before = (await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages`)).rows[0].n;
      const res = await post(p['project-manager'], { to_roles: ['platform-health'] });
      expect(res.status, JSON.stringify(res.json)).toBe(503);
      expect(res.json.error).toBe('unavailable');
      const after = (await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages`)).rows[0].n;
      expect(after).toBe(before);
      expect((await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.delivery_outbox`)).rows[0].n).toBe(0);
    } finally {
      await h.adminPool.query(`DROP TRIGGER IF EXISTS test_fail_outbox ON agent_bus.delivery_outbox`);
    }
  });

  it('revocation-store failure fails closed with 503 (M-10)', async () => {
    await h.adminPool.query(`REVOKE SELECT ON agent_bus.token_revocations FROM muster_api`);
    try {
      const res = await send(h.baseUrl, { method: 'GET', path: '/v1/registry', auth: tokenAuth(p.nic) });
      expect(res.status).toBe(503);
      expect(res.json.error).toBe('unavailable');
    } finally {
      await h.adminPool.query(`GRANT SELECT ON agent_bus.token_revocations TO muster_api`);
    }
  });

  it('reconciler recovery: a stale fencing token cannot complete a pass; a 15-minute gap fails the delivery objective independently of /health (M-10)', async () => {
    const leaseToken = 'lease-token-1';
    const { rows } = await h.adminPool.query<{ heartbeat_id: string }>(
      `INSERT INTO agent_bus.reconciler_heartbeats (reconciler_agent_id, fencing_token, pass_started_at)
       VALUES ('muster-delivery-reconciler', $1, now() - interval '16 minutes')
       RETURNING heartbeat_id::text`,
      [leaseToken],
    );
    const id = rows[0]!.heartbeat_id;
    const stale = await h.adminPool.query(
      `UPDATE agent_bus.reconciler_heartbeats SET pass_completed_at = now()
        WHERE heartbeat_id = $1::bigint AND fencing_token = $2
        RETURNING heartbeat_id`,
      [id, 'stale-other-instance'],
    );
    expect(stale.rowCount).toBe(0);

    const live = await h.adminPool.query(
      `UPDATE agent_bus.reconciler_heartbeats SET pass_completed_at = now()
        WHERE heartbeat_id = $1::bigint AND fencing_token = $2
        RETURNING heartbeat_id`,
      [id, leaseToken],
    );
    expect(live.rowCount).toBe(1);

    const { rows: sli } = await h.adminPool.query<{ delivery_objective_ok: boolean }>(
      `SELECT (
          NOT EXISTS (SELECT 1 FROM agent_bus.deliveries)
          OR EXISTS (
            SELECT 1 FROM agent_bus.reconciler_heartbeats
             WHERE reconciler_agent_id = 'muster-delivery-reconciler'
               AND pass_completed_at IS NOT NULL
               AND pass_completed_at > now() - interval '15 minutes'
          )
        ) AS delivery_objective_ok`,
    );
    expect(sli[0]!.delivery_objective_ok).toBe(true);

    await h.adminPool.query(
      `UPDATE agent_bus.reconciler_heartbeats SET pass_completed_at = now() - interval '16 minutes' WHERE heartbeat_id = $1::bigint`,
      [id],
    );
    await h.adminPool.query(
      `INSERT INTO agent_bus.messages (author, msg_type, body) VALUES ('sli', 'status', 'delivery exists')`,
    );
    const messageId = (await h.adminPool.query(`SELECT id FROM agent_bus.messages WHERE author = 'sli'`)).rows[0].id;
    await h.adminPool.query(
      `INSERT INTO agent_bus.message_routes (message_id, target_kind, target_agent_id) VALUES ($1, 'agent', 'sli-agent')`,
      [messageId],
    );
    const routeId = (await h.adminPool.query(`SELECT route_id FROM agent_bus.message_routes WHERE message_id = $1`, [messageId])).rows[0]
      .route_id;
    await h.adminPool.query(
      `INSERT INTO agent_bus.deliveries (route_id, message_id, recipient_agent_id, adapter)
       VALUES ($1, $2, 'sli-agent', 'api')`,
      [routeId, messageId],
    );
    const { rows: failed } = await h.adminPool.query<{ delivery_objective_ok: boolean }>(
      `SELECT (
          NOT EXISTS (SELECT 1 FROM agent_bus.deliveries)
          OR EXISTS (
            SELECT 1 FROM agent_bus.reconciler_heartbeats
             WHERE reconciler_agent_id = 'muster-delivery-reconciler'
               AND pass_completed_at IS NOT NULL
               AND pass_completed_at > now() - interval '15 minutes'
          )
        ) AS delivery_objective_ok`,
    );
    expect(failed[0]!.delivery_objective_ok).toBe(false);

    const health = await fetch(`${h.baseUrl}/health`);
    expect(health.status).toBe(200);
    expect((await health.json()).status).toBe('ok');
  });

  it('shared DB kill switch: authorized toggle is audited, API and adapters freeze, then drain', async () => {
    const previous = h.ctx.killSwitch;
    h.ctx.killSwitch = undefined;
    try {
      await expect(setKillSwitch(h.adminPool, { enabled: true, reason: 'resume', actor: 'fleet-controller' })).rejects.toMatchObject({
        status: 403,
        code: 'kill_switch_forbidden',
      });
      await expect(setKillSwitch(h.adminPool, { enabled: true, reason: '  ', actor: 'operator' })).rejects.toMatchObject({
        status: 400,
        code: 'reason_required',
      });

      const on = await setKillSwitch(h.adminPool, { enabled: true, reason: 'slice-1 incident', actor: 'operator' });
      expect(on.enabled).toBe(true);
      expect(await readKillSwitch(h.adminPool)).toBe(true);

      const health = await fetch(`${h.baseUrl}/health`);
      expect(await health.json()).toMatchObject({ status: 'ok', kill_switch: true, mode: 'read_only', adapters: 'off' });
      const blocked = await post(p['project-manager']);
      expect(blocked.status).toBe(503);
      expect(blocked.json.error).toBe('read_only');

      await expect(h.adminPool.query(`UPDATE agent_bus.operational_control_audit SET reason = 'tamper'`)).rejects.toThrow(
        /append-only/,
      );
      await expect(h.adminPool.query(`DELETE FROM agent_bus.operational_control_audit`)).rejects.toThrow(/append-only/);

      const off = await setKillSwitch(h.adminPool, { enabled: false, reason: 'resume drain', actor: 'platform-ops' });
      expect(off.enabled).toBe(false);
      const resumed = await post(p['project-manager']);
      expect(resumed.status, JSON.stringify(resumed.json)).toBe(201);

      const { rows: audit } = await h.adminPool.query<{ actor: string; reason: string; resulting_enabled: boolean }>(
        `SELECT actor, reason, resulting_enabled FROM agent_bus.operational_control_audit ORDER BY audit_id`,
      );
      expect(audit).toEqual([
        { actor: 'operator', reason: 'slice-1 incident', resulting_enabled: true },
        { actor: 'platform-ops', reason: 'resume drain', resulting_enabled: false },
      ]);
    } finally {
      h.ctx.killSwitch = previous;
    }
  });

  it('toggle waits for FOR SHARE on the control row, then commits', async () => {
    const holder = await h.adminPool.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(
        `SELECT enabled FROM agent_bus.operational_controls WHERE control_key = 'kill_switch' FOR SHARE`,
      );
      let resolved = false;
      const toggling = setKillSwitch(h.adminPool, {
        enabled: true,
        reason: 'blocked by share',
        actor: 'operator',
      }).then((row) => {
        resolved = true;
        return row;
      });
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(resolved).toBe(false);
      expect(await readKillSwitch(h.adminPool)).toBe(false);
      await holder.query('COMMIT');
      expect((await toggling).enabled).toBe(true);
      expect(await readKillSwitch(h.adminPool)).toBe(true);
    } finally {
      await holder.query('ROLLBACK').catch(() => undefined);
      holder.release();
    }
  });

  it('fails closed when the kill-switch row is missing', async () => {
    const previous = h.ctx.killSwitch;
    h.ctx.killSwitch = undefined;
    try {
      await h.adminPool.query(`DELETE FROM agent_bus.operational_controls WHERE control_key = 'kill_switch'`);
      expect(await readKillSwitch(h.adminPool)).toBe(true);
      const blocked = await post(p['project-manager']);
      expect(blocked.status).toBe(503);
      expect(blocked.json.error).toBe('read_only');
    } finally {
      h.ctx.killSwitch = previous;
    }
  });

  it('rejects a non-operator POST /v1/admin/kill-switch with 403', async () => {
    const res = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/admin/kill-switch',
      body: { enabled: true, reason: 'non-operator must not toggle' },
      auth: tokenAuth(p['project-manager']),
    });
    expect(res).toEqual({ status: 403, json: { error: 'principal_admin_forbidden' } });
    expect(await readKillSwitch(h.adminPool)).toBe(false);
  });

  it('denies muster_api EXECUTE on the toggle even with SET LOCAL muster.actor', async () => {
    await expect(
      withTransaction(h.pool, async (client) => {
        await client.query(`SELECT set_config('muster.actor', $1, true)`, ['nic']);
        await client.query(`SELECT * FROM agent_bus.muster_set_kill_switch($1, $2, $3)`, [true, 'spoof', 'nic']);
      }),
    ).rejects.toMatchObject({ code: '42501' });
    expect(await readKillSwitch(h.adminPool)).toBe(false);
  });

  it('CLI cannot toggle; operator POST /v1/admin/kill-switch derives actor from the principal', async () => {
    const previous = h.ctx.killSwitch;
    h.ctx.killSwitch = undefined;
    try {
      const spoofed = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/admin/kill-switch',
        body: { enabled: true, reason: 'slice-1 incident', actor: 'fleet-controller' },
        auth: tokenAuth(p.nic),
      });
      expect(spoofed.status, JSON.stringify(spoofed.json)).toBe(200);
      expect(spoofed.json).toMatchObject({ kill_switch: true, actor: 'nic', reason: 'slice-1 incident' });
      expect(await readKillSwitch(h.adminPool)).toBe(true);

      const blocked = await post(p['project-manager']);
      expect(blocked.status).toBe(503);
      expect(blocked.json.error).toBe('read_only');

      const off = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/admin/kill-switch',
        body: { enabled: false, reason: 'resume drain' },
        auth: tokenAuth(p.nic),
      });
      expect(off.status, JSON.stringify(off.json)).toBe(200);
      expect(off.json).toMatchObject({ kill_switch: false, actor: 'nic' });
      expect(await readKillSwitch(h.adminPool)).toBe(false);
    } finally {
      h.ctx.killSwitch = previous;
    }
  });

  it('returns 503 on the kill-switch route when the admin pool is missing', async () => {
    const prev = h.ctx.adminPool;
    h.ctx.adminPool = undefined;
    try {
      const res = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/admin/kill-switch',
        body: { enabled: true, reason: 'no admin pool' },
        auth: tokenAuth(p.nic),
      });
      expect(res).toEqual({ status: 503, json: { error: 'admin_unavailable' } });
    } finally {
      h.ctx.adminPool = prev;
    }
  });
});
