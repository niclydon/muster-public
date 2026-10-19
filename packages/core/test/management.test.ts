import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { recoverWrites } from '../src/admin.js';
import { withTransaction } from '../src/db.js';
import { approveInteractiveRegistration } from '../src/identity.js';
import {
  enrollAndRegisterPersistent,
  ephemeralBody,
  hasDb,
  interactiveBody,
  resetDatabase,
  send,
  startHarness,
  TestPrincipal,
  tokenAuth,
  truncateIdentity,
  type Harness,
} from './helpers.js';

const ADMIN_ROUTES: Array<{ method: string; path: string; body: Record<string, unknown> }> = [
  { method: 'POST', path: '/v1/registry/launcher-a/tier', body: { tier: 'T1' } },
  { method: 'POST', path: '/v1/principals/launcher-b/revoke', body: { reason: 'test' } },
  { method: 'POST', path: '/v1/principals/enroll', body: { agent_id: 'launcher-b', public_key: 'placeholder' } },
  { method: 'POST', path: '/v1/break-glass', body: { reason: 'test' } },
  { method: 'POST', path: '/v1/break-glass/recover', body: { reason: 'test' } },
];

describe.skipIf(!hasDb)('Muster management surface (OB-60221)', () => {
  let h: Harness;
  let operator: TestPrincipal;
  let launcher: TestPrincipal;

  beforeAll(async () => {
    await resetDatabase();
    h = await startHarness();
  });

  afterAll(async () => {
    await h?.close();
  });

  beforeEach(async () => {
    await truncateIdentity(h.adminPool);
    operator = await enrollAndRegisterPersistent(h, 'operator-console');
    launcher = await enrollAndRegisterPersistent(h, 'launcher-a');
  });

  it('rejects a non-operator with 403 on every admin route', async () => {
    for (const route of ADMIN_ROUTES) {
      const res = await send(h.baseUrl, { method: route.method, path: route.path, body: route.body, auth: tokenAuth(launcher) });
      expect(res, route.path).toEqual({ status: 403, json: { error: 'principal_admin_forbidden' } });
    }
  });

  it('serves the append-only North Star history after a mission and a goal (slice 1 smoke: 42804 on the text/jsonb UNION)', async () => {
    const mission = await send(h.baseUrl, { method: 'POST', path: '/v1/north-star/mission', body: { mission: 'history smoke' }, auth: tokenAuth(operator) });
    expect(mission.status, JSON.stringify(mission.json)).toBe(201);
    const goal = await send(h.baseUrl, { method: 'POST', path: '/v1/goals', body: { title: 'history goal', domain: 'ops', position: 0 }, auth: tokenAuth(operator) });
    expect(goal.status, JSON.stringify(goal.json)).toBe(201);
    const history = await send(h.baseUrl, { method: 'GET', path: '/v1/north-star/history', auth: tokenAuth(operator) });
    expect(history.status, JSON.stringify(history.json)).toBe(200);
    const kinds = (history.json.history as Array<{ kind: string; value: unknown }>).map((row) => row.kind);
    expect(kinds).toContain('mission');
    expect(kinds).toContain('goal');
    const missionRow = (history.json.history as Array<{ kind: string; value: unknown }>).find((row) => row.kind === 'mission');
    expect(missionRow?.value).toBe('history smoke');
  });

  it('audits a rejected North Star edit before returning 403 (acceptance 2)', async () => {
    const refused = await send(h.baseUrl, { method: 'POST', path: '/v1/north-star/mission', body: { mission: 'forged' }, auth: tokenAuth(launcher) });
    expect(refused).toEqual({ status: 403, json: { error: 'north_star_edit_forbidden' } });
    const audited = await h.adminPool.query<{ n: string; detail: { resource?: string } }>(
      `SELECT count(*)::text AS n, min(detail::text)::jsonb AS detail FROM agent_bus.principal_audit_events
        WHERE event_type = 'north_star_edit_rejected' AND agent_id = $1`,
      [launcher.agentId],
    );
    expect(audited.rows[0]!.n).toBe('1');
    expect(audited.rows[0]!.detail.resource).toBe('mission');
  });

  it('rejects enrollment when an active persistent key exists, and rotate revokes the old key', async () => {
    const next = new TestPrincipal('launcher-b');
    const first = new TestPrincipal('launcher-b');
    const enrolled = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/principals/enroll',
      body: { agent_id: 'launcher-b', public_key: first.publicKeyB64, expires_in_days: 30 },
      auth: tokenAuth(operator),
    });
    expect(enrolled.status, JSON.stringify(enrolled.json)).toBe(201);
    expect(enrolled.json.rotated_key_ids).toEqual([]);

    const conflict = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/principals/enroll',
      body: { agent_id: 'launcher-b', public_key: next.publicKeyB64 },
      auth: tokenAuth(operator),
    });
    expect(conflict).toEqual({ status: 409, json: { error: 'active_key_exists' } });

    const rotated = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/principals/enroll',
      body: { agent_id: 'launcher-b', public_key: next.publicKeyB64, rotate: true },
      auth: tokenAuth(operator),
    });
    expect(rotated.status, JSON.stringify(rotated.json)).toBe(201);
    expect(rotated.json.rotated_key_ids).toEqual([enrolled.json.key_id]);
    const old = await h.adminPool.query<{ revoked_at: Date | null }>(
      `SELECT revoked_at FROM agent_bus.principal_keys WHERE key_id = $1`,
      [enrolled.json.key_id],
    );
    expect(old.rows[0]!.revoked_at).not.toBeNull();
    const audit = await h.adminPool.query<{ event_type: string }>(
      `SELECT event_type FROM agent_bus.principal_audit_events WHERE agent_id = 'launcher-b' ORDER BY event_id`,
    );
    expect(audit.rows.map((r) => r.event_type)).toEqual(expect.arrayContaining(['key_issued', 'key_revoked', 'key_rotated']));
  });

  it('serializes concurrent enrollment so only one active persistent key remains', async () => {
    const keys = [new TestPrincipal('launcher-c'), new TestPrincipal('launcher-c')];
    const results = await Promise.all(
      keys.map((k) =>
        send(h.baseUrl, {
          method: 'POST',
          path: '/v1/principals/enroll',
          body: { agent_id: 'launcher-c', public_key: k.publicKeyB64 },
          auth: tokenAuth(operator),
        }),
      ),
    );
    expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
    const live = await h.adminPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM agent_bus.principal_keys WHERE agent_id = 'launcher-c' AND key_kind = 'persistent' AND revoked_at IS NULL`,
    );
    expect(live.rows[0]!.n).toBe('1');
  });

  it('rejects a forged actor on a SECURITY DEFINER call', async () => {
    const next = new TestPrincipal('launcher-b');
    await expect(
      withTransaction(h.ctx.adminPool!, async (client) => {
        await client.query(`SELECT set_config('muster.actor', $1, true)`, ['forged-operator']);
        await client.query(`SELECT agent_bus.muster_principal_enroll($1,$2,$3,$4,$5)`, [
          'launcher-b',
          next.publicKeyB64,
          next.keyHash,
          30,
          false,
        ]);
      }),
    ).rejects.toThrow(/muster_actor_not_operator/);

    await expect(
      withTransaction(h.ctx.adminPool!, async (client) => {
        await client.query(`SELECT set_config('muster.actor', $1, true)`, [launcher.agentId]);
        await client.query(`SELECT agent_bus.muster_break_glass($1)`, ['forged']);
      }),
    ).rejects.toThrow(/muster_actor_not_operator/);
  });

  it('denies muster_api EXECUTE on admin functions even with a real operator actor', async () => {
    await expect(
      withTransaction(h.pool, async (client) => {
        await client.query(`SELECT set_config('muster.actor', $1, true)`, [operator.agentId]);
        await client.query(`SELECT agent_bus.muster_break_glass($1)`, ['spoof']);
      }),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('returns 503 on admin routes when the admin pool is missing', async () => {
    const prev = h.ctx.adminPool;
    h.ctx.adminPool = undefined;
    try {
      const res = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/principals/enroll',
        body: { agent_id: 'launcher-b', public_key: new TestPrincipal('launcher-b').publicKeyB64 },
        auth: tokenAuth(operator),
      });
      expect(res).toEqual({ status: 503, json: { error: 'admin_unavailable' } });
    } finally {
      h.ctx.adminPool = prev;
    }
  });

  it('freezes mutating writes after break-glass and restores them only through recovery', async () => {
    const glass = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/break-glass',
      body: { reason: 'credential compromise' },
      auth: tokenAuth(operator),
    });
    expect(glass.status, JSON.stringify(glass.json)).toBe(200);
    expect(glass.json.read_only).toBe(true);
    expect(glass.json.grants_revoked).toBeGreaterThanOrEqual(0);

    const frozen = await h.adminPool.query<{ read_only: boolean }>(`SELECT read_only FROM agent_bus.operational_state WHERE singleton`);
    expect(frozen.rows[0]!.read_only).toBe(true);

    const replacement = new TestPrincipal('operator-console');
    const { enrollPersistentKey } = await import('../src/admin.js');
    await expect(
      enrollPersistentKey(h.adminPool, h.ctx.roles, {
        agentId: 'operator-console',
        publicKeyB64: replacement.publicKeyB64,
        rotate: true,
        actor: 'operator:test',
      }),
    ).rejects.toMatchObject({ status: 423, code: 'writes_frozen' });

    const registered = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/register',
      body: { persistence_class: 'persistent', agent_id: 'operator-console' },
      auth: { kind: 'key', keyHash: replacement.keyHash, signer: replacement.privateKeyPem },
    });
    expect(registered).toEqual({ status: 423, json: { error: 'writes_frozen' } });

    const recovered = await recoverWrites(h.adminPool, { reason: 'incident closed', actor: 'operator:test' });
    expect(recovered.read_only).toBe(false);

    const enrolled = await enrollPersistentKey(h.adminPool, h.ctx.roles, {
      agentId: 'operator-console',
      publicKeyB64: replacement.publicKeyB64,
      rotate: true,
      actor: 'operator:test',
    });
    expect(enrolled.key_id).toBeTruthy();
    const registeredAfter = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/register',
      body: { persistence_class: 'persistent', agent_id: 'operator-console' },
      auth: { kind: 'key', keyHash: replacement.keyHash, signer: replacement.privateKeyPem },
    });
    expect(registeredAfter.status, JSON.stringify(registeredAfter.json)).toBe(201);
    replacement.token = registeredAfter.json.token;

    const restored = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/north-star/mission',
      body: { mission: 'writes restored' },
      auth: tokenAuth(replacement),
    });
    expect(restored.status, JSON.stringify(restored.json)).toBe(201);
  });

  it('returns 423 on every ordinary mutating route while frozen', async () => {
    let published: { requestId: string; challengeSha256: string } | undefined;
    h.ctx.publishInteractiveApproval = async (input) => {
      published = { requestId: input.requestId, challengeSha256: input.challengeSha256 };
    };
    const runner = new TestPrincipal('codex:furnace:runner-frozen');
    const interactive = new TestPrincipal('claude_code:interactive:session_frozen');
    const claimId = h.binding.add(runner.agentId);
    const requested = await send(h.baseUrl, { method: 'POST', path: '/v1/register', body: interactiveBody(interactive), auth: { kind: 'none' } });
    expect(requested.status, JSON.stringify(requested.json)).toBe(202);
    expect(published?.requestId).toBe(requested.json.request_id);
    const goal = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/goals',
      body: { title: 'pre-freeze', domain: 'ops', position: 0 },
      auth: tokenAuth(operator),
    });
    expect(goal.status, JSON.stringify(goal.json)).toBe(201);
    const condition = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/conditions',
      body: { kind: 'incident', scope: { host: 'test' }, effect: { operator: 'annotate' }, duration_seconds: 120 },
      auth: tokenAuth(operator),
    });
    expect(condition.status, JSON.stringify(condition.json)).toBe(201);
    const pmo = await enrollAndRegisterPersistent(h, 'project-manager');
    const posted = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/messages',
      body: { type: 'status', body: 'pre-freeze', to_roles: ['pmo'], idempotency_key: 'frozen-setup-1' },
      auth: tokenAuth(launcher),
    });
    expect(posted.status, JSON.stringify(posted.json)).toBe(201);
    const pendingDelivery = await h.adminPool.query<{ delivery_id: string; state: string }>(
      `SELECT delivery_id::text AS delivery_id, state FROM agent_bus.deliveries
        WHERE recipient_agent_id = $1 AND state = 'pending' ORDER BY delivery_id LIMIT 1`,
      [pmo.agentId],
    );
    const deliveryId = pendingDelivery.rows[0]?.delivery_id;

    await h.adminPool.query(`UPDATE agent_bus.operational_state SET read_only = TRUE WHERE singleton`);
    const frozen = { status: 423, json: { error: 'writes_frozen' } };
    const routes: Array<{ method: string; path: string; body?: Record<string, unknown>; auth: Parameters<typeof send>[1]['auth'] }> = [
      { method: 'POST', path: '/v1/register', body: { persistence_class: 'persistent', agent_id: 'operator-console' }, auth: { kind: 'key', keyHash: operator.keyHash, signer: operator.privateKeyPem } },
      { method: 'POST', path: '/v1/register', body: ephemeralBody(runner, claimId), auth: tokenAuth(launcher) },
      { method: 'POST', path: '/v1/register', body: interactiveBody(new TestPrincipal('claude_code:interactive:session_frozen2')), auth: { kind: 'none' } },
      { method: 'POST', path: `/v1/register/${requested.json.request_id}/exchange`, body: { public_key: interactive.publicKeyB64 }, auth: { kind: 'key', keyHash: interactive.keyHash, signer: interactive.privateKeyPem } },
      { method: 'POST', path: '/v1/launch-grants', body: { agent_id: runner.agentId }, auth: tokenAuth(launcher) },
      { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(operator) },
      { method: 'POST', path: '/v1/registry/launcher-a/tier', body: { tier: 'T1' }, auth: tokenAuth(operator) },
      { method: 'POST', path: '/v1/principals/launcher-b/revoke', body: { reason: 'frozen' }, auth: tokenAuth(operator) },
      { method: 'POST', path: '/v1/principals/enroll', body: { agent_id: 'launcher-b', public_key: new TestPrincipal('launcher-b').publicKeyB64 }, auth: tokenAuth(operator) },
      { method: 'POST', path: '/v1/north-star/mission', body: { mission: 'frozen' }, auth: tokenAuth(operator) },
      { method: 'POST', path: '/v1/goals', body: { title: 'g', domain: 'ops', position: 1 }, auth: tokenAuth(operator) },
      { method: 'POST', path: `/v1/goals/${goal.json.goal_id}`, body: { title: 'g2', domain: 'ops', position: 0 }, auth: tokenAuth(operator) },
      { method: 'POST', path: '/v1/messages', body: { type: 'status', body: 'frozen', to_roles: ['pmo'], idempotency_key: 'frozen-msg-1' }, auth: tokenAuth(operator) },
      { method: 'GET', path: '/v1/messages', auth: tokenAuth(pmo) },
      { method: 'POST', path: `/v1/conditions/${condition.json.condition_id}/clear`, body: {}, auth: tokenAuth(operator) },
      { method: 'POST', path: '/v1/conditions', body: { kind: 'incident', scope: { host: 'test2' }, effect: { operator: 'annotate' }, duration_seconds: 120 }, auth: tokenAuth(operator) },
    ];
    if (deliveryId) {
      routes.push({ method: 'POST', path: `/v1/deliveries/${deliveryId}/ack`, body: {}, auth: tokenAuth(pmo) });
    }
    for (const route of routes) {
      const res = await send(h.baseUrl, { method: route.method, path: route.path, body: route.body, auth: route.auth });
      expect(res, `${route.method} ${route.path}`).toEqual(frozen);
    }
    expect(deliveryId, 'expected a delivery to ack').toBeTruthy();
    await expect(
      approveInteractiveRegistration(h.ctx, { requestId: published!.requestId, challengeSha256: published!.challengeSha256 }),
    ).rejects.toMatchObject({ status: 423, code: 'writes_frozen' });
    const stillPending = await h.adminPool.query<{ status: string }>(
      `SELECT status FROM agent_bus.registration_requests WHERE request_id = $1`,
      [published!.requestId],
    );
    expect(stillPending.rows[0]!.status).toBe('pending');
    const approvedAudit = await h.adminPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM agent_bus.principal_audit_events WHERE event_type = 'registration_approved' AND request_id = $1`,
      [published!.requestId],
    );
    expect(approvedAudit.rows[0]!.n).toBe('0');
    const stillQueued = await h.adminPool.query<{ state: string; delivered_at: Date | null }>(
      `SELECT state, delivered_at FROM agent_bus.deliveries WHERE delivery_id = $1`,
      [deliveryId],
    );
    expect(stillQueued.rows[0]).toEqual({ state: 'pending', delivered_at: null });
  });

  it('cannot approve or consume an interactive request that was pending when freeze commits', async () => {
    let published: { requestId: string; challengeSha256: string } | undefined;
    h.ctx.publishInteractiveApproval = async (input) => {
      published = { requestId: input.requestId, challengeSha256: input.challengeSha256 };
    };
    const interactive = new TestPrincipal('claude_code:interactive:session_pending_freeze');
    const requested = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/register',
      body: interactiveBody(interactive),
      auth: { kind: 'none' },
    });
    expect(requested.status, JSON.stringify(requested.json)).toBe(202);
    expect(published?.requestId).toBe(requested.json.request_id);

    const holder = await h.adminPool.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(`SELECT read_only FROM agent_bus.operational_state WHERE singleton FOR UPDATE`);

      const pendingApprove = approveInteractiveRegistration(h.ctx, {
        requestId: published!.requestId,
        challengeSha256: published!.challengeSha256,
      });
      const pendingExchange = send(h.baseUrl, {
        method: 'POST',
        path: `/v1/register/${requested.json.request_id}/exchange`,
        body: { public_key: interactive.publicKeyB64 },
        auth: { kind: 'key', keyHash: interactive.keyHash, signer: interactive.privateKeyPem },
      });
      let approveSettled = false;
      let exchangeSettled = false;
      void pendingApprove.then(
        () => {
          approveSettled = true;
        },
        () => {
          approveSettled = true;
        },
      );
      void pendingExchange.then(() => {
        exchangeSettled = true;
      });
      await new Promise((r) => setTimeout(r, 200));
      expect(approveSettled).toBe(false);
      expect(exchangeSettled).toBe(false);

      await holder.query(`UPDATE agent_bus.operational_state SET read_only = TRUE WHERE singleton`);
      await holder.query('COMMIT');

      await expect(pendingApprove).rejects.toMatchObject({ status: 423, code: 'writes_frozen' });
      expect(await pendingExchange).toEqual({ status: 423, json: { error: 'writes_frozen' } });
    } catch (err) {
      await holder.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      holder.release();
    }

    const stillPending = await h.adminPool.query<{ status: string }>(
      `SELECT status FROM agent_bus.registration_requests WHERE request_id = $1`,
      [published!.requestId],
    );
    expect(stillPending.rows[0]!.status).toBe('pending');
    const mutated = await h.adminPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM agent_bus.principal_audit_events
        WHERE event_type IN ('registration_approved', 'registration_consumed') AND request_id = $1`,
      [published!.requestId],
    );
    expect(mutated.rows[0]!.n).toBe('0');
  });

  it('cannot mark a pending pull delivery delivered after freeze commits', async () => {
    const pmo = await enrollAndRegisterPersistent(h, 'project-manager');
    const posted = await send(h.baseUrl, {
      method: 'POST',
      path: '/v1/messages',
      body: { type: 'status', body: 'pre-freeze-pull', to_roles: ['pmo'], idempotency_key: 'frozen-pull-1' },
      auth: tokenAuth(launcher),
    });
    expect(posted.status, JSON.stringify(posted.json)).toBe(201);
    const before = await h.adminPool.query<{ delivery_id: string; state: string }>(
      `SELECT delivery_id::text AS delivery_id, state FROM agent_bus.deliveries
        WHERE recipient_agent_id = $1 AND state = 'pending' ORDER BY delivery_id DESC LIMIT 1`,
      [pmo.agentId],
    );
    expect(before.rows[0]?.state).toBe('pending');

    const holder = await h.adminPool.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(`SELECT read_only FROM agent_bus.operational_state WHERE singleton FOR UPDATE`);

      const pendingGet = send(h.baseUrl, { method: 'GET', path: '/v1/messages', auth: tokenAuth(pmo) });
      let settled = false;
      void pendingGet.then(() => {
        settled = true;
      });
      await new Promise((r) => setTimeout(r, 200));
      expect(settled).toBe(false);

      await holder.query(`UPDATE agent_bus.operational_state SET read_only = TRUE WHERE singleton`);
      await holder.query('COMMIT');

      expect(await pendingGet).toEqual({ status: 423, json: { error: 'writes_frozen' } });
    } catch (err) {
      await holder.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      holder.release();
    }

    const after = await h.adminPool.query<{ state: string; delivered_at: Date | null }>(
      `SELECT state, delivered_at FROM agent_bus.deliveries WHERE delivery_id = $1`,
      [before.rows[0]!.delivery_id],
    );
    expect(after.rows[0]).toEqual({ state: 'pending', delivered_at: null });
  });

  it('holds FOR SHARE so break-glass cannot commit under an in-flight write', async () => {
    const holder = await h.adminPool.connect();
    try {
      await holder.query('BEGIN');
      const locked = await holder.query<{ read_only: boolean }>(`SELECT read_only FROM agent_bus.operational_state WHERE singleton FOR SHARE`);
      expect(locked.rows[0]!.read_only).toBe(false);

      const probe = await h.adminPool.connect();
      try {
        await probe.query(`SET lock_timeout = '200ms'`);
        await expect(probe.query(`SELECT read_only FROM agent_bus.operational_state WHERE singleton FOR UPDATE`)).rejects.toMatchObject({ code: '55P03' });
      } finally {
        probe.release();
      }

      const pending = send(h.baseUrl, {
        method: 'POST',
        path: '/v1/break-glass',
        body: { reason: 'interleave' },
        auth: tokenAuth(operator),
      });
      let settled = false;
      void pending.then(() => {
        settled = true;
      });
      await new Promise((r) => setTimeout(r, 200));
      expect(settled).toBe(false);

      await holder.query(`INSERT INTO agent_bus.north_star_versions (mission, updated_by) VALUES ('in-flight before freeze', $1)`, [operator.agentId]);
      await holder.query('COMMIT');
      const result = await pending;
      expect(result.status, JSON.stringify(result.json)).toBe(200);
      expect(result.json.read_only).toBe(true);
      const flag = await h.adminPool.query<{ read_only: boolean }>(`SELECT read_only FROM agent_bus.operational_state WHERE singleton`);
      expect(flag.rows[0]!.read_only).toBe(true);
      const after = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/north-star/mission',
        body: { mission: 'must not land after freeze' },
        auth: tokenAuth(operator),
      });
      expect(after.status).not.toBe(201);
    } catch (err) {
      await holder.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      holder.release();
    }
  });

  it('accepts the 1895 verifier grants and flags anything broader', async () => {
    const violations = async (role: string): Promise<string[]> =>
      (await h.adminPool.query<{ v: string[] }>(`SELECT agent_bus.muster_api_privilege_violations($1) AS v`, [role])).rows[0]!.v;
    expect(await violations('muster_api')).toEqual([]);

    const definers = await h.adminPool.query<{ name: string; ok: boolean }>(`
      SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS name,
             has_function_privilege('muster_api', p.oid, 'EXECUTE') AS ok
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE p.prosecdef AND n.nspname = 'agent_bus'
         AND p.proname IN ('muster_assert_writable','muster_principal_revoke','muster_principal_enroll','muster_break_glass','muster_recover_writes')
       ORDER BY 1`);
    expect(definers.rows.map((r) => ({ name: r.name, ok: r.ok }))).toEqual([
      { name: 'agent_bus.muster_assert_writable()', ok: true },
      { name: 'agent_bus.muster_break_glass(p_reason text)', ok: false },
      { name: 'agent_bus.muster_principal_enroll(p_agent_id text, p_public_key text, p_key_hash text, p_days integer, p_rotate boolean)', ok: false },
      { name: 'agent_bus.muster_principal_revoke(p_agent_id text, p_reason text)', ok: false },
      { name: 'agent_bus.muster_recover_writes(p_reason text)', ok: false },
    ]);

    const adminDefiners = await h.adminPool.query<{ name: string }>(`
      SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS name
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE p.prosecdef AND n.nspname = 'agent_bus' AND has_function_privilege('muster_admin', p.oid, 'EXECUTE')
       ORDER BY 1`);
    expect(adminDefiners.rows.map((r) => r.name)).toEqual([
      'agent_bus.muster_break_glass(p_reason text)',
      'agent_bus.muster_principal_enroll(p_agent_id text, p_public_key text, p_key_hash text, p_days integer, p_rotate boolean)',
      'agent_bus.muster_principal_revoke(p_agent_id text, p_reason text)',
      'agent_bus.muster_recover_writes(p_reason text)',
      // 1897 (OB-60179) adds the operator kill-switch toggle to the same muster_admin-only set.
      'agent_bus.muster_set_kill_switch(p_enabled boolean, p_reason text, p_actor text)',
    ]);

    const credentialGrants = await h.adminPool.query<{ t: string; p: string }>(`
      SELECT table_name AS t, privilege_type AS p
        FROM information_schema.role_table_grants
       WHERE grantee = 'muster_api'
         AND table_schema = 'agent_bus'
         AND table_name IN ('principal_keys','issued_tokens','launch_grants','token_revocations')
         AND privilege_type IN ('DELETE','TRUNCATE','TRIGGER','REFERENCES')`);
    expect(credentialGrants.rows).toEqual([]);

    await h.adminPool.query(`GRANT UPDATE ON agent_bus.operational_state TO muster_api`);
    expect(await violations('muster_api')).toEqual(expect.arrayContaining(['prohibited agent_bus.operational_state:UPDATE']));
    await h.adminPool.query(`REVOKE UPDATE ON agent_bus.operational_state FROM muster_api`);
    expect(await violations('muster_api')).toEqual([]);
  });
});
