import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import pg from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { enrollPersistentKey, recoverWrites, revokeAgent, revokeAll, revokeGrant, revokeKey, revokeToken } from '../src/admin.js';
import { assertBinding } from '../src/binding.js';
import { MusterError } from '../src/errors.js';
import { approveInteractiveRegistration, OPERATOR_INTERACTIVE_APPROVAL_TTL_SECONDS, tokenJti } from '../src/identity.js';
import { RateLimiter } from '../src/rate-limit.js';
import { parseRolesConfig } from '../src/roles.js';
import {
  AUDIENCE,
  auditEvents,
  enrollAndRegisterPersistent,
  ephemeralBody,
  interactiveBody,
  GENEROUS_LIMITS,
  grantLaunch,
  hasDb,
  putPresence,
  registerPersistentWithKey,
  registerRunner,
  resetDatabase,
  send,
  sendFull,
  startHarness,
  TEST_DB_URL,
  TestPrincipal,
  tokenAuth,
  truncateIdentity,
  type Harness,
} from './helpers.js';

describe.skipIf(!hasDb)('Muster identity API (OB-60176)', () => {
  let h: Harness;
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
    h.binding.claims.clear();
    launcher = await enrollAndRegisterPersistent(h, 'launcher-a');
  });

  async function grant(agentId: string, by: TestPrincipal = launcher): Promise<void> {
    const res = await grantLaunch(h, by, agentId);
    expect(res.status, JSON.stringify(res.json)).toBe(201);
  }

  async function registeredRunner(agentId = 'codex:furnace:runner-1', by: TestPrincipal = launcher): Promise<{ runner: TestPrincipal; claimId: string }> {
    await grant(agentId, by);
    const runner = new TestPrincipal(agentId);
    const claimId = h.binding.add(agentId);
    const res = await registerRunner(h, by, ephemeralBody(runner, claimId));
    expect(res.status, JSON.stringify(res.json)).toBe(201);
    runner.token = res.json.token;
    return { runner, claimId };
  }

  describe('brokered ephemeral registration', () => {
    it('issues a token only for a granted launch, authenticated by proof of possession, stored as a hash', async () => {
      const { runner, claimId } = await registeredRunner();

      const presence = await putPresence(h, runner);
      expect(presence.status).toBe(200);
      expect(presence.json.agent_id).toBe(runner.agentId);

      const registry = await send(h.baseUrl, { method: 'GET', path: '/v1/registry', auth: tokenAuth(runner) });
      expect(registry.status).toBe(200);
      const entry = registry.json.entries.find((e: { agent_id: string }) => e.agent_id === runner.agentId);
      expect(entry).toMatchObject({ runtime: 'codex', persistence_class: 'ephemeral', roles: ['fleet-ops'], presence_state: 'live', ttl_seconds: 600 });

      const plaintext = await h.adminPool.query(`SELECT 1 FROM agent_bus.issued_tokens WHERE jti = $1`, [runner.token]);
      expect(plaintext.rowCount).toBe(0);
      const { rows } = await h.adminPool.query(
        `SELECT r.status, r.launcher_agent_id, t.claim_id
           FROM agent_bus.issued_tokens t JOIN agent_bus.registration_requests r ON r.consumed_token_jti = t.jti
          WHERE t.jti = $1`,
        [tokenJti(runner.token)],
      );
      expect(rows).toEqual([{ status: 'consumed', launcher_agent_id: 'launcher-a', claim_id: claimId }]);
      expect(await auditEvents(h.adminPool, runner.agentId)).toEqual([
        'launch_granted',
        'registration_requested',
        'key_issued',
        'token_issued',
        'registration_consumed',
      ]);
    });

    it('rejects a launcher registering an agent_id it did not launch, and audits each rejection', async () => {
      const runner = new TestPrincipal('codex:furnace:runner-2');
      const claimId = h.binding.add(runner.agentId);
      expect(await registerRunner(h, launcher, ephemeralBody(runner, claimId))).toEqual({ status: 403, json: { error: 'launch_grant_missing' } });

      const launcherC = await enrollAndRegisterPersistent(h, 'launcher-c');
      await grant(runner.agentId, launcherC);
      const later = h.binding.add(runner.agentId);
      expect(await registerRunner(h, launcher, ephemeralBody(runner, later))).toEqual({ status: 403, json: { error: 'launch_grant_launcher_mismatch' } });

      const launcherB = await enrollAndRegisterPersistent(h, 'launcher-b');
      expect(await grantLaunch(h, launcherB, 'codex:furnace:runner-3')).toEqual({ status: 403, json: { error: 'launcher_not_authorized' } });

      const tokens = await h.adminPool.query(`SELECT 1 FROM agent_bus.issued_tokens WHERE agent_id = $1`, [runner.agentId]);
      expect(tokens.rowCount).toBe(0);
      const rejected = await h.adminPool.query<{ code: string }>(
        `SELECT detail->>'code' AS code FROM agent_bus.principal_audit_events
          WHERE event_type = 'registration_rejected' ORDER BY event_id`,
      );
      expect(rejected.rows.map((r) => r.code)).toEqual(['launch_grant_missing', 'launch_grant_launcher_mismatch', 'launcher_not_authorized']);
    });

    it("cannot take over another launcher's live runner", async () => {
      const launcherC = await enrollAndRegisterPersistent(h, 'launcher-c');
      const { runner, claimId } = await registeredRunner('codex:furnace:runner-4', launcherC);
      const impostor = new TestPrincipal(runner.agentId);
      expect(await registerRunner(h, launcher, ephemeralBody(impostor, claimId))).toEqual({ status: 403, json: { error: 'launch_grant_launcher_mismatch' } });
      expect(await grantLaunch(h, launcher, runner.agentId)).toEqual({ status: 409, json: { error: 'launch_grant_exists' } });
      expect((await putPresence(h, runner)).status).toBe(200);
    });

    it('requires the claim to exist, be active, be held by the agent, and be created after the grant', async () => {
      const agentId = 'codex:furnace:runner-5';
      const runner = new TestPrincipal(agentId);
      const before = h.binding.add(agentId, new Date(Date.now() - 60_000));
      await grant(agentId);
      expect((await registerRunner(h, launcher, ephemeralBody(runner, '00000000-0000-4000-8000-000000000000'))).json).toEqual({ error: 'claim_not_found' });
      expect((await registerRunner(h, launcher, ephemeralBody(runner, before))).json).toEqual({ error: 'claim_predates_launch_grant' });
      const other = h.binding.add('codex:furnace:runner-9');
      expect((await registerRunner(h, launcher, ephemeralBody(runner, other))).json).toEqual({ error: 'claim_agent_mismatch' });
      const inactive = h.binding.add(agentId);
      h.binding.claims.get(inactive)!.active = false;
      expect((await registerRunner(h, launcher, ephemeralBody(runner, inactive))).json).toEqual({ error: 'claim_not_active' });
    });

    it('closes a grant that was never used within its claim window', async () => {
      const agentId = 'codex:furnace:runner-6';
      await h.adminPool.query(
        `INSERT INTO agent_bus.launch_grants (agent_id, launcher_agent_id, launcher_key_id, launcher_session_id, created_at, claim_window_ends_at)
         SELECT $1, 'launcher-a', key_id, 'old-session', now() - interval '2 hours', now() - interval '90 minutes'
           FROM agent_bus.principal_keys WHERE agent_id = 'launcher-a' AND revoked_at IS NULL`,
        [agentId],
      );
      const runner = new TestPrincipal(agentId);
      const claimId = h.binding.add(agentId);
      expect((await registerRunner(h, launcher, ephemeralBody(runner, claimId))).json).toEqual({ error: 'launch_grant_window_closed' });
      const tamper = await h.adminPool.query(`UPDATE agent_bus.launch_grants SET launcher_agent_id = 'launcher-c' WHERE agent_id = $1`, [agentId]).catch((e) => e);
      expect(tamper).toBeInstanceOf(Error);
    });

    it('binds a grant to the launcher key that made it (review XB-01)', async () => {
      const agentId = 'codex:furnace:runner-20';
      await grant(agentId);
      const rotated = new TestPrincipal('launcher-a');
      await enrollPersistentKey(h.adminPool, h.ctx.roles, { agentId: 'launcher-a', publicKeyB64: rotated.publicKeyB64, rotate: true, actor: 'operator:test' });
      await registerPersistentWithKey(h, rotated);
      const runner = new TestPrincipal(agentId);
      expect(await registerRunner(h, rotated, ephemeralBody(runner, h.binding.add(agentId)))).toEqual({ status: 403, json: { error: 'launch_grant_missing' } });
      expect((await grantLaunch(h, rotated, agentId)).status).toBe(201);
      expect((await registerRunner(h, rotated, ephemeralBody(runner, h.binding.add(agentId)))).status).toBe(201);

      const launcherC = await enrollAndRegisterPersistent(h, 'launcher-c');
      const foreignKeyGrant = 'codex:furnace:runner-25';
      await h.adminPool.query(
        `INSERT INTO agent_bus.launch_grants (agent_id, launcher_agent_id, launcher_key_id, launcher_session_id, claim_window_ends_at)
         SELECT $1, 'launcher-a', key_id, 'forged', now() + interval '10 minutes'
           FROM agent_bus.principal_keys WHERE agent_id = 'launcher-c' AND revoked_at IS NULL`,
        [foreignKeyGrant],
      );
      const other = new TestPrincipal(foreignKeyGrant);
      expect(await registerRunner(h, rotated, ephemeralBody(other, h.binding.add(foreignKeyGrant)))).toEqual({ status: 403, json: { error: 'launch_grant_stale' } });
      expect(launcherC.token).not.toBe('');
    });

    it('does not revive a grant when a revoked launcher is reinstated (review XB-01)', async () => {
      const agentId = 'codex:furnace:runner-21';
      await grant(agentId);
      await revokeAgent(h.adminPool, { agentId: 'launcher-a', reason: 'drill', actor: 'operator:test' });
      const fresh = new TestPrincipal('launcher-a');
      await enrollPersistentKey(h.adminPool, h.ctx.roles, { agentId: 'launcher-a', publicKeyB64: fresh.publicKeyB64, actor: 'operator:test' });
      await registerPersistentWithKey(h, fresh);
      const runner = new TestPrincipal(agentId);
      expect(await registerRunner(h, fresh, ephemeralBody(runner, h.binding.add(agentId)))).toEqual({ status: 403, json: { error: 'launch_grant_missing' } });
      expect((await grantLaunch(h, fresh, agentId)).status).toBe(201);
      expect((await registerRunner(h, fresh, ephemeralBody(runner, h.binding.add(agentId)))).status).toBe(201);
    });

    it('refuses a co-launcher squat on a live grant, replaces an expired unused grant, and lets an operator revoke one (review XB-02)', async () => {
      const launcherC = await enrollAndRegisterPersistent(h, 'launcher-c');
      const agentId = 'codex:furnace:runner-22';
      expect((await grantLaunch(h, launcherC, agentId)).status).toBe(201);
      expect(await grantLaunch(h, launcher, agentId)).toEqual({ status: 409, json: { error: 'launch_grant_exists' } });
      expect(await revokeGrant(h.adminPool, { agentId, reason: 'squatted', actor: 'operator:test' })).toEqual({ grants_revoked: 1 });
      expect((await grantLaunch(h, launcher, agentId)).status).toBe(201);

      const expiredId = 'codex:furnace:runner-23';
      await h.adminPool.query(
        `INSERT INTO agent_bus.launch_grants (agent_id, launcher_agent_id, launcher_key_id, launcher_session_id, created_at, claim_window_ends_at)
         SELECT $1, 'launcher-c', key_id, 'old', now() - interval '2 hours', now() - interval '90 minutes'
           FROM agent_bus.principal_keys WHERE agent_id = 'launcher-c' AND revoked_at IS NULL`,
        [expiredId],
      );
      expect((await grantLaunch(h, launcher, expiredId)).status).toBe(201);
      const history = await h.adminPool.query(
        `SELECT launcher_agent_id, revoke_reason FROM agent_bus.launch_grants WHERE agent_id = $1 ORDER BY created_at`,
        [expiredId],
      );
      expect(history.rows).toEqual([
        { launcher_agent_id: 'launcher-c', revoke_reason: 'expired_unused' },
        { launcher_agent_id: 'launcher-a', revoke_reason: null },
      ]);
      expect(await auditEvents(h.adminPool, expiredId)).toEqual(['launch_grant_revoked', 'launch_granted']);
    });

    it('keeps grant history: identity immutable, revocation final, no deletes', async () => {
      const agentId = 'codex:furnace:runner-24';
      await grant(agentId);
      const run = (sql: string) => h.adminPool.query(sql, [agentId]).then(() => 'ok', (e: { code?: string }) => e.code ?? 'error');
      expect(await run(`UPDATE agent_bus.launch_grants SET launcher_agent_id = 'launcher-c' WHERE agent_id = $1`)).toBe('23514');
      expect(await run(`UPDATE agent_bus.launch_grants SET revoked_at = now(), revoke_reason = 'test' WHERE agent_id = $1`)).toBe('ok');
      expect(await run(`UPDATE agent_bus.launch_grants SET revoked_at = now(), revoke_reason = 'again' WHERE agent_id = $1`)).toBe('23514');
      expect(await run(`DELETE FROM agent_bus.launch_grants WHERE agent_id = $1`)).not.toBe('ok');
    });

    it('lets the granting launcher re-register its runner on a later claim pack', async () => {
      const { runner } = await registeredRunner('codex:furnace:runner-7');
      const restarted = new TestPrincipal(runner.agentId);
      const nextPack = h.binding.add(runner.agentId);
      const res = await registerRunner(h, launcher, ephemeralBody(restarted, nextPack));
      expect(res.status).toBe(201);
      restarted.token = res.json.token;
      expect(await putPresence(h, runner)).toEqual({ status: 401, json: { error: 'session_superseded' } });
      expect((await putPresence(h, restarted)).status).toBe(200);
    });

    it('requires the runner to prove possession of the key, a fresh nonce, and a persistent launcher', async () => {
      const agentId = 'codex:furnace:runner-8';
      await grant(agentId);
      const runner = new TestPrincipal(agentId);
      const claimId = h.binding.add(agentId);
      expect(await registerRunner(h, launcher, ephemeralBody(runner, claimId, undefined, launcher))).toEqual({ status: 401, json: { error: 'bad_key_proof' } });

      const nonce = 'registration-nonce-0001';
      expect((await registerRunner(h, launcher, ephemeralBody(runner, claimId, nonce))).status).toBe(201);
      const second = new TestPrincipal(agentId);
      expect(await registerRunner(h, launcher, ephemeralBody(second, claimId, nonce))).toEqual({ status: 409, json: { error: 'nonce_reused' } });

      const { runner: registered } = await registeredRunner('codex:furnace:runner-10');
      expect(await grantLaunch(h, registered, 'codex:furnace:runner-11')).toEqual({ status: 403, json: { error: 'launcher_not_persistent' } });
    });

    it('serializes concurrent registrations so exactly one session stays live', async () => {
      const agentId = 'codex:furnace:runner-12';
      await grant(agentId);
      const claimId = h.binding.add(agentId);
      const runners = [new TestPrincipal(agentId), new TestPrincipal(agentId), new TestPrincipal(agentId)];
      const results = await Promise.all(runners.map((r) => registerRunner(h, launcher, ephemeralBody(r, claimId))));
      expect(results.map((r) => r.status)).toEqual([201, 201, 201]);
      const live = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.issued_tokens WHERE agent_id = $1 AND revoked_at IS NULL`, [agentId]);
      expect(live.rows[0].n).toBe(1);
    });
  });

  describe('operator-interactive registration (OB-60180)', () => {
    it('requires out-of-band approval, atomically consumes it once, and binds the token to the submitted key', async () => {
      const published: { requestId: string; challengeSha256: string; agentId: string; keyFingerprint: string; expiresAt: string }[] = [];
      const interactive = await startHarness({ publishInteractiveApproval: async (input) => { published.push(input); } });
      try {
        const runner = new TestPrincipal('claude_code:interactive:session_test-1');
        const request = await send(interactive.baseUrl, { method: 'POST', path: '/v1/register', body: interactiveBody(runner), auth: { kind: 'none' } });
        expect(request.status).toBe(202);
        expect(published).toEqual([expect.objectContaining({ agentId: runner.agentId, keyFingerprint: runner.keyHash })]);
        expect(new Date(published[0]!.expiresAt).getTime() - Date.now()).toBeGreaterThanOrEqual((OPERATOR_INTERACTIVE_APPROVAL_TTL_SECONDS - 2) * 1000);
        expect(new Date(published[0]!.expiresAt).getTime() - Date.now()).toBeLessThanOrEqual((OPERATOR_INTERACTIVE_APPROVAL_TTL_SECONDS + 1) * 1000);
        expect(await send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${request.json.request_id}/exchange`, body: {}, auth: { kind: 'none' } })).toEqual({ status: 401, json: { error: 'missing_credentials' } });
        await approveInteractiveRegistration(interactive.ctx, { requestId: published[0]!.requestId, challengeSha256: published[0]!.challengeSha256 });
        const wrongKey = new TestPrincipal(runner.agentId);
        expect(await send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${request.json.request_id}/exchange`, body: { public_key: wrongKey.publicKeyB64 }, auth: { kind: 'key', keyHash: wrongKey.keyHash, signer: wrongKey.privateKeyPem } })).toEqual({ status: 401, json: { error: 'key_mismatch' } });
        const issued = await send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${request.json.request_id}/exchange`, body: { public_key: runner.publicKeyB64 }, auth: { kind: 'key', keyHash: runner.keyHash, signer: runner.privateKeyPem } });
        expect(issued.status).toBe(201);
        runner.token = issued.json.token;
        expect((await putPresence(interactive, runner)).status).toBe(200);
        await expect(approveInteractiveRegistration(interactive.ctx, { requestId: published[0]!.requestId, challengeSha256: published[0]!.challengeSha256 })).rejects.toMatchObject({ code: 'approval_not_pending' });
        expect(await send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${request.json.request_id}/exchange`, body: { public_key: runner.publicKeyB64 }, auth: { kind: 'key', keyHash: runner.keyHash, signer: runner.privateKeyPem } })).toEqual({ status: 409, json: { error: 'approval_consumed' } });
        const differentKey = new TestPrincipal(runner.agentId);
        expect((await putPresence(interactive, runner, differentKey)).json).toEqual({ error: 'bad_signature' });
      } finally { await interactive.close(); }
    });

    it('allows only one helper to exchange one approval', async () => {
      const published: { requestId: string; challengeSha256: string }[] = [];
      const interactive = await startHarness({ publishInteractiveApproval: async (input) => { published.push(input); } });
      try {
        const runner = new TestPrincipal('claude_code:interactive:session_test-2');
        expect((await send(interactive.baseUrl, { method: 'POST', path: '/v1/register', body: interactiveBody(runner), auth: { kind: 'none' } })).status).toBe(202);
        await approveInteractiveRegistration(interactive.ctx, { requestId: published[0]!.requestId, challengeSha256: published[0]!.challengeSha256 });
        const attempts = await Promise.all([0, 1].map(() => send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${published[0]!.requestId}/exchange`, body: { public_key: runner.publicKeyB64 }, auth: { kind: 'key', keyHash: runner.keyHash, signer: runner.privateKeyPem } })));
        expect(attempts.map((attempt) => attempt.status).sort()).toEqual([201, 409]);
      } finally { await interactive.close(); }
    });

    it('rejects an approval after its challenge expires', async () => {
      const published: { requestId: string; challengeSha256: string }[] = [];
      const interactive = await startHarness({ publishInteractiveApproval: async (input) => { published.push(input); }, interactiveApprovalTtlSeconds: 1 });
      try {
        const runner = new TestPrincipal('claude_code:interactive:session_test-3');
        expect((await send(interactive.baseUrl, { method: 'POST', path: '/v1/register', body: interactiveBody(runner), auth: { kind: 'none' } })).status).toBe(202);
        await new Promise((resolve) => setTimeout(resolve, 1_100));
        await expect(approveInteractiveRegistration(interactive.ctx, { requestId: published[0]!.requestId, challengeSha256: published[0]!.challengeSha256 })).rejects.toMatchObject({ code: 'approval_expired' });
      } finally { await interactive.close(); }
    });

    it('rejects an approved request that expires before exchange', async () => {
      const published: { requestId: string; challengeSha256: string }[] = [];
      const interactive = await startHarness({ publishInteractiveApproval: async (input) => { published.push(input); }, interactiveApprovalTtlSeconds: 1 });
      try {
        const runner = new TestPrincipal('claude_code:interactive:session_test-4');
        const request = await send(interactive.baseUrl, { method: 'POST', path: '/v1/register', body: interactiveBody(runner), auth: { kind: 'none' } });
        await approveInteractiveRegistration(interactive.ctx, { requestId: published[0]!.requestId, challengeSha256: published[0]!.challengeSha256 });
        await new Promise((resolve) => setTimeout(resolve, 1_100));
        expect(await send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${request.json.request_id}/exchange`, body: { public_key: runner.publicKeyB64 }, auth: { kind: 'key', keyHash: runner.keyHash, signer: runner.privateKeyPem } })).toEqual({ status: 409, json: { error: 'approval_expired' } });
      } finally { await interactive.close(); }
    });

    it('rolls back an exchange delayed on the agent lock until approval expiry', async () => {
      const published: { requestId: string; challengeSha256: string }[] = [];
      const interactive = await startHarness({ publishInteractiveApproval: async (input) => { published.push(input); }, interactiveApprovalTtlSeconds: 1 });
      const blocker = await interactive.adminPool.connect();
      try {
        const runner = new TestPrincipal('claude_code:interactive:session_test-5');
        const request = await send(interactive.baseUrl, { method: 'POST', path: '/v1/register', body: interactiveBody(runner), auth: { kind: 'none' } });
        await approveInteractiveRegistration(interactive.ctx, { requestId: published[0]!.requestId, challengeSha256: published[0]!.challengeSha256 });
        await blocker.query('BEGIN');
        await blocker.query(`SELECT pg_advisory_xact_lock(hashtextextended('muster:agent:' || $1, 0))`, [runner.agentId]);
        const exchange = send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${request.json.request_id}/exchange`, body: { public_key: runner.publicKeyB64 }, auth: { kind: 'key', keyHash: runner.keyHash, signer: runner.privateKeyPem } });
        await new Promise((resolve) => setTimeout(resolve, 1_100));
        await blocker.query('COMMIT');
        expect(await exchange).toEqual({ status: 409, json: { error: 'approval_expired' } });
        expect((await interactive.adminPool.query('SELECT 1 FROM agent_bus.principal_keys WHERE request_id = $1', [request.json.request_id])).rowCount).toBe(0);
        expect((await interactive.adminPool.query('SELECT 1 FROM agent_bus.issued_tokens WHERE request_id = $1', [request.json.request_id])).rowCount).toBe(0);
      } finally {
        await blocker.query('ROLLBACK').catch(() => undefined);
        blocker.release();
        await interactive.close();
      }
    });

    it("rejects a terminal-pane registration from the operator's own Unix user without device approval (acceptance OB-60180)", async () => {
      // Acceptance scenario: a process running as the operator's Unix user in a terminal pane
      // attempts registration, but the operator never completes device approval. Local process
      // identity is not a bypass: without approval the exchange fails closed with no token.
      expect(typeof process.getuid === 'function' ? process.getuid() : -1).toBeGreaterThanOrEqual(0);
      expect(os.userInfo().username.length).toBeGreaterThan(0);
      vi.stubEnv('TERM', 'xterm-256color');
      const published: { requestId: string; challengeSha256: string }[] = [];
      const interactive = await startHarness({ publishInteractiveApproval: async (input) => { published.push(input); } });
      try {
        const runner = new TestPrincipal('claude_code:interactive:session_test-6');
        const request = await send(interactive.baseUrl, { method: 'POST', path: '/v1/register', body: interactiveBody(runner), auth: { kind: 'none' } });
        expect(request.status, JSON.stringify(request.json)).toBe(202);
        // The operator's process skips device approval and exchanges with the correct key.
        expect(await send(interactive.baseUrl, { method: 'POST', path: `/v1/register/${request.json.request_id}/exchange`, body: { public_key: runner.publicKeyB64 }, auth: { kind: 'key', keyHash: runner.keyHash, signer: runner.privateKeyPem } })).toEqual({ status: 403, json: { error: 'approval_required' } });
        // Nothing was issued for the unapproved request, and it stays pending: device
        // approval remains the only path to a token.
        expect((await interactive.adminPool.query('SELECT 1 FROM agent_bus.issued_tokens WHERE request_id = $1', [request.json.request_id])).rowCount).toBe(0);
        expect((await interactive.adminPool.query('SELECT 1 FROM agent_bus.principal_keys WHERE request_id = $1', [request.json.request_id])).rowCount).toBe(0);
        const { rows } = await interactive.adminPool.query<{ status: string }>(`SELECT status FROM agent_bus.registration_requests WHERE request_id = $1`, [request.json.request_id]);
        expect(rows[0]!.status).toBe('pending');
        expect(await auditEvents(interactive.adminPool, runner.agentId)).toEqual(['registration_requested']);
      } finally {
        await interactive.close();
        vi.unstubAllEnvs();
      }
    });
  });

  describe('live-state checks on every request', () => {
    it('keeps a runner live while it holds any claim of its pack and rejects it once all are released', async () => {
      const { runner, claimId } = await registeredRunner();
      const second = h.binding.add(runner.agentId);
      h.binding.claims.get(claimId)!.active = false;
      expect((await putPresence(h, runner)).status).toBe(200);
      h.binding.claims.get(second)!.active = false;
      expect(await putPresence(h, runner)).toEqual({ status: 401, json: { error: 'claim_not_live' } });
    });

    it('rejects a token presented with a signature from a different key or host', async () => {
      const { runner } = await registeredRunner();
      const otherHost = new TestPrincipal(runner.agentId);
      expect(await putPresence(h, runner, otherHost)).toEqual({ status: 401, json: { error: 'bad_signature' } });
      expect(await putPresence(h, runner, launcher)).toEqual({ status: 401, json: { error: 'bad_signature' } });
    });

    it('rejects a revoked jti and audits the revocation', async () => {
      const { runner } = await registeredRunner();
      expect(await revokeToken(h.adminPool, { tokenOrJti: runner.token, reason: 'test revocation', actor: 'operator:test' })).toEqual({ revoked: 1 });
      expect(await putPresence(h, runner)).toEqual({ status: 401, json: { error: 'token_revoked' } });
      const listed = await h.adminPool.query(`SELECT reason FROM agent_bus.token_revocations WHERE jti = $1`, [tokenJti(runner.token)]);
      expect(listed.rows).toEqual([{ reason: 'test revocation' }]);
      expect((await auditEvents(h.adminPool, runner.agentId)).at(-1)).toBe('token_revoked');
    });

    it("rejects a superseded session's writes for persistent seats", async () => {
      const firstToken = launcher.token;
      await registerPersistentWithKey(h, launcher);
      expect(launcher.token).not.toBe(firstToken);
      const stale = Object.assign(new TestPrincipal('launcher-a'), { token: firstToken });
      expect(await send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(stale, launcher) })).toEqual({
        status: 401,
        json: { error: 'session_superseded' },
      });
      expect((await putPresence(h, launcher)).status).toBe(200);
    });

    it("revokes a launcher's runners with the launcher, including a registration that raced the revocation", async () => {
      const { runner } = await registeredRunner();
      const result = await revokeAgent(h.adminPool, { agentId: 'launcher-a', reason: 'compromised seat', actor: 'operator:test' });
      expect(result.runners_revoked).toEqual([runner.agentId]);
      expect((await putPresence(h, runner)).status).toBe(401);
      expect((await putPresence(h, launcher)).status).toBe(401);

      const launcherC = await enrollAndRegisterPersistent(h, 'launcher-c');
      const { runner: raced } = await registeredRunner('codex:furnace:runner-13', launcherC);
      await h.adminPool.query(`UPDATE agent_bus.registry_entries SET tombstoned_at = now() WHERE agent_id = 'launcher-c'`);
      expect(await putPresence(h, raced)).toEqual({ status: 401, json: { error: 'launcher_revoked' } });
    });

    it('keeps a revoked runner revoked', async () => {
      const { runner } = await registeredRunner();
      await revokeAgent(h.adminPool, { agentId: runner.agentId, reason: 'bad runner', actor: 'operator:test' });
      const again = new TestPrincipal(runner.agentId);
      const claimId = h.binding.add(runner.agentId);
      expect(await registerRunner(h, launcher, ephemeralBody(again, claimId))).toEqual({ status: 403, json: { error: 'agent_revoked' } });
    });

    it('break glass revokes every key and token', async () => {
      const { runner } = await registeredRunner();
      const result = await revokeAll(h.adminPool, { reason: 'drill', actor: 'operator:test' });
      expect(result.tokens_revoked).toBeGreaterThanOrEqual(2);
      expect((await putPresence(h, runner)).status).toBe(401);
      expect((await putPresence(h, launcher)).status).toBe(401);
      const reregister = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/register',
        body: { persistence_class: 'persistent', agent_id: 'launcher-a' },
        auth: { kind: 'key', keyHash: launcher.keyHash, signer: launcher.privateKeyPem },
      });
      expect(reregister).toEqual({ status: 423, json: { error: 'writes_frozen' } });
      await recoverWrites(h.adminPool, { reason: 'drill over', actor: 'operator:test' });
      const afterRecover = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/register',
        body: { persistence_class: 'persistent', agent_id: 'launcher-a' },
        auth: { kind: 'key', keyHash: launcher.keyHash, signer: launcher.privateKeyPem },
      });
      expect(afterRecover).toEqual({ status: 401, json: { error: 'key_revoked' } });
    });

    it('rejects an unknown token and a request without credentials', async () => {
      const ghost = Object.assign(new TestPrincipal('launcher-a'), { token: `mst_${'A'.repeat(43)}` });
      expect(await putPresence(h, ghost)).toEqual({ status: 401, json: { error: 'token_unknown' } });
      expect(await send(h.baseUrl, { method: 'GET', path: '/v1/registry', auth: { kind: 'none' } })).toEqual({ status: 401, json: { error: 'missing_credentials' } });
    });
  });

  describe('request signing', () => {
    it('rejects a replayed nonce', async () => {
      const nonce = 'replayed-nonce-000001';
      expect((await send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(launcher), nonce })).status).toBe(200);
      expect(await send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(launcher), nonce })).toEqual({
        status: 401,
        json: { error: 'replayed_nonce' },
      });
    });

    it('rejects stale timestamps and requests signed in or before the server start second', async () => {
      const now = Math.floor(Date.now() / 1000);
      expect((await send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(launcher), timestamp: now - 120 })).json).toEqual({
        error: 'stale_timestamp',
      });
      const started = h.ctx.startedAtSeconds;
      h.ctx.startedAtSeconds = now;
      try {
        expect((await send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(launcher), timestamp: now })).json).toEqual({
          error: 'stale_timestamp',
        });
      } finally {
        h.ctx.startedAtSeconds = started;
      }
    });

    it('binds the signature to body, path, query, and audience', async () => {
      const put = { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(launcher) };
      expect(await send(h.baseUrl, { ...put, sendBodyInstead: '{ }' })).toEqual({ status: 401, json: { error: 'bad_signature' } });
      expect(await send(h.baseUrl, { ...put, sendPathInstead: '/v1/presence?x=1' })).toEqual({ status: 401, json: { error: 'bad_signature' } });
      expect(await send(h.baseUrl, { method: 'GET', path: '/v1/registry?limit=1', auth: tokenAuth(launcher), sendPathInstead: '/v1/registry?limit=2' })).toEqual({
        status: 401,
        json: { error: 'bad_signature' },
      });
      expect(await send(h.baseUrl, { ...put, audience: 'muster:elsewhere' })).toEqual({ status: 401, json: { error: 'bad_signature' } });
    });
  });

  describe('persistent seats and operator administration', () => {
    it('rejects a key used for another agent, an unenrolled agent, and a revoked key', async () => {
      const wrongAgent = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/register',
        body: { persistence_class: 'persistent', agent_id: 'project-manager' },
        auth: { kind: 'key', keyHash: launcher.keyHash, signer: launcher.privateKeyPem },
      });
      expect(wrongAgent).toEqual({ status: 403, json: { error: 'agent_key_mismatch' } });

      await expect(
        enrollPersistentKey(h.adminPool, h.ctx.roles, { agentId: 'not-in-roles', publicKeyB64: new TestPrincipal('x').publicKeyB64, actor: 'operator:test' }),
      ).rejects.toThrow(MusterError);

      const { rows } = await h.adminPool.query<{ key_id: string }>(`SELECT key_id FROM agent_bus.principal_keys WHERE agent_id = 'launcher-a'`);
      expect(await revokeKey(h.adminPool, { keyId: rows[0]!.key_id, reason: 'compromised', actor: 'operator:test' })).toEqual({ key_revoked: true, tokens_revoked: 1, grants_revoked: 0 });
      expect((await putPresence(h, launcher)).json).toEqual({ error: 'token_revoked' });
      const again = await send(h.baseUrl, {
        method: 'POST',
        path: '/v1/register',
        body: { persistence_class: 'persistent', agent_id: 'launcher-a' },
        auth: { kind: 'key', keyHash: launcher.keyHash, signer: launcher.privateKeyPem },
      });
      expect(again).toEqual({ status: 401, json: { error: 'key_revoked' } });
    });

    it('rotates a seat key only when asked, revoking the old key and its tokens with audit rows', async () => {
      const next = new TestPrincipal('launcher-a');
      await expect(enrollPersistentKey(h.adminPool, h.ctx.roles, { agentId: 'launcher-a', publicKeyB64: next.publicKeyB64, actor: 'operator:test' })).rejects.toMatchObject({
        code: 'active_key_exists',
      });
      const rotated = await enrollPersistentKey(h.adminPool, h.ctx.roles, { agentId: 'launcher-a', publicKeyB64: next.publicKeyB64, rotate: true, actor: 'operator:test' });
      expect(rotated.rotated_key_ids).toHaveLength(1);
      expect((await putPresence(h, launcher)).json).toEqual({ error: 'token_revoked' });
      await registerPersistentWithKey(h, next);
      expect((await putPresence(h, next)).status).toBe(200);
      expect(await auditEvents(h.adminPool, 'launcher-a')).toEqual(expect.arrayContaining(['key_issued', 'token_issued', 'token_revoked', 'key_revoked', 'key_rotated']));
    });

    it('reinstates a revoked seat only through operator enrollment', async () => {
      await revokeAgent(h.adminPool, { agentId: 'launcher-a', reason: 'rotation drill', actor: 'operator:test' });
      const fresh = new TestPrincipal('launcher-a');
      const enrolled = await enrollPersistentKey(h.adminPool, h.ctx.roles, { agentId: 'launcher-a', publicKeyB64: fresh.publicKeyB64, actor: 'operator:test' });
      expect(enrolled.reinstated).toBe(true);
      await registerPersistentWithKey(h, fresh);
      expect((await putPresence(h, fresh)).status).toBe(200);
    });

    it('refreshes roles, may_address, and addressable_by from the roles file on every presence heartbeat (OB-60329)', async () => {
      const original = h.ctx.roles;
      try {
        const before = await send(h.baseUrl, { method: 'GET', path: '/v1/registry', auth: tokenAuth(launcher) });
        expect(before.json.entries.find((e: { agent_id: string }) => e.agent_id === 'launcher-a')).toMatchObject({
          roles: ['fleet-ops'],
          may_address: ['pmo'],
          addressable_by: ['pmo'],
        });

        // Simulate a reviewed roles-file change applied by SIGHUP: fleet-ops now also reaches operator.
        // A real registration never runs again for launcher-a in this test, so any refresh must come
        // from the presence heartbeat alone.
        h.ctx.roles = parseRolesConfig(`
version: 1
roles:
  fleet-ops:
    owner: launcher-a
    may_address: [pmo, operator]
    addressable_by: [pmo, operator]
  pmo:
    owner: project-manager
    may_address: [fleet-ops]
    addressable_by: [fleet-ops]
  operator:
    owner: operator-console
    may_address: [pmo, fleet-ops]
    addressable_by: [pmo]
principals:
  - agent_id: launcher-a
    runtime: claude_code
    persistence_class: persistent
    roles: [fleet-ops]
`);

        expect((await putPresence(h, launcher)).status).toBe(200);

        const after = await send(h.baseUrl, { method: 'GET', path: '/v1/registry', auth: tokenAuth(launcher) });
        expect(after.json.entries.find((e: { agent_id: string }) => e.agent_id === 'launcher-a')).toMatchObject({
          roles: ['fleet-ops'],
          may_address: ['operator', 'pmo'],
          addressable_by: ['operator', 'pmo'],
          presence_state: 'live',
        });
      } finally {
        h.ctx.roles = original;
      }
    });

    it('rejects operator-interactive registration, unknown classes, and client-supplied presence fields', async () => {
      const operator = await send(h.baseUrl, { method: 'POST', path: '/v1/register', body: { persistence_class: 'operator_interactive', agent_id: 'launcher-a' }, auth: { kind: 'none' } });
      expect(operator).toEqual({ status: 403, json: { error: 'persistence_class_not_enrolled' } });
      const unknown = await send(h.baseUrl, { method: 'POST', path: '/v1/register', body: { persistence_class: 'root', agent_id: 'launcher-a' }, auth: { kind: 'none' } });
      expect(unknown).toEqual({ status: 400, json: { error: 'invalid_persistence_class' } });
      const selfAssigned = await send(h.baseUrl, { method: 'PUT', path: '/v1/presence', body: { roles: ['cos'] }, auth: tokenAuth(launcher) });
      expect(selfAssigned).toEqual({ status: 400, json: { error: 'unsupported_field' } });
    });
  });

  describe('database role (review CA-07)', () => {
    it('gives muster_api no mutation path to agent_bus.messages, persistent keys, or tombstones', async () => {
      // OB-60178 grants INSERT on the message content columns and SELECT for the stream; the server-set id,
      // UPDATE, and DELETE stay denied.
      await expect(h.pool.query(`INSERT INTO agent_bus.messages (id, author, msg_type, body) VALUES (1, 'x', 'status', 'x')`)).rejects.toMatchObject({ code: '42501' });
      await expect(h.pool.query(`UPDATE agent_bus.messages SET body = 'x'`)).rejects.toMatchObject({ code: '42501' });
      await expect(h.pool.query(`DELETE FROM agent_bus.messages`)).rejects.toMatchObject({ code: '42501' });
      await expect(
        h.pool.query(
          `INSERT INTO agent_bus.principal_keys (agent_id, public_key, public_key_sha256, key_kind)
           VALUES ('launcher-b', 'x', repeat('a', 64), 'persistent')`,
        ),
      ).rejects.toMatchObject({ code: '42501' });
      await expect(h.pool.query(`UPDATE agent_bus.registry_entries SET tombstoned_at = NULL`)).rejects.toMatchObject({ code: '42501' });
      await expect(h.pool.query(`DELETE FROM agent_bus.issued_tokens`)).rejects.toMatchObject({ code: '42501' });
    });
  });

  it('answers 429 with Retry-After when one principal exceeds its budget, without blocking another', async () => {
    const tight = await startHarness({ limits: { ...GENEROUS_LIMITS, persistentPerMinute: 2 } });
    try {
      const a = await enrollAndRegisterPersistent(tight, 'launcher-b').catch(async () => {
        throw new Error('setup');
      });
      const statuses: number[] = [];
      let retryAfter: string | null = null;
      for (let i = 0; i < 6; i += 1) {
        const res = await sendFull(tight.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(a) });
        statuses.push(res.status);
        if (res.status === 429) retryAfter = res.headers.get('retry-after');
      }
      expect(statuses).toContain(429);
      expect(Number(retryAfter)).toBeGreaterThan(0);
      const other = await enrollAndRegisterPersistent(tight, 'project-manager');
      expect((await putPresence(tight, other)).status).toBe(200);
    } finally {
      await tight.close();
    }
  });

  it('does not let invalid traffic spend the authenticated global budget, and throttles the failing source (review XB-04)', async () => {
    const flood = await startHarness({ limits: { ...GENEROUS_LIMITS, globalPerSecond: 0.01, globalBurst: 3, failuresPerSecond: 0.01, failureBurst: 1_000 } });
    try {
      const seat = await enrollAndRegisterPersistent(flood, 'launcher-b');
      for (let i = 0; i < 50; i += 1) {
        expect((await send(flood.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: { kind: 'none' } })).status).toBe(401);
      }
      expect((await putPresence(flood, seat)).status).toBe(200);
    } finally {
      await flood.close();
    }

    const strict = await startHarness({ limits: { ...GENEROUS_LIMITS, failuresPerSecond: 0.01, failureBurst: 5 } });
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 7; i += 1) {
        statuses.push((await send(strict.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: { kind: 'none' } })).status);
      }
      expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
      expect(statuses.slice(5)).toEqual([429, 429]);
      // A different client behind the same address still gets through with a signed request (review XC-03).
      const seat = await enrollAndRegisterPersistent(strict, 'project-manager');
      expect((await putPresence(strict, seat)).status).toBe(200);
    } finally {
      await strict.close();
    }
  });

  describe('muster_api privilege contract (review XB-03, XC-01, XC-05)', () => {
    const violations = async (role: string): Promise<string[]> =>
      (await h.adminPool.query<{ v: string[] }>(`SELECT agent_bus.muster_api_privilege_violations($1) AS v`, [role])).rows[0]!.v;

    it('accepts the migrated muster_api role', async () => {
      expect(await violations('muster_api')).toEqual([]);
    });

    it('allows only the freeze-check SECURITY DEFINER and no direct credential-table mutation grants', async () => {
      expect(await violations('muster_api')).toEqual([]);
      const { rows } = await h.adminPool.query<{ name: string }>(`
        SELECT n.nspname || '.' || p.proname AS name
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE p.prosecdef AND n.nspname = 'agent_bus' AND has_function_privilege('muster_api', p.oid, 'EXECUTE')
         ORDER BY 1`);
      expect(rows.map((r) => r.name)).toEqual([
        'agent_bus.muster_assert_writable',
      ]);
      await h.adminPool.query(`GRANT DELETE ON agent_bus.principal_keys TO muster_api`);
      expect(await violations('muster_api')).toEqual(
        expect.arrayContaining(['prohibited agent_bus.principal_keys:DELETE', 'prohibited direct credential-table delete']),
      );
      await h.adminPool.query(`REVOKE DELETE ON agent_bus.principal_keys FROM muster_api`);
      expect(await violations('muster_api')).toEqual([]);
    });

    it('allows only status and approved_at updates on registration requests', async () => {
      expect(await violations('muster_api')).toEqual([]);
      await h.adminPool.query('GRANT UPDATE (requested_agent_id) ON agent_bus.registration_requests TO muster_api');
      await expect(violations('muster_api')).resolves.toContain('prohibited agent_bus.registration_requests:requested_agent_id:UPDATE');
      await h.adminPool.query('REVOKE UPDATE (requested_agent_id) ON agent_bus.registration_requests FROM muster_api');
      expect(await violations('muster_api')).toEqual([]);
    });

    it('reports a missing role without touching the shared role, and the migration refuses on it', async () => {
      expect(await violations('muster_api_missing_fixture')).toEqual(['role muster_api_missing_fixture does not exist']);
      const sql = readFileSync(new URL('./fixtures/1889-ob60176-muster-launch-grants.sql', import.meta.url), 'utf8');
      expect(sql).toMatch(/IF NOT EXISTS \(SELECT 1 FROM pg_roles WHERE rolname = 'muster_api'\) THEN\s+RAISE EXCEPTION/);
      expect(sql).toMatch(/IF cardinality\(violations\) > 0 THEN\s+RAISE EXCEPTION/);
    });

    it('rejects direct and inherited prohibited privileges on a temporary fixture role', async () => {
      const fixture = `muster_fixture_${process.pid}`;
      const parent = `${fixture}_parent`;
      try {
        await h.adminPool.query(`CREATE ROLE ${fixture} NOLOGIN`);
        await h.adminPool.query(`CREATE ROLE ${parent} NOLOGIN`);
        await h.adminPool.query(`GRANT UPDATE ON agent_bus.messages TO ${parent}`);
        await h.adminPool.query(`GRANT DELETE ON operator_backlog_claims TO ${parent}`);
        await h.adminPool.query(`GRANT ${parent} TO ${fixture}`);
        await h.adminPool.query(`GRANT TRUNCATE ON agent_bus.principal_audit_events TO ${fixture}`);
        await h.adminPool.query(`GRANT UPDATE (tombstoned_at) ON agent_bus.registry_entries TO ${fixture}`);
        expect(await violations(fixture)).toEqual(
          expect.arrayContaining([
            `role ${fixture} is a member of another role`,
            'prohibited agent_bus.messages:UPDATE',
            'prohibited public.operator_backlog_claims:DELETE',
            'prohibited agent_bus.principal_audit_events:TRUNCATE',
            'prohibited agent_bus.registry_entries:tombstoned_at:UPDATE',
            'missing agent_bus.issued_tokens:INSERT',
          ]),
        );
      } finally {
        await h.adminPool.query(`DROP OWNED BY ${fixture}`).catch(() => undefined);
        await h.adminPool.query(`DROP OWNED BY ${parent}`).catch(() => undefined);
        await h.adminPool.query(`DROP ROLE IF EXISTS ${fixture}`);
        await h.adminPool.query(`DROP ROLE IF EXISTS ${parent}`);
      }
    });

    it('rejects reachable relations, sequences, definer functions, and schema CREATE outside the contract (review XD-01)', async () => {
      const fixture = `muster_fixture_reach_${process.pid}`;
      const schema = `muster_fixture_schema_${process.pid}`;
      try {
        await h.adminPool.query(`CREATE ROLE ${fixture} NOLOGIN`);
        await h.adminPool.query(`CREATE SCHEMA ${schema}`);
        await h.adminPool.query(`CREATE TABLE ${schema}.secrets (x int)`);
        await h.adminPool.query(`CREATE SEQUENCE ${schema}.counter`);
        await h.adminPool.query(`CREATE FUNCTION ${schema}.definer() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`);
        await h.adminPool.query(`CREATE FUNCTION ${schema}.invoker() RETURNS int LANGUAGE sql AS 'SELECT 1'`);
        await h.adminPool.query(`REVOKE ALL ON FUNCTION ${schema}.definer() FROM PUBLIC`);
        await h.adminPool.query(`GRANT USAGE, CREATE ON SCHEMA ${schema} TO ${fixture}`);
        await h.adminPool.query(`GRANT SELECT ON ${schema}.secrets TO ${fixture}`);
        await h.adminPool.query(`GRANT USAGE ON SEQUENCE ${schema}.counter TO ${fixture}`);
        await h.adminPool.query(`GRANT EXECUTE ON FUNCTION ${schema}.definer() TO ${fixture}`);
        const found = await violations(fixture);
        expect(found).toEqual(
          expect.arrayContaining([
            `prohibited access to ${schema}.secrets`,
            `prohibited access to sequence ${schema}.counter`,
            `prohibited execute on security definer ${schema}.definer()`,
            `prohibited create on schema ${schema}`,
          ]),
        );
        expect(found.some((line) => line.includes(`${schema}.invoker`))).toBe(false);
      } finally {
        await h.adminPool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
        await h.adminPool.query(`DROP OWNED BY ${fixture}`).catch(() => undefined);
        await h.adminPool.query(`DROP ROLE IF EXISTS ${fixture}`);
      }
    });

    it('flags security-definer EXECUTE inherited via PUBLIC, not only direct grants (OB-60208)', async () => {
      const fixture = `muster_fixture_pub_${process.pid}`;
      const schema = `muster_fixture_pubsch_${process.pid}`;
      try {
        await h.adminPool.query(`CREATE ROLE ${fixture} NOLOGIN`);
        await h.adminPool.query(`CREATE SCHEMA ${schema}`);
        // Default PUBLIC EXECUTE is left intact (not revoked): the role inherits it via PUBLIC.
        await h.adminPool.query(
          `CREATE FUNCTION ${schema}.pubdefiner() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`,
        );
        const found = await violations(fixture);
        expect(found).toEqual(
          expect.arrayContaining([`prohibited execute on security definer ${schema}.pubdefiner()`]),
        );
      } finally {
        await h.adminPool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
        await h.adminPool.query(`DROP OWNED BY ${fixture}`).catch(() => undefined);
        await h.adminPool.query(`DROP ROLE IF EXISTS ${fixture}`);
      }
    });

    it('holds the claim row until the issuing transaction ends (review XA-07)', async () => {
      const { rows } = await h.adminPool.query<{ id: string }>(
        `INSERT INTO operator_backlog_claims (runner_id, lease_expires_at) VALUES ('codex:furnace:runner-lock', now() + interval '5 minutes') RETURNING id`,
      );
      const claimId = rows[0]!.id;
      const api = await h.pool.connect();
      const admin = await h.adminPool.connect();
      try {
        await api.query('BEGIN');
        const locked = await api.query(`SELECT runner_id, active FROM public.muster_lock_claim($1)`, [claimId]);
        expect(locked.rows).toEqual([{ runner_id: 'codex:furnace:runner-lock', active: true }]);
        await admin.query(`SET lock_timeout = '300ms'`);
        await expect(
          admin.query(`UPDATE operator_backlog_claims SET claim_status = 'released', released_at = now() WHERE id = $1`, [claimId]),
        ).rejects.toMatchObject({ code: '55P03' });
        await api.query('COMMIT');
        const released = await admin.query(`UPDATE operator_backlog_claims SET claim_status = 'released', released_at = now() WHERE id = $1`, [claimId]);
        expect(released.rowCount).toBe(1);
      } finally {
        await api.query('ROLLBACK').catch(() => undefined);
        await admin.query('RESET lock_timeout').catch(() => undefined);
        api.release();
        admin.release();
      }
    });
  });

  it('bounds database lookups for shaped fake credentials from an exhausted source, but not for proven clients (review XD-02)', async () => {
    const strict = await startHarness({
      limits: { ...GENEROUS_LIMITS, failuresPerSecond: 0.01, failureBurst: 3, candidatesPerSecond: 0.01, candidateBurst: 2 },
    });
    try {
      const seat = await enrollAndRegisterPersistent(strict, 'launcher-b');
      expect((await putPresence(strict, seat)).status).toBe(200);
      const fake = () => {
        const forged = Object.assign(new TestPrincipal('launcher-b'), { token: `mst_${randomBytes(32).toString('base64url')}` });
        return send(strict.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(forged) });
      };
      const statuses: number[] = [];
      for (let i = 0; i < 7; i += 1) statuses.push((await fake()).status);
      // 3 fill the source failure budget, 2 spend the candidate budget, the rest never reach the database.
      expect(statuses).toEqual([401, 401, 401, 401, 401, 429, 429]);
      expect((await putPresence(strict, seat)).status).toBe(200);
    } finally {
      await strict.close();
    }
  });

  it('requires current proof of possession before a recent credential skips the candidate budget (review XE-01)', async () => {
    const strict = await startHarness({
      limits: { ...GENEROUS_LIMITS, failuresPerSecond: 0.01, failureBurst: 3, candidatesPerSecond: 0.01, candidateBurst: 2 },
    });
    try {
      const seat = await enrollAndRegisterPersistent(strict, 'launcher-b');
      expect((await putPresence(strict, seat)).status).toBe(200);
      for (let i = 0; i < 3; i += 1) {
        expect((await send(strict.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: { kind: 'none' } })).status).toBe(401);
      }
      const holderOfLeakedToken = new TestPrincipal('launcher-b');
      const statuses: number[] = [];
      for (let i = 0; i < 4; i += 1) statuses.push((await putPresence(strict, seat, holderOfLeakedToken)).status);
      // The remembered token id alone does not bypass the budget: 2 invalid signatures spend it, then 429.
      expect(statuses).toEqual([401, 401, 429, 429]);
      const replayNonce = 'gate-replay-nonce-0001';
      expect((await send(strict.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(seat), nonce: replayNonce })).status).toBe(200);
      expect((await send(strict.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: tokenAuth(seat), nonce: replayNonce })).status).toBe(429);
      expect((await putPresence(strict, seat)).status).toBe(200);
    } finally {
      await strict.close();
    }
  });

  it('keeps signed requests working when the failure limiter is full of other sources (review XC-04)', async () => {
    const failureLimiter = new RateLimiter(3, true);
    const full = await startHarness({ failureLimiter });
    try {
      for (const source of ['10.0.0.1', '10.0.0.2', '10.0.0.3']) failureLimiter.charge(`failures:${source}`, 1, 10);
      const seat = await enrollAndRegisterPersistent(full, 'launcher-b');
      expect((await putPresence(full, seat)).status).toBe(200);
      expect((await send(full.baseUrl, { method: 'PUT', path: '/v1/presence', body: {}, auth: { kind: 'none' } })).status).toBe(429);
    } finally {
      await full.close();
    }
  });

  it('refuses to apply migration 1889 when the muster_api role is missing (review XB-03)', async () => {
    // OB-60202: the shared muster_api role must never be renamed or dropped (other suites
    // share the cluster). Simulate the missing role by rewriting the role name in a copy of
    // the migration SQL to a throwaway name that does not exist, so the guard DO block raises
    // exactly as it would for a genuinely missing role.
    const probe = `muster_api_absent_${randomBytes(4).toString('hex')}`;
    const client = new pg.Client({ connectionString: TEST_DB_URL });
    await client.connect();
    try {
      const sql = readFileSync(new URL('./fixtures/1889-ob60176-muster-launch-grants.sql', import.meta.url), 'utf8')
        .replaceAll('muster_api', probe);
      await expect(client.query(sql)).rejects.toThrow(`role ${probe} must exist`);
      await client.query('ROLLBACK');
    } finally {
      await client.end();
    }
  });

  it('fails closed when the database is unavailable', async () => {
    const down = await startHarness({ pool: new pg.Pool({ connectionString: 'postgres://nobody@127.0.0.1:1/none', connectionTimeoutMillis: 500 }) });
    try {
      expect(await send(down.baseUrl, { method: 'GET', path: '/health', auth: { kind: 'none' } })).toEqual({
        status: 503,
        json: { status: 'unavailable', kill_switch: true },
      });
      expect(await putPresence(down, launcher)).toEqual({ status: 503, json: { error: 'read_only' } });
    } finally {
      await down.close();
    }
  });

  // Runs the real Nexus binding SQL against a claims table (review CA-06). Set MUSTER_NEXUS_BINDING_PATH
  // to a nexus checkout's muster/nexus-binding.mjs; CI has no nexus checkout, so it skips there.
  describe.skipIf(!process.env.MUSTER_NEXUS_BINDING_PATH)('with the real Nexus binding', () => {
    it('registers against a real claim row, keeps presence TTL to the remaining lease, and drops the runner on release', async () => {
      const mod = (await import(pathToFileURL(process.env.MUSTER_NEXUS_BINDING_PATH as string).href)) as { default: unknown };
      const real = await startHarness({ binding: assertBinding(mod.default) });
      try {
        const agentId = 'codex:furnace:runner-real-1';
        const launcherReal = await enrollAndRegisterPersistent(real, 'launcher-c');
        expect((await grantLaunch(real, launcherReal, agentId)).status).toBe(201);
        const { rows } = await real.adminPool.query<{ id: string }>(
          `INSERT INTO operator_backlog_claims (runner_id, lease_expires_at) VALUES ($1, now() + interval '5 minutes') RETURNING id`,
          [agentId],
        );
        const runner = new TestPrincipal(agentId);
        const res = await registerRunner(real, launcherReal, ephemeralBody(runner, rows[0]!.id));
        expect(res.status, JSON.stringify(res.json)).toBe(201);
        runner.token = res.json.token;
        expect((await putPresence(real, runner)).status).toBe(200);
        const ttl = await real.adminPool.query<{ ttl_seconds: number }>(`SELECT ttl_seconds FROM agent_bus.registry_entries WHERE agent_id = $1`, [agentId]);
        expect(ttl.rows[0]!.ttl_seconds).toBeGreaterThan(240);
        expect(ttl.rows[0]!.ttl_seconds).toBeLessThanOrEqual(300);
        await real.adminPool.query(`UPDATE operator_backlog_claims SET claim_status = 'released', released_at = now() WHERE id = $1`, [rows[0]!.id]);
        expect(await putPresence(real, runner)).toEqual({ status: 401, json: { error: 'claim_not_live' } });
        expect(AUDIENCE).toBe(real.ctx.audience);
      } finally {
        await real.close();
      }
    });

    it('serializes concurrent registrations against one real claim to a single live session', async () => {
      const mod = (await import(pathToFileURL(process.env.MUSTER_NEXUS_BINDING_PATH as string).href)) as { default: unknown };
      const real = await startHarness({ binding: assertBinding(mod.default) });
      try {
        const agentId = 'codex:furnace:runner-real-2';
        const launcherReal = await enrollAndRegisterPersistent(real, 'launcher-c');
        expect((await grantLaunch(real, launcherReal, agentId)).status).toBe(201);
        const { rows } = await real.adminPool.query<{ id: string }>(
          `INSERT INTO operator_backlog_claims (runner_id, lease_expires_at) VALUES ($1, now() + interval '5 minutes') RETURNING id`,
          [agentId],
        );
        const runners = [new TestPrincipal(agentId), new TestPrincipal(agentId), new TestPrincipal(agentId)];
        const results = await Promise.all(runners.map((r) => registerRunner(real, launcherReal, ephemeralBody(r, rows[0]!.id))));
        expect(results.map((r) => r.status)).toEqual([201, 201, 201]);
        const live = await real.adminPool.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM agent_bus.issued_tokens WHERE agent_id = $1 AND revoked_at IS NULL`,
          [agentId],
        );
        expect(live.rows[0]!.n).toBe(1);
      } finally {
        await real.close();
      }
    });
  });
});
