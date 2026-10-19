import { createPrivateKey, createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { loadPrivateKey, publicKeySha256, signedRequest } from '../src/client.js';
import { createLogger } from '../src/logger.js';
import { PresenceKeeper, seatKeyEnvName, type PresenceResponse } from '../src/presence.js';
import { canonicalRequest, generateSigningKeyPair, parsePublicKey, verifySignature } from '../src/signing.js';

const AUDIENCE = 'muster:test';
const logger = createLogger('presence-test', 'minimal');

function seat(agentId: string) {
  const pair = generateSigningKeyPair();
  return { agentId, privateKey: createPrivateKey(pair.privateKeyPem), publicKeyB64: pair.publicKeyB64 };
}

/** A scripted muster-api: records every call and answers from a queue per path. */
function fakeApi() {
  const calls: Array<{ path: string; method: string; authorization: string; body: unknown }> = [];
  const queue = new Map<string, PresenceResponse[]>();
  let issued = 0;
  return {
    calls,
    answer(path: string, ...responses: PresenceResponse[]) {
      queue.set(path, [...(queue.get(path) ?? []), ...responses]);
    },
    fetch: async (path: string, init: { method: string; headers: Record<string, string>; body?: string }) => {
      calls.push({ path, method: init.method, authorization: init.headers.authorization ?? '', body: init.body ? JSON.parse(init.body) : undefined });
      const scripted = queue.get(path)?.shift();
      if (scripted) return scripted;
      if (path === '/v1/register') {
        issued += 1;
        return { status: 201, json: { agent_id: 'x', session_id: `s${issued}`, key_id: 'k', token: `mst_${issued}`, token_expires_at: new Date(Date.now() + 86_400_000).toISOString(), north_star_version: '1' } };
      }
      return { status: 200, json: { agent_id: 'x', last_seen_at: new Date().toISOString(), ttl_seconds: 900 } };
    },
  };
}

describe('seat client', () => {
  it('loads a key as PEM or as single-line base64 PKCS#8 DER and derives the same registration credential', () => {
    const pair = generateSigningKeyPair();
    const der = pair.privateKeyPem.split('\n').filter((l) => l && !l.startsWith('-----')).join('');
    expect(publicKeySha256(loadPrivateKey(der))).toBe(parsePublicKey(pair.publicKeyB64).sha256);
    expect(publicKeySha256(loadPrivateKey(pair.privateKeyPem))).toBe(parsePublicKey(pair.publicKeyB64).sha256);
  });

  it('signs muster-request-v1 over the exact body and credential the server will see', () => {
    const s = seat('project-manager');
    const req = signedRequest({ audience: AUDIENCE, method: 'PUT', path: '/v1/presence', body: {}, credential: { kind: 'token', token: 'mst_abc' }, privateKey: s.privateKey });
    expect(req.headers.authorization).toBe('Muster-PoP mst_abc');
    expect(req.body).toBe('{}');
    const payload = canonicalRequest({
      audience: AUDIENCE, method: 'PUT', pathWithQuery: '/v1/presence', timestamp: req.headers['muster-timestamp']!, nonce: req.headers['muster-nonce']!, body: Buffer.from('{}'), credential: 'mst_abc',
    });
    expect(verifySignature(createPublicKey(s.privateKey), payload, req.headers['muster-signature'])).toBe(true);
    const reg = signedRequest({ audience: AUDIENCE, method: 'POST', path: '/v1/register', body: { a: 1 }, credential: { kind: 'key', publicKeySha256: 'deadbeef' }, privateKey: s.privateKey });
    expect(reg.headers.authorization).toBe('Muster-Key deadbeef');
    expect(signedRequest({ audience: AUDIENCE, method: 'GET', path: '/v1/registry', credential: { kind: 'token', token: 't' }, privateKey: s.privateKey }).body).toBeUndefined();
  });

  it('names the key variable from the agent id', () => {
    expect(seatKeyEnvName('project-manager')).toBe('MUSTER_AGENT_KEY_PROJECT_MANAGER');
    expect(seatKeyEnvName('aria')).toBe('MUSTER_AGENT_KEY_ARIA');
  });
});

describe('presence keeper', () => {
  it('registers with the seat key on the first tick and heartbeats with the issued token afterwards', async () => {
    const api = fakeApi();
    const pm = seat('project-manager');
    const keeper = new PresenceKeeper({ audience: AUDIENCE, seats: [pm], fetch: api.fetch, logger, intervalMs: 300_000 });
    expect(await keeper.tick()).toEqual({ 'project-manager': 'registered' });
    expect(await keeper.tick()).toEqual({ 'project-manager': 'live' });
    expect(api.calls.map((c) => [c.method, c.path])).toEqual([['POST', '/v1/register'], ['PUT', '/v1/presence']]);
    expect(api.calls[0]!.authorization).toBe(`Muster-Key ${parsePublicKey(pm.publicKeyB64).sha256}`);
    expect(api.calls[0]!.body).toEqual({ persistence_class: 'persistent', agent_id: 'project-manager' });
    expect(api.calls[1]!.authorization).toBe('Muster-PoP mst_1');
  });

  it('starts a new session in the same tick when the heartbeat comes back 401 (superseded or expired)', async () => {
    const api = fakeApi();
    const keeper = new PresenceKeeper({ audience: AUDIENCE, seats: [seat('aria')], fetch: api.fetch, logger, intervalMs: 300_000 });
    await keeper.tick();
    api.answer('/v1/presence', { status: 401, json: { error: 'session_superseded' } });
    expect(await keeper.tick()).toEqual({ aria: 'registered' });
    expect(api.calls.map((c) => c.path)).toEqual(['/v1/register', '/v1/presence', '/v1/register']);
    expect(await keeper.tick()).toEqual({ aria: 'live' });
    expect(api.calls.at(-1)!.authorization).toBe('Muster-PoP mst_2');
  });

  it('keeps the session through a freeze and keeps other seats going when one is not enrolled', async () => {
    const api = fakeApi();
    const keeper = new PresenceKeeper({ audience: AUDIENCE, seats: [seat('platform-ops'), seat('nobody')], fetch: api.fetch, logger, intervalMs: 300_000 });
    api.answer('/v1/register', { status: 201, json: { token: 'mst_ops', session_id: 's', key_id: 'k', token_expires_at: null, north_star_version: '1' } }, { status: 403, json: { error: 'agent_not_enrolled' } });
    expect(await keeper.tick()).toEqual({ 'platform-ops': 'registered', nobody: 'failed' });
    api.answer('/v1/presence', { status: 503, json: { error: 'read_only' } });
    api.answer('/v1/register', { status: 503, json: { error: 'read_only' } });
    expect(await keeper.tick()).toEqual({ 'platform-ops': 'frozen', nobody: 'frozen' });
    expect(keeper.hasSession('platform-ops')).toBe(true);
    expect(await keeper.tick()).toEqual({ 'platform-ops': 'live', nobody: 'registered' });
    expect(api.calls.filter((c) => c.path === '/v1/presence').every((c) => c.authorization === 'Muster-PoP mst_ops')).toBe(true);
  });

  it('re-registers before the token expires instead of heartbeating into a 401', async () => {
    const api = fakeApi();
    let now = Date.parse('2026-09-15T12:00:00Z');
    const keeper = new PresenceKeeper({ audience: AUDIENCE, seats: [seat('project-manager')], fetch: api.fetch, logger, intervalMs: 300_000, now: () => now });
    api.answer('/v1/register', { status: 201, json: { token: 'mst_short', session_id: 's', key_id: 'k', token_expires_at: new Date(now + 3_600_000).toISOString(), north_star_version: '1' } });
    await keeper.tick();
    now += 3_120_000; // 52 min in: 8 min of token left, under two periods
    expect(await keeper.tick()).toEqual({ 'project-manager': 'registered' });
    expect(api.calls.map((c) => c.path)).toEqual(['/v1/register', '/v1/register']);
  });
});
