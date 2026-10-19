import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { NonceCache } from '../src/nonce-cache.js';
import { RateLimiter } from '../src/rate-limit.js';
import { RecentCredentials } from '../src/recent-credentials.js';
import { parseRolesConfig } from '../src/roles.js';
import { generateSigningKeyPair, parsePublicKey } from '../src/signing.js';
import { ROLES_YAML } from './helpers.js';

const SRC = fileURLToPath(new URL('../src', import.meta.url));

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

describe('OB-60176 static guarantees', () => {
  it('references agent_bus.messages only from the stream module, and never mutates it (OB-60178; the database role also denies it)', () => {
    for (const file of files(SRC)) {
      const text = readFileSync(file, 'utf8');
      if (file.endsWith(`${sep}stream.ts`)) {
        expect(text, file).not.toMatch(/(UPDATE|DELETE\s+FROM|TRUNCATE)\s+agent_bus\.messages\b/i);
      } else {
        expect(text, file).not.toMatch(/agent_bus\.messages\b/);
      }
    }
  });
});

describe('roles file', () => {
  const roles = parseRolesConfig(ROLES_YAML);

  it('resolves an exact agent_id through a pattern without letting * cross a segment or match nothing', () => {
    expect(roles.resolve('codex:furnace:runner-7')).toMatchObject({
      agentId: 'codex:furnace:runner-7',
      persistenceClass: 'ephemeral',
      launchedBy: ['launcher-a', 'launcher-c'],
    });
    expect(() => roles.resolve('codex:furnace:runner-7:extra')).toThrow('agent_not_enrolled');
    expect(() => roles.resolve('codex:elsewhere:runner-7')).toThrow('agent_not_enrolled');
    expect(() => roles.resolve('codex:furnace:runner-')).toThrow('agent_not_enrolled');
  });

  it('derives addressability from roles, never from the client', () => {
    expect(roles.resolve('project-manager')).toMatchObject({ roles: ['pmo'], mayAddress: ['fleet-ops'], addressableBy: ['fleet-ops'] });
  });

  it.each([
    ['ephemeral without launched_by', ROLES_YAML.replace('    launched_by: [launcher-a, launcher-c]\n', ''), 'needs launched_by'],
    ['an unknown key', ROLES_YAML.replace('runtime: nexus_agent', 'runtime: nexus_agent\n    persistence_class_typo: x'), 'unknown key'],
    ['ephemeral nexus_agent', ROLES_YAML.replace('runtime: codex', 'runtime: nexus_agent'), 'not allowed for ephemeral'],
    ['unknown role reference', ROLES_YAML.replace('roles: [pmo]', 'roles: [cos]'), 'invalid'],
    ['duplicate agent_id', ROLES_YAML.replace('agent_id: launcher-b', 'agent_id: launcher-a'), 'duplicates'],
  ])('rejects %s', (_name, text, message) => {
    expect(() => parseRolesConfig(text)).toThrow(message);
  });

  it('rejects an agent_id matched by two patterns', () => {
    const overlapping = parseRolesConfig(
      ROLES_YAML + `  - agent_id_pattern: "codex:furnace:*-1"\n    runtime: codex\n    persistence_class: ephemeral\n    roles: [pmo]\n    launched_by: [launcher-b]\n`,
    );
    expect(() => overlapping.resolve('codex:furnace:runner-1')).toThrow('enrollment_ambiguous');
  });
});

describe('signing primitives', () => {
  it('accepts canonical Ed25519 SPKI keys only', () => {
    const { publicKeyB64 } = generateSigningKeyPair();
    expect(parsePublicKey(publicKeyB64).sha256).toMatch(/^[0-9a-f]{64}$/);
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    expect(() => parsePublicKey(rsa)).toThrow('invalid_public_key');
    expect(() => parsePublicKey('not base64!')).toThrow('invalid_public_key');
  });
});

describe('replay cache and rate limits (review XA-06, CA-09)', () => {
  it('remembers nonces per credential until they expire', () => {
    const cache = new NonceCache(1000, 10, 100);
    expect(cache.checkAndRemember('a', 'n', 0)).toBe(true);
    expect(cache.checkAndRemember('a', 'n', 500)).toBe(false);
    expect(cache.checkAndRemember('b', 'n', 500)).toBe(true);
    expect(cache.checkAndRemember('a', 'n', 1500)).toBe(true);
  });

  it('caps each credential without starving the others', () => {
    const cache = new NonceCache(60_000, 3, 100);
    for (const n of ['1', '2', '3']) expect(cache.checkAndRemember('noisy', n, 0)).toBe(true);
    expect(() => cache.checkAndRemember('noisy', '4', 0)).toThrow(expect.objectContaining({ status: 429 }));
    expect(cache.checkAndRemember('quiet', '1', 0)).toBe(true);
    expect(cache.checkAndRemember('noisy', '4', 60_001)).toBe(true);
  });

  it('treats new sources as exhausted when a fail-closed limiter is full, without touching existing buckets', () => {
    const failures = new RateLimiter(2, true);
    failures.charge('failures:a', 1, 5, 0);
    failures.charge('failures:b', 1, 5, 0);
    expect(failures.exhausted('failures:c', 1, 5, 0)).toBe(true);
    expect(failures.exhausted('failures:a', 1, 5, 0)).toBe(false);
    const principals = new RateLimiter(2);
    expect(principals.exhausted('agent:new', 1, 5, 0)).toBe(false);
  });

  it('remembers proven credentials with their key until they expire and stays bounded', () => {
    const recent = new RecentCredentials(1_000, 2);
    const key = parsePublicKey(generateSigningKeyPair().publicKeyB64).key;
    recent.remember('a', { key, nonceScope: 'agent:a' }, 0);
    recent.remember('b', { key, nonceScope: 'agent:b' }, 0);
    recent.remember('c', { key, nonceScope: 'agent:c' }, 0);
    expect(recent.get('a', 10)).toBeUndefined();
    expect(recent.get('c', 10)).toMatchObject({ nonceScope: 'agent:c' });
    expect(recent.get('c', 1_001)).toBeUndefined();
  });

  it('refills token buckets over time and reports Retry-After', () => {
    const limiter = new RateLimiter();
    limiter.take('agent:x', 60, 2, 0);
    limiter.take('agent:x', 60, 2, 0);
    expect(() => limiter.take('agent:x', 60, 2, 0)).toThrow(expect.objectContaining({ status: 429, retryAfterSeconds: 1 }));
    limiter.take('agent:y', 60, 2, 0);
    limiter.take('agent:x', 60, 2, 1_000);
  });
});
