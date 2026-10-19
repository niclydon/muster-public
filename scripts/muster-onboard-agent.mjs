#!/usr/bin/env node
// Onboard a persistent Muster seat end to end, from Furnace, with no secret ever printed:
//   1. the agent must already be a persistent principal in the reviewed roles file
//   2. generate an Ed25519 seat key
//   3. store the private key in vault secret muster/agent-keys under the agent id (merged, never clobbered)
//   4. enroll the public key on muster-api as operator-console (rotate: any earlier key and its tokens are revoked)
//   5. wire the seat to its holder (--holder): `presence` (default) adds it to MUSTER_PRESENCE_AGENTS in
//      /services/muster/presence/.env.secrets and restarts muster-presence; `worker` adds it to MUSTER_WORKER_SEATS
//      in the same file (nexus-worker loads it) and restarts nexus-worker; `self` stores the key only, for a seat
//      whose own runtime registers (launchers, aria-grok, nova). One holder per seat: registering twice supersedes.
//   6. wait until the registry shows the seat live first-hand (proxied_by null); skipped for --holder self
// Usage: node scripts/muster-onboard-agent.mjs <agent_id> [--holder presence|worker|self] [--expires-days 90] [--no-restart]
// Re-running is safe: it rotates the key and moves the seat between holders. Runs outside packages/* because it
// shells out (import boundary).
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { generateSigningKeyPair, loadPrivateKey, loadRolesFile, parsePublicKey, seatKeyEnvName, signedRequest } from '../packages/core/dist/index.js';

const REPO = new URL('..', import.meta.url).pathname;
const ROLES_FILE = process.env.MUSTER_ROLES_FILE ?? '/services/nexus/muster/roles.yaml';
const CONSOLE_ENV = process.env.MUSTER_CONSOLE_ENV ?? '/etc/homelab/secrets/muster-operator-console.env';
const PRESENCE_DIR = process.env.MUSTER_PRESENCE_DIR ?? '/services/muster/presence';
const PRESENCE_ENV = process.env.MUSTER_PRESENCE_ENV ?? '/etc/homelab/secrets/muster-presence.env';
const SECRET_ID = 'muster/agent-keys';
const SV = '/home/niclydon/projects/secrets-vault/bin/sv';
const AWS_ENV = { ...process.env, HOME: homedir(), AWS_PROFILE: process.env.AWS_PROFILE ?? 'secrets', AWS_REGION: process.env.AWS_REGION ?? 'us-east-1' };

const { values: opts, positionals } = parseArgs({
  allowPositionals: true,
  options: { holder: { type: 'string', default: 'presence' }, 'expires-days': { type: 'string', default: '90' }, 'no-restart': { type: 'boolean', default: false } },
});
const agentId = positionals[0];
const holder = opts.holder;
if (!agentId || !['presence', 'worker', 'self'].includes(holder)) {
  console.error('usage: node scripts/muster-onboard-agent.mjs <agent_id> [--holder presence|worker|self] [--expires-days 90] [--no-restart]');
  process.exit(2);
}
const expiresInDays = Number(opts['expires-days']);

function step(name, extra = {}) {
  console.log(JSON.stringify({ step: name, ok: true, ...extra }));
}
function fail(name, detail) {
  console.log(JSON.stringify({ step: name, ok: false, detail }));
  process.exit(1);
}
/** Runs a command with stdio captured; the output is never echoed unless the caller asks. */
function run(cmd, args, env = process.env) {
  const res = spawnSync(cmd, args, { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  return { status: res.status ?? -1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}
/** KEY=VALUE lines from a materialized env file (values may be quoted). Read by this process only. */
function readEnvFile(path) {
  const out = {};
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    out[m[1]] = v;
  }
  return out;
}

// 1. roles
let principal;
try {
  principal = loadRolesFile(ROLES_FILE).resolve(agentId);
} catch (err) {
  fail('roles_file_has_principal', {
    error: err instanceof Error ? err.message : String(err),
    fix: `add a persistent principal for ${agentId} to muster/roles.yaml in the nexus repo (PR), deploy nexus, then \`sudo systemctl kill -s HUP muster-api\``,
  });
}
if (principal.persistenceClass !== 'persistent') fail('roles_file_has_principal', { error: 'class_mismatch', persistence_class: principal.persistenceClass });
step('roles_file_has_principal', { agent_id: agentId, runtime: principal.runtime, roles: principal.roles });

// 2. keygen
const pair = generateSigningKeyPair();
const privateKeyDerB64 = pair.privateKeyPem.split('\n').filter((l) => l && !l.startsWith('-----')).join('');
const publicKeySha256 = parsePublicKey(pair.publicKeyB64).sha256;
step('keygen', { public_key_sha256: publicKeySha256 });

// 3. vault: merge into muster/agent-keys
// Read the current secret with boto3 (what sv itself uses; there is no aws CLI on Furnace). A missing
// secret is an empty object; the value never leaves this process.
const READ_SECRET = `
import json, sys, boto3, botocore
c = boto3.session.Session(profile_name=sys.argv[2], region_name=sys.argv[3]).client("secretsmanager")
try:
    print(c.get_secret_value(SecretId=sys.argv[1])["SecretString"])
except c.exceptions.ResourceNotFoundException:
    print("{}")
`;
const current = run('python3', ['-c', READ_SECRET, SECRET_ID, AWS_ENV.AWS_PROFILE, AWS_ENV.AWS_REGION], AWS_ENV);
if (current.status !== 0) fail('vault_read', { error: current.stderr.trim().split('\n').at(-1)?.slice(0, 300) ?? 'unknown' });
let keys = {};
try {
  keys = JSON.parse(current.stdout);
  if (!keys || typeof keys !== 'object' || Array.isArray(keys)) throw new Error('not an object');
} catch {
  fail('vault_merge', { error: `${SECRET_ID} is not a JSON object` });
}
keys[agentId] = privateKeyDerB64;
keys[`${agentId}.public_key`] = pair.publicKeyB64;
const tmp = mkdtempSync(join(tmpdir(), 'muster-onboard-'));
try {
  const file = join(tmp, 'agent-keys.json');
  writeFileSync(file, JSON.stringify(keys), { mode: 0o600 });
  const push = run(SV, ['push', SECRET_ID, '--file', file], AWS_ENV);
  if (push.status !== 0) fail('vault_push', { error: push.stderr.trim().slice(0, 300) });
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
step('vault_push', { secret: SECRET_ID, key: agentId, seats_in_secret: Object.keys(keys).filter((k) => !k.endsWith('.public_key')).length });

// 4. enroll as operator-console
const consoleEnv = readEnvFile(CONSOLE_ENV);
for (const name of ['MUSTER_API_URL', 'MUSTER_AUDIENCE', 'MUSTER_OPERATOR_SIGNING_KEY', 'MUSTER_OPERATOR_TOKEN']) {
  if (!consoleEnv[name] || consoleEnv[name] === 'pending') fail('console_credential', { error: `${name} missing in ${CONSOLE_ENV}; redeploy muster or re-issue the operator-console token` });
}
const baseUrl = consoleEnv.MUSTER_API_URL.replace(/\/$/, '');
const consoleKey = loadPrivateKey(consoleEnv.MUSTER_OPERATOR_SIGNING_KEY);
async function asConsole(method, path, body) {
  const init = signedRequest({ audience: consoleEnv.MUSTER_AUDIENCE, method, path, body, credential: { kind: 'token', token: consoleEnv.MUSTER_OPERATOR_TOKEN }, privateKey: consoleKey });
  const res = await fetch(baseUrl + path, { ...init, signal: AbortSignal.timeout(10_000) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}
const enrolled = await asConsole('POST', '/v1/principals/enroll', { agent_id: agentId, public_key: pair.publicKeyB64, expires_in_days: expiresInDays, rotate: true });
if (enrolled.status !== 201) {
  fail('enroll', {
    status: enrolled.status,
    error: enrolled.json?.error ?? null,
    hint: enrolled.status === 401 ? 'operator-console session is stale: re-issue its token (docs/runbooks/muster.md, onboarding section)' : undefined,
  });
}
step('enroll', { key_id: enrolled.json.key_id, expires_at: enrolled.json.expires_at, rotated_key_ids: enrolled.json.rotated_key_ids, reinstated: enrolled.json.reinstated });

// 5. holder wiring
if (holder === 'self') {
  step('holder', { holder: 'self', key_ref: `{aws:secret:${SECRET_ID}#${agentId}}`, note: 'the seat runtime loads this key and registers itself; nothing on Furnace holds its session' });
  process.exit(0);
}
const envSecrets = join(PRESENCE_DIR, '.env.secrets');
if (!existsSync(envSecrets)) {
  run('mkdir', ['-p', PRESENCE_DIR]);
  writeFileSync(envSecrets, readFileSync(join(REPO, 'deploy', 'presence.env.secrets.template'), 'utf8'), { mode: 0o640 });
}
const varName = seatKeyEnvName(agentId);
const lines = readFileSync(envSecrets, 'utf8').split('\n');
/** Adds or removes the seat in a comma-list variable, keeping the line in place. */
function setList(name, present) {
  const idx = lines.findIndex((l) => l.startsWith(`${name}=`));
  const ids = (idx >= 0 ? lines[idx].slice(name.length + 1) : '').split(',').map((s) => s.trim()).filter(Boolean).filter((id) => id !== agentId);
  if (present) ids.push(agentId);
  const line = `${name}=${ids.join(',')}`;
  if (idx >= 0) lines[idx] = line;
  else lines.push(line);
  return ids;
}
const presenceAgents = setList('MUSTER_PRESENCE_AGENTS', holder === 'presence');
const workerSeats = setList('MUSTER_WORKER_SEATS', holder === 'worker');
const keyLine = `${varName}={aws:secret:${SECRET_ID}#${agentId}}`;
const keyIdx = lines.findIndex((l) => l.startsWith(`${varName}=`));
if (keyIdx >= 0) lines[keyIdx] = keyLine;
else lines.push(keyLine);
writeFileSync(envSecrets, `${lines.join('\n').replace(/\n+$/, '')}\n`, { mode: 0o640 });
step('holder', { holder, file: envSecrets, presence_agents: presenceAgents, worker_seats: workerSeats });

// Moving a seat between holders empties a list variable; that shrink is deliberate, so tell sv's shrink guard.
const listShrank = holder !== 'presence' || workerSeats.length === 0;
const materialize = run('sudo', ['-n', 'env', `HOME=${homedir()}`, `AWS_PROFILE=${AWS_ENV.AWS_PROFILE}`, `AWS_REGION=${AWS_ENV.AWS_REGION}`, SV, 'materialize', '--cwd', PRESENCE_DIR, '--output', PRESENCE_ENV, '--owner', 'root', '--group', 'niclydon', '--mode', '0640', '--backup-previous', ...(listShrank ? ['--allow-shrink'] : [])]);
if (materialize.status !== 0) fail('materialize', { error: `${materialize.stdout}\n${materialize.stderr}`.trim().split('\n').filter((l) => /abort|refus|error:|failed/i.test(l) && !/fetch_secrets|resolve_environment/.test(l)).join(' | ').slice(0, 400) });
step('materialize', { output: PRESENCE_ENV });

// Both units read the same file: muster-presence always restarts so it drops a seat that moved to the worker.
const units = holder === 'worker' ? ['muster-presence', 'nexus-worker'] : ['muster-presence'];
if (opts['no-restart']) {
  step('restart', { skipped: true, units });
} else {
  for (const unit of units) {
    const restart = run('sudo', ['-n', 'systemctl', 'restart', unit]);
    if (restart.status !== 0) fail('restart', { unit, error: restart.stderr.trim().slice(0, 300), hint: unit === 'muster-presence' ? 'deploy muster first (deploy/deploy.sh installs muster-presence.service)' : 'nexus-worker must carry the seat keeper (nexus PR #2861) and EnvironmentFile=-/etc/homelab/secrets/muster-presence.env' });
    step('restart', { unit });
  }
}

// 6. verify first-hand presence
const journal = holder === 'worker' ? 'journalctl -u nexus-worker -n 50 | grep muster-seats' : 'journalctl -u muster-presence -n 50';
for (let attempt = 0; attempt < 24; attempt += 1) {
  const registry = await asConsole('GET', '/v1/registry');
  const entry = registry.json?.entries?.find((e) => e.agent_id === agentId);
  if (entry && entry.proxied_by === null && entry.presence_state === 'live') {
    step('registry_live_first_hand', { agent_id: agentId, holder, last_seen_at: entry.last_seen_at, ttl_seconds: entry.ttl_seconds, roles: entry.roles, initiative_tier: entry.initiative_tier });
    process.exit(0);
  }
  if (opts['no-restart']) {
    step('registry_live_first_hand', { skipped: true, reason: `${units.join(', ')} not restarted`, current: entry ? { presence_state: entry.presence_state, proxied_by: entry.proxied_by } : null });
    process.exit(0);
  }
  await new Promise((r) => setTimeout(r, 5000));
}
fail('registry_live_first_hand', { error: `seat did not come live within 120s; check \`${journal}\`` });
