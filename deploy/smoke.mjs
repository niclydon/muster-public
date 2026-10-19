// OB-60176 live smoke against the deployed muster-api.
// Two phases, because the claim must be created after the launch grant:
//   node smoke.mjs grant    <runner_agent_id> <launcher_pem> <launcher_pub_b64>
//   (create the real claim for <runner_agent_id>)
//   node smoke.mjs register <runner_agent_id> <launcher_pem> <launcher_pub_b64> <claim_id>
// Prints one JSON line per step and exits 1 on the first unexpected result.
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import {
  canonicalRequest,
  generateSigningKeyPair,
  keyProofPayload,
  parsePublicKey,
  signPayload,
} from '/services/muster/packages/core/dist/index.js';

const BASE = process.env.MUSTER_URL ?? 'http://127.0.0.1:7880';
const AUDIENCE = process.env.MUSTER_AUDIENCE ?? 'muster:furnace';
const [phase, runnerId, launcherPemPath, launcherPub, claimId] = process.argv.slice(2);
if (!['grant', 'register'].includes(phase) || !runnerId || !launcherPemPath || !launcherPub || (phase === 'register' && !claimId)) {
  console.error('usage: node smoke.mjs grant|register <runner_agent_id> <launcher_pem> <launcher_pub_b64> [claim_id]');
  process.exit(2);
}
const launcherPem = readFileSync(launcherPemPath, 'utf8');
const launcherHash = parsePublicKey(launcherPub).sha256;

function signed(method, path, body, credential, authorization, signerPem, nonce = randomBytes(18).toString('base64url')) {
  const bodyText = body === undefined ? '' : JSON.stringify(body);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const payload = canonicalRequest({ audience: AUDIENCE, method, pathWithQuery: path, timestamp, nonce, body: Buffer.from(bodyText), credential });
  return {
    method,
    headers: {
      'content-type': 'application/json',
      authorization,
      'muster-timestamp': timestamp,
      'muster-nonce': nonce,
      'muster-signature': signPayload(signerPem, payload),
    },
    body: method === 'GET' ? undefined : bodyText,
  };
}

async function send(path, init) {
  const res = await fetch(BASE + path, init);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

function expectStep(name, got, status, check = () => true) {
  const ok = got.status === status && check(got.json);
  console.log(JSON.stringify({ step: name, ok, status: got.status, error: got.json?.error ?? null }));
  if (!ok) process.exit(1);
  return got.json;
}

expectStep('health', await send('/health', { method: 'GET' }), 200, (j) => j.status === 'ok');

// A second-resolution restart guard rejects requests signed in the server's start second; wait out one second.
await new Promise((resolve) => setTimeout(resolve, 1100));

const launcher = expectStep(
  'launcher_registers_with_seat_key',
  await send('/v1/register', signed('POST', '/v1/register', { persistence_class: 'persistent', agent_id: 'muster-smoke-launcher' }, `key:${launcherHash}`, `Muster-Key ${launcherHash}`, launcherPem)),
  201,
);
const asLauncher = (method, path, body) => signed(method, path, body, launcher.token, `Muster-PoP ${launcher.token}`, launcherPem);

if (phase === 'grant') {
  const grant = expectStep(
    'launcher_records_launch_grant',
    await send('/v1/launch-grants', asLauncher('POST', '/v1/launch-grants', { agent_id: runnerId })),
    201,
    (j) => j.agent_id === runnerId,
  );
  console.log(JSON.stringify({ step: 'grant_done', ok: true, grant_id: grant.grant_id, claim_window_ends_at: grant.claim_window_ends_at }));
  process.exit(0);
}

const runnerKey = generateSigningKeyPair();
const runnerHash = parsePublicKey(runnerKey.publicKeyB64).sha256;
const regNonce = randomBytes(18).toString('base64url');
const body = {
  persistence_class: 'ephemeral',
  agent_id: runnerId,
  claim_id: claimId,
  public_key: runnerKey.publicKeyB64,
  nonce: regNonce,
  key_proof: signPayload(
    runnerKey.privateKeyPem,
    keyProofPayload({ audience: AUDIENCE, agentId: runnerId, claimId, nonce: regNonce, publicKeySha256: runnerHash }),
  ),
};
const runner = expectStep(
  'launcher_brokers_runner_against_real_claim',
  await send('/v1/register', asLauncher('POST', '/v1/register', body)),
  201,
  (j) => j.agent_id === runnerId,
);
const asRunner = (method, path, reqBody, signerPem = runnerKey.privateKeyPem, nonce) =>
  signed(method, path, reqBody, runner.token, `Muster-PoP ${runner.token}`, signerPem, nonce);

const presenceInit = asRunner('PUT', '/v1/presence', {});
expectStep('runner_presence', await send('/v1/presence', presenceInit), 200, (j) => j.agent_id === runnerId);

expectStep(
  'registry_lists_runner_live',
  await send('/v1/registry', asRunner('GET', '/v1/registry', undefined)),
  200,
  (j) => j.entries.some((e) => e.agent_id === runnerId && e.presence_state === 'live' && e.persistence_class === 'ephemeral'),
);

const otherHost = generateSigningKeyPair();
expectStep(
  'cross_host_token_replay_rejected',
  await send('/v1/presence', asRunner('PUT', '/v1/presence', {}, otherHost.privateKeyPem)),
  401,
  (j) => j.error === 'bad_signature',
);

expectStep('captured_request_replay_rejected', await send('/v1/presence', presenceInit), 401, (j) => j.error === 'replayed_nonce');

// Since review XB-02 a launcher may replace its own grant (the old grant is revoked, not deleted); a different
// launcher taking over a live grant gets 409, which the identity suite covers. Here: the same-launcher
// replacement succeeds, and the runner's already-issued token keeps working, because grants gate registration only.
expectStep(
  'same_launcher_grant_replacement',
  await send('/v1/launch-grants', asLauncher('POST', '/v1/launch-grants', { agent_id: runnerId })),
  201,
  (j) => j.agent_id === runnerId,
);
expectStep('runner_token_survives_grant_replacement', await send('/v1/presence', asRunner('PUT', '/v1/presence', {})), 200, (j) => j.agent_id === runnerId);

console.log(JSON.stringify({ step: 'done', ok: true, runner_session: runner.session_id, launcher_session: launcher.session_id }));
