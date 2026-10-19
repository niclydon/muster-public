#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { parseArgs } from 'node:util';
import pg from 'pg';
import { enrollPersistentKey, recoverWrites, revokeAgent, revokeAll, revokeGrant, revokeKey, revokeToken } from '../admin.js';
import { MusterError } from '../errors.js';
import { readKillSwitch, readKillSwitchState } from '../kill-switch.js';
import { loadRolesFile } from '../roles.js';
import { generateSigningKeyPair, parsePublicKey } from '../signing.js';

const USAGE = `muster-admin <command> [options]

  keygen --out-private <path>
      Write a new Ed25519 private key (mode 0600, never overwrites) and print its public key.
  enroll-persistent --agent <id> --public-key <base64 spki> [--expires-days 90] [--rotate]
      Also reinstates a revoked seat.
  revoke-token --token <mst_... or jti> --reason <text>
  revoke-key --key-id <uuid> --reason <text>
  revoke-agent --agent <id> --reason <text>
      Tombstones the agent and revokes any runners it brokered.
  revoke-grant --agent <runner id> --reason <text>
      Revokes the active launch grant for a runner id (recovery for a stuck or squatted id).
  revoke-all --reason <text> --confirm
      Break glass: revoke every key, token, and launch grant, and freeze writes.
  recover-writes --reason <text>
      Clear the break-glass read-only flag so mutating API routes accept writes again.
  kill-switch status
      Print the durable switch row (fail-closed: missing or unreadable is on).
  kill-switch on|off
      Removed. Toggle via authenticated POST /v1/admin/kill-switch {enabled, reason}
      as an operator principal. Actor is the authenticated identity, not --actor.

Database commands need DATABASE_URL for the admin role (not muster_api);
enroll-persistent also needs MUSTER_ROLES_FILE. Kill-switch status uses the
same DATABASE_URL. Toggling is operator-only on muster-api and needs
MUSTER_ADMIN_DATABASE_URL (vault secret muster/admin-database).`;

function required(values: Record<string, unknown>, name: string): string {
  const value = values[name];
  if (typeof value !== 'string' || value === '') {
    console.error(`--${name} is required\n\n${USAGE}`);
    process.exit(2);
  }
  return value;
}

async function withPool<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T> {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is required');
  const pool = new pg.Pool({ connectionString: url, max: 2, application_name: 'muster-admin' });
  try {
    return await fn(pool);
  } finally {
    await pool.end();
  }
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      'out-private': { type: 'string' },
      agent: { type: 'string' },
      'public-key': { type: 'string' },
      'expires-days': { type: 'string' },
      rotate: { type: 'boolean' },
      token: { type: 'string' },
      'key-id': { type: 'string' },
      reason: { type: 'string' },
      actor: { type: 'string' },
      confirm: { type: 'boolean' },
    },
  });
  const actor = `operator:muster-admin:${userInfo().username}`;

  switch (command) {
    case 'keygen': {
      const pair = generateSigningKeyPair();
      writeFileSync(required(values, 'out-private'), pair.privateKeyPem, { mode: 0o600, flag: 'wx' });
      console.log(JSON.stringify({ public_key: pair.publicKeyB64, public_key_sha256: parsePublicKey(pair.publicKeyB64).sha256 }));
      return;
    }
    case 'enroll-persistent': {
      const roles = loadRolesFile(required({ roles: process.env.MUSTER_ROLES_FILE }, 'roles'));
      const result = await withPool((pool) =>
        enrollPersistentKey(pool, roles, {
          agentId: required(values, 'agent'),
          publicKeyB64: required(values, 'public-key'),
          expiresInDays: values['expires-days'] ? Number(values['expires-days']) : undefined,
          rotate: values.rotate === true,
          actor,
        }),
      );
      console.log(JSON.stringify(result));
      return;
    }
    case 'revoke-token': {
      const result = await withPool((pool) => revokeToken(pool, { tokenOrJti: required(values, 'token'), reason: required(values, 'reason'), actor }));
      console.log(JSON.stringify(result));
      return;
    }
    case 'revoke-key': {
      const result = await withPool((pool) => revokeKey(pool, { keyId: required(values, 'key-id'), reason: required(values, 'reason'), actor }));
      console.log(JSON.stringify(result));
      return;
    }
    case 'revoke-agent': {
      const result = await withPool((pool) => revokeAgent(pool, { agentId: required(values, 'agent'), reason: required(values, 'reason'), actor }));
      console.log(JSON.stringify(result));
      return;
    }
    case 'revoke-grant': {
      const result = await withPool((pool) => revokeGrant(pool, { agentId: required(values, 'agent'), reason: required(values, 'reason'), actor }));
      console.log(JSON.stringify(result));
      return;
    }
    case 'revoke-all': {
      if (values.confirm !== true) {
        console.error('revoke-all needs --confirm');
        process.exit(2);
      }
      const result = await withPool((pool) => revokeAll(pool, { reason: required(values, 'reason'), actor }));
      console.log(JSON.stringify(result));
      return;
    }
    case 'recover-writes': {
      const result = await withPool((pool) => recoverWrites(pool, { reason: required(values, 'reason'), actor }));
      console.log(JSON.stringify(result));
      return;
    }
    case 'kill-switch': {
      const action = positionals[0];
      if (action === 'on' || action === 'off') {
        console.error(
          `kill-switch ${action} was removed. Toggle via authenticated POST /v1/admin/kill-switch with {enabled, reason}. Actor comes from the operator principal, not --actor.\n\n${USAGE}`,
        );
        process.exit(2);
      }
      if (action === 'status') {
        const status = await withPool(async (pool) => {
          const on = await readKillSwitch(pool);
          const state = await readKillSwitchState(pool);
          return { on, state };
        });
        console.log(
          JSON.stringify({
            kill_switch: status.on ? 'on' : 'off',
            actor: status.state?.actor ?? null,
            reason: status.state?.reason ?? null,
            updated_at: status.state?.updated_at.toISOString() ?? null,
            adapters: status.on ? 'off' : 'on',
            api: status.on ? 'read_only' : 'read_write',
          }),
        );
        return;
      }
      console.error(`kill-switch needs status (on|off was removed; use POST /v1/admin/kill-switch)\n\n${USAGE}`);
      process.exit(2);
    }
    default:
      console.error(USAGE);
      process.exit(2);
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof MusterError ? `error: ${err.code}` : `error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
