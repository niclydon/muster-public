import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const src = readFileSync(new URL('../../packages/core/src/bin/muster-admin.ts', import.meta.url), 'utf8');
const dist = fileURLToPath(new URL('../../packages/core/dist/bin/muster-admin.js', import.meta.url));

describe('muster-admin kill-switch CLI (OB-60179)', () => {
  it('removed set and cannot toggle even with a database URL', () => {
    expect(src).not.toMatch(/setKillSwitch\(/);
    expect(src).toContain('POST /v1/admin/kill-switch');
    expect(existsSync(dist), 'npm run build before npm test so the CLI binary exists').toBe(true);
    const result = spawnSync(
      process.execPath,
      [dist, 'kill-switch', 'on', '--actor', 'operator', '--reason', 'cli must not toggle'],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          DATABASE_URL: process.env.MUSTER_TEST_DATABASE_URL ?? 'postgres://invalid@127.0.0.1:1/invalid_test',
        },
      },
    );
    expect(result.status).toBe(2);
    expect(`${result.stderr}${result.stdout}`).toMatch(/\/v1\/admin\/kill-switch/);
  });
});
