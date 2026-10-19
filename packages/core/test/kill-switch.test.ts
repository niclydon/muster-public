import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MusterError } from '../src/errors.js';
import {
  adaptersEnabled,
  assertSwitchWritable,
  killSwitchActorFromAuth,
  memoryKillSwitch,
  normalizeKillSwitchActor,
  requireKillSwitchReason,
} from '../src/kill-switch.js';
import { RequestMetrics } from '../src/metrics.js';

describe('Muster kill switch (OB-60179)', () => {
  it('memory switch flips without touching disk', () => {
    const state = { on: false };
    const sw = memoryKillSwitch(state);
    expect(adaptersEnabled(sw)).toBe(true);
    assertSwitchWritable(sw);
    state.on = true;
    expect(adaptersEnabled(sw)).toBe(false);
    expect(() => assertSwitchWritable(sw)).toThrow(MusterError);
    try {
      assertSwitchWritable(sw);
    } catch (err) {
      expect(err).toMatchObject({ status: 503, code: 'read_only' });
    }
  });

  it('accepts operator, platform-ops, and nic, and rejects anyone else', () => {
    expect(normalizeKillSwitchActor('operator')).toBe('operator');
    expect(normalizeKillSwitchActor(' platform-ops ')).toBe('platform-ops');
    expect(normalizeKillSwitchActor('nic')).toBe('nic');
    expect(() => normalizeKillSwitchActor('fleet-controller')).toThrow(MusterError);
    expect(() => normalizeKillSwitchActor('operator:muster-admin:root')).toThrow(MusterError);
    try {
      normalizeKillSwitchActor('world');
    } catch (err) {
      expect(err).toMatchObject({ status: 403, code: 'kill_switch_forbidden' });
    }
  });

  it('requires a non-empty reason for both on and off', () => {
    expect(requireKillSwitchReason(' slice-1 incident ')).toBe('slice-1 incident');
    expect(() => requireKillSwitchReason('')).toThrow(MusterError);
    expect(() => requireKillSwitchReason('   ')).toThrow(MusterError);
    try {
      requireKillSwitchReason('\n');
    } catch (err) {
      expect(err).toMatchObject({ status: 400, code: 'reason_required' });
    }
  });

  it('derives the kill-switch actor from an operator principal, never a supplied seat name', () => {
    expect(killSwitchActorFromAuth({ agentId: 'nic', principal: { roles: ['operator'] } })).toBe('nic');
    expect(killSwitchActorFromAuth({ agentId: 'operator-console', principal: { roles: ['operator'] } })).toBe('operator');
    expect(() => killSwitchActorFromAuth({ agentId: 'project-manager', principal: { roles: ['pmo'] } })).toThrow(MusterError);
    try {
      killSwitchActorFromAuth({ agentId: 'project-manager', principal: { roles: ['pmo'] } });
    } catch (err) {
      expect(err).toMatchObject({ status: 403, code: 'principal_admin_forbidden' });
    }
  });

  it('toggle is a SECURITY DEFINER function that locks FOR UPDATE, not a TypeScript UPDATE', () => {
    const src = readFileSync(new URL('../src/kill-switch.ts', import.meta.url), 'utf8');
    const sql = readFileSync(new URL('./fixtures/1897-ob60179-muster-ops-baseline.sql', import.meta.url), 'utf8');
    const cli = readFileSync(new URL('../src/bin/muster-admin.ts', import.meta.url), 'utf8');
    expect(sql).toMatch(/operational_controls WHERE control_key = 'kill_switch' FOR UPDATE/);
    expect(sql).toContain('SECURITY DEFINER');
    expect(sql).toContain('GRANT EXECUTE ON FUNCTION agent_bus.muster_set_kill_switch(boolean, text, text) TO muster_admin');
    expect(src).toContain('agent_bus.muster_set_kill_switch');
    expect(src).not.toContain('pg_advisory');
    expect(cli).not.toMatch(/setKillSwitch\(/);
    expect(cli).toContain('/v1/admin/kill-switch');
  });
});

describe('Muster request metrics (OB-60179)', () => {
  it('computes write p99 from observed write durations and ignores GET /health', () => {
    const m = new RequestMetrics();
    m.observe('GET', '/health', 200, 5);
    for (let i = 1; i <= 100; i++) m.observe('POST', '/v1/messages', 201, i);
    expect(m.writeP99Ms()).toBe(99);
    const text = m.render({ killSwitchOn: true });
    expect(text).toContain('muster_kill_switch 1');
    expect(text).toContain('muster_http_write_p99_milliseconds 99');
    expect(text).toContain('path="/v1/messages"');
    expect(text).toContain('path="/health"');
  });
});
