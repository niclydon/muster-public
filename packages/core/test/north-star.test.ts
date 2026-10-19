import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { canEditNorthStar, normalizeGoal } from '../src/north-star.js';
import { parseRolesConfig } from '../src/roles.js';

describe('north-star policy', () => {
  it('permits only operator sessions to replace the mission', () => {
    expect(canEditNorthStar({ agentId: 'operator-console', persistenceClass: 'persistent', principal: { roles: ['operator'] } } as any, 'mission')).toBe(true);
    expect(canEditNorthStar({ agentId: 'runner', persistenceClass: 'ephemeral', principal: { roles: ['fleet-ops'] } } as any, 'mission')).toBe(false);
  });

  it('accepts a bounded, ordered active goal', () => {
    expect(normalizeGoal({ title: 'Ship Muster', detail: 'Management surface', domain: 'platform', position: 2 })).toEqual({ title: 'Ship Muster', detail: 'Management surface', domain: 'platform', position: 2 });
  });

  it('does not treat a non-operator principal as a management operator', () => {
    expect(canEditNorthStar({ agentId: 'runner', persistenceClass: 'ephemeral', principal: { roles: ['fleet-ops'] } } as any, 'mission')).toBe(false);
  });

  it('rejects an enrollment id that matches no configured principal or pattern', () => {
    const roles = parseRolesConfig(`version: 1\nroles: { operator: { owner: op, may_address: [], addressable_by: [] } }\nprincipals: [{ agent_id: op, runtime: codex, persistence_class: persistent, roles: [operator] }]`);
    expect(() => roles.resolve('not-configured')).toThrow('agent_not_enrolled');
  });

  it('keeps enrollment as an execute-only verifier exception in the real 1895 fixture', () => {
    const sql = readFileSync(new URL('./fixtures/1895-ob60221-muster-management.sql', import.meta.url), 'utf8');
    expect(sql).toContain('REVOKE ALL ON FUNCTION agent_bus.muster_principal_enroll');
    expect(sql).toContain('GRANT EXECUTE ON FUNCTION agent_bus.muster_principal_enroll');
    expect(sql).not.toMatch(/GRANT (?:ALL|SELECT|INSERT|UPDATE) ON FUNCTION agent_bus\.muster_principal_enroll/);
    expect(sql).not.toMatch(/p_actor/);
  });
});
