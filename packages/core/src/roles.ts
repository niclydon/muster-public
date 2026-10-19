import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { MusterError } from './errors.js';

export type PersistenceClass = 'persistent' | 'ephemeral' | 'operator_interactive';

export const RUNTIMES = [
  'nexus_agent',
  'grok_seat',
  'meta_seat',
  'claude_code',
  'codex',
  'grok_cli',
  'kimi',
  'antigravity',
  'deploy',
  'worker',
] as const;

/** Runtimes each persistence class may declare (design 4.1: class is validated against runtime). */
const CLASS_RUNTIMES: Record<PersistenceClass, ReadonlySet<string>> = {
  persistent: new Set(RUNTIMES),
  ephemeral: new Set(['claude_code', 'codex', 'grok_cli', 'kimi', 'antigravity', 'deploy', 'worker']),
  operator_interactive: new Set(['claude_code', 'codex', 'grok_cli', 'kimi', 'antigravity']),
};

const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,199}$/;
const AGENT_ID_PATTERN = /^[A-Za-z0-9*][A-Za-z0-9_.:@*-]{0,199}$/;
const ROLE_NAME = /^[a-z][a-z0-9-]{0,63}$/;

export interface RoleSpec {
  owner: string;
  mayAddress: string[];
  addressableBy: string[];
}

export interface PrincipalSpec {
  agentId: string | null;
  agentIdPattern: string | null;
  matcher: RegExp | null;
  runtime: string;
  persistenceClass: PersistenceClass;
  roles: string[];
  launchedBy: string[];
  scope: Record<string, unknown>;
}

export interface ResolvedPrincipal {
  agentId: string;
  runtime: string;
  persistenceClass: PersistenceClass;
  roles: string[];
  mayAddress: string[];
  addressableBy: string[];
  scope: Record<string, unknown>;
  launchedBy: string[];
}

export interface RolesConfig {
  roles: Map<string, RoleSpec>;
  principals: PrincipalSpec[];
  /** Resolves an exact agent_id to its enrolled spec. Patterns bound enrollment; the exact id is returned. */
  resolve(agentId: string): ResolvedPrincipal;
}

export function isValidAgentId(value: unknown): value is string {
  return typeof value === 'string' && AGENT_ID.test(value);
}

function fail(message: string): never {
  throw new Error(`roles file: ${message}`);
}

function stringList(value: unknown, where: string, check: (s: string) => boolean): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) fail(`${where} must be a list`);
  return value.map((item, i) => {
    if (typeof item !== 'string' || !check(item)) fail(`${where}[${i}] is invalid`);
    return item;
  });
}

function onlyKeys(obj: Record<string, unknown>, allowed: string[], where: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) fail(`${where} has unknown key "${key}"`);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * `*` matches one or more characters within one id segment, so a pattern never widens across `:`
 * separators and never matches an empty segment (AR CA-04).
 */
function patternToRegExp(pattern: string): RegExp {
  const body = pattern
    .split('*')
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('[A-Za-z0-9_.@-]+');
  return new RegExp(`^${body}$`);
}

export function parseRolesConfig(text: string): RolesConfig {
  const doc: unknown = parse(text);
  if (!isPlainObject(doc)) fail('top level must be a mapping');
  onlyKeys(doc, ['version', 'roles', 'principals'], 'top level');
  if (doc.version !== 1) fail('version must be 1');
  if (!isPlainObject(doc.roles)) fail('roles must be a mapping');
  if (!Array.isArray(doc.principals)) fail('principals must be a list');

  const roles = new Map<string, RoleSpec>();
  for (const [name, raw] of Object.entries(doc.roles)) {
    if (!ROLE_NAME.test(name)) fail(`role name "${name}" is invalid`);
    if (!isPlainObject(raw)) fail(`role ${name} must be a mapping`);
    onlyKeys(raw, ['owner', 'may_address', 'addressable_by', 'routed', 'notes'], `role ${name}`);
    if (typeof raw.owner !== 'string' || raw.owner.trim() === '') fail(`role ${name} needs an owner`);
    roles.set(name, {
      owner: raw.owner,
      mayAddress: stringList(raw.may_address, `role ${name}.may_address`, (s) => ROLE_NAME.test(s)),
      addressableBy: stringList(raw.addressable_by, `role ${name}.addressable_by`, (s) => ROLE_NAME.test(s)),
    });
  }
  for (const [name, spec] of roles) {
    for (const ref of [...spec.mayAddress, ...spec.addressableBy]) {
      if (!roles.has(ref)) fail(`role ${name} references unknown role "${ref}"`);
    }
  }

  const exactIds = new Set<string>();
  const patterns = new Set<string>();
  const principals: PrincipalSpec[] = doc.principals.map((raw, i) => {
    const where = `principals[${i}]`;
    if (!isPlainObject(raw)) fail(`${where} must be a mapping`);
    onlyKeys(raw, ['agent_id', 'agent_id_pattern', 'runtime', 'persistence_class', 'roles', 'launched_by', 'scope', 'notes'], where);
    const hasId = raw.agent_id !== undefined;
    const hasPattern = raw.agent_id_pattern !== undefined;
    if (hasId === hasPattern) fail(`${where} needs exactly one of agent_id or agent_id_pattern`);
    if (hasId && !isValidAgentId(raw.agent_id)) fail(`${where}.agent_id is invalid`);
    if (hasPattern && (typeof raw.agent_id_pattern !== 'string' || !AGENT_ID_PATTERN.test(raw.agent_id_pattern) || !raw.agent_id_pattern.includes('*'))) {
      fail(`${where}.agent_id_pattern is invalid`);
    }
    const persistenceClass = raw.persistence_class;
    if (persistenceClass !== 'persistent' && persistenceClass !== 'ephemeral' && persistenceClass !== 'operator_interactive') {
      fail(`${where}.persistence_class is invalid`);
    }
    if (typeof raw.runtime !== 'string' || !CLASS_RUNTIMES[persistenceClass].has(raw.runtime)) {
      fail(`${where}.runtime is not allowed for ${persistenceClass}`);
    }
    const principalRoles = stringList(raw.roles, `${where}.roles`, (s) => roles.has(s));
    const launchedBy = stringList(raw.launched_by, `${where}.launched_by`, (s) => AGENT_ID.test(s));
    if (persistenceClass === 'ephemeral' && launchedBy.length === 0) fail(`${where} is ephemeral and needs launched_by`);
    if (persistenceClass !== 'ephemeral' && launchedBy.length > 0) fail(`${where} is not ephemeral and cannot have launched_by`);
    if (raw.scope !== undefined && !isPlainObject(raw.scope)) fail(`${where}.scope must be a mapping`);
    if (hasId) {
      if (exactIds.has(raw.agent_id as string)) fail(`${where} duplicates agent_id ${String(raw.agent_id)}`);
      exactIds.add(raw.agent_id as string);
    } else {
      if (patterns.has(raw.agent_id_pattern as string)) fail(`${where} duplicates agent_id_pattern`);
      patterns.add(raw.agent_id_pattern as string);
    }
    return {
      agentId: hasId ? (raw.agent_id as string) : null,
      agentIdPattern: hasPattern ? (raw.agent_id_pattern as string) : null,
      matcher: hasPattern ? patternToRegExp(raw.agent_id_pattern as string) : null,
      runtime: raw.runtime,
      persistenceClass,
      roles: principalRoles,
      launchedBy,
      scope: (raw.scope as Record<string, unknown> | undefined) ?? {},
    };
  });

  return {
    roles,
    principals,
    resolve(agentId: string): ResolvedPrincipal {
      if (!isValidAgentId(agentId)) throw new MusterError(400, 'invalid_agent_id');
      const exact = principals.find((p) => p.agentId === agentId);
      let spec = exact;
      if (!spec) {
        const matches = principals.filter((p) => p.matcher?.test(agentId));
        if (matches.length === 0) throw new MusterError(403, 'agent_not_enrolled');
        if (matches.length > 1) throw new MusterError(403, 'enrollment_ambiguous');
        spec = matches[0];
      }
      if (!spec) throw new MusterError(403, 'agent_not_enrolled');
      const union = (pick: (r: RoleSpec) => string[]) =>
        [...new Set(spec.roles.flatMap((name) => pick(roles.get(name) as RoleSpec)))].sort();
      return {
        agentId,
        runtime: spec.runtime,
        persistenceClass: spec.persistenceClass,
        roles: [...spec.roles],
        mayAddress: union((r) => r.mayAddress),
        addressableBy: union((r) => r.addressableBy),
        scope: spec.scope,
        launchedBy: [...spec.launchedBy],
      };
    },
  };
}

export function loadRolesFile(path: string): RolesConfig {
  return parseRolesConfig(readFileSync(path, 'utf8'));
}
