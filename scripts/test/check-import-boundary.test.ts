import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const SCRIPT = fileURLToPath(new URL('../check-import-boundary.mjs', import.meta.url));
const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const roots: string[] = [];

function run(root: string) {
  return spawnSync(process.execPath, [SCRIPT, root], { encoding: 'utf8' });
}

function fixture(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'muster-boundary-'));
  roots.push(root);
  for (const [path, content] of Object.entries({ 'packages/core/package.json': '{"name":"x"}', ...files })) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('core import boundary check (design section 9)', () => {
  it('passes on this repository', () => {
    const result = run(REPO_ROOT);
    expect(result.status, result.stderr).toBe(0);
  });

  it('passes a clean package and the exact allowlisted binding load in the service entry point', () => {
    const root = fixture({
      'packages/core/src/ok.ts': "import pg from 'pg';\n",
      'packages/core/src/bin/muster-api.ts': "import { pathToFileURL } from 'node:url';\nconst bindingModule = process.env.B as string;\nawait import(pathToFileURL(bindingModule).href);\n",
    });
    const result = run(root);
    expect(result.status, result.stderr).toBe(0);
  });

  it('has no comment escape hatch and allows the binding load nowhere else (review XD-03)', () => {
    const annotated = fixture({
      'packages/core/src/a.ts': "// muster-boundary: allow-dynamic-import convenience\nawait import('@' + 'nexus/core');\n",
    });
    expect(run(annotated).status).toBe(1);
    const elsewhere = fixture({
      'packages/core/src/other.ts': "import { pathToFileURL } from 'node:url';\nconst bindingModule = 'x';\nawait import(pathToFileURL(bindingModule).href);\n",
    });
    expect(run(elsewhere).status).toBe(1);
    const altered = fixture({
      'packages/core/src/bin/muster-api.ts': "import { pathToFileURL } from 'node:url';\nconst bindingModule = 'x';\nawait import(pathToFileURL('@' + bindingModule).href);\n",
    });
    expect(run(altered).status).toBe(1);
  });

  it('lets test fixtures name deployment tables but not import deployment code', () => {
    const named = fixture({ 'packages/core/test/helpers.ts': "const stub = 'CREATE TABLE operator_backlog_claims (id uuid)';\n" });
    expect(run(named).status, run(named).stderr).toBe(0);
    const imported = fixture({ 'packages/core/test/helpers.ts': "import { claim } from '@nexus/core';\n" });
    expect(run(imported).status).toBe(1);
    const computed = fixture({ 'packages/core/test/helpers.ts': "await import(['disc', 'ord.js'].join(''));\n" });
    expect(run(computed).status).toBe(1);
  });

  it.each([
    ['static Nexus import', 'packages/core/src/a.ts', "import { reserveMigrationVersion } from '@nexus/core';"],
    ['relative path into nexus', 'packages/core/src/a.ts', "import { deliver } from '../../nexus/packages/worker/src/lib/comms.js';"],
    ['literal dynamic Discord import', 'packages/core/src/a.ts', "const { Client } = await import('discord.js');"],
    ['claims SQL', 'packages/core/src/a.ts', "const holds = 'SELECT * FROM operator_backlog_claims';"],
    ['agent_inbox reference', 'packages/core/src/a.ts', "export const sink = 'agent_inbox';"],
    ['OB helper import', 'packages/core/src/a.ts', "import { claim } from './ob-claim.js';"],
    ['computed dynamic import', 'packages/core/src/a.ts', "const mod = await import(['@ne', 'xus/core'].join(''));"],
    ['computed require', 'packages/core/src/a.cjs', "const m = require('@ne' + 'xus/core');"],
    ['template dynamic import', 'packages/core/src/a.ts', 'const name = "x"; await import(`${name}`);'],
    ['import outside src', 'packages/core/lib/a.ts', "import x from '@nexus/core';"],
    ['tsx file', 'packages/core/src/a.tsx', "import { Client } from 'discord.js';"],
    ['re-export', 'packages/core/src/a.ts', "export * from '@nexus/core';"],
    ['import-equals', 'packages/core/src/a.ts', "import inbox = require('agent-inbox');"],
    ['second package', 'packages/extra/src/a.mjs', "import x from 'discord.js';"],
    ['aliased createRequire', 'packages/core/src/a.ts', "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nload('@' + 'ne' + 'xus/core');"],
    ['builtin module createRequire', 'packages/core/src/a.ts', "const m = process.getBuiltinModule('module');\nm.createRequire(import.meta.url)('x');"],
    ['module.require', 'packages/core/src/a.cjs', "module.require('@' + 'nexus/core');"],
    ['eval', 'packages/core/src/a.ts', "eval(\"import('\" + 'discord.js' + \"')\");"],
    ['Function constructor', 'packages/core/src/a.ts', "new Function('return import(\"x\")')();"],
    ['computed global access', 'packages/core/src/a.ts', "const r = globalThis['req' + 'uire'];"],
    ['Module._load', 'packages/core/src/a.ts', "import Module from 'node:module';\nModule._load('@' + 'ne' + 'xus/core', null, false);"],
    ['Module._load without the import', 'packages/core/src/a.ts', "declare const M: { _load(s: string): unknown };\nM._load('@' + 'nexus/core');"],
    ['vm', 'packages/core/src/a.ts', "import vm from 'node:vm';\nvm.runInThisContext('1');"],
    ['worker_threads', 'packages/core/src/a.ts', "import { Worker } from 'worker_threads';\nnew Worker('x', { eval: true });"],
    ['child_process', 'packages/core/src/a.ts', "import { spawn } from 'node:child_process';\nspawn('node', ['-e', 'x']);"],
    ['process.binding', 'packages/core/src/a.ts', "(process as any).binding('fs');"],
    ['string-keyed _load', 'packages/core/src/a.ts', "declare const M: Record<string, unknown>;\nconst f = M['_load'];"],
  ])('fails on a planted violation: %s', (_name, path, line) => {
    const result = run(fixture({ [path]: `${line}\n` }));
    expect(result.status, result.stdout).toBe(1);
    expect(result.stderr).toContain('boundary violation');
  });

  it('fails on a forbidden dependency in a package manifest, the root manifest, or the lockfile', () => {
    expect(run(fixture({ 'packages/core/package.json': '{"name":"x","dependencies":{"discord.js":"^14.0.0"}}' })).status).toBe(1);
    expect(run(fixture({ 'package.json': '{"name":"root","devDependencies":{"@nexus/core":"*"}}' })).status).toBe(1);
    expect(run(fixture({ 'package-lock.json': '{"packages":{"node_modules/some-lib/node_modules/discord-api-types":{}}}' })).status).toBe(1);
  });
});
