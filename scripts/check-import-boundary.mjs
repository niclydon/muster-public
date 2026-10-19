#!/usr/bin/env node
// Muster core must not import or reference Nexus work-management, Discord, or agent_inbox code
// (design section 9). Deployment knowledge enters only through a binding module loaded by path.
//
// Checks (AR XA-05, CA-13):
//   * every JS/TS source under packages/* (not just src), parsed with the TypeScript compiler:
//     static imports, re-exports, import-equals, dynamic import(), require(), require.resolve(),
//     and createRequire(); a module specifier must be a string literal, except the exact binding
//     loads listed in ALLOWED_DYNAMIC_IMPORTS
//   * forbidden names in any specifier, and in source text or JSON under packages/* outside test
//     directories (test fixtures may name deployment tables but not import deployment code)
//   * dependencies in the root and package manifests, and every package in package-lock.json
// Usage: node scripts/check-import-boundary.mjs [repo-root]
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = process.argv[2] ?? fileURLToPath(new URL('..', import.meta.url));

const FORBIDDEN = [
  { name: 'Nexus package or path', re: /@nexus\/|(^|[/\\])nexus([/\\.]|$)/i, specifierOnly: true },
  { name: 'operator backlog (OB) code', re: /operator[_-]?backlog|nexus_ob_|\bob[_-](claim|close|update|create|list|get)\b/i },
  { name: 'Discord code', re: /discord/i },
  { name: 'agent_inbox code', re: /agent[_-]?inbox/i },
];
const SOURCE_EXT = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/;
// Builtins that can load or run code from a specifier this scan cannot see (AR XC-02). Core has no use for them.
const LOADER_MODULES = new Set(
  ['module', 'vm', 'worker_threads', 'child_process', 'inspector', 'repl', 'wasi', 'cluster'].flatMap((m) => [m, `node:${m}`]),
);
const LOADER_IDENTIFIERS = new Set([
  'createRequire', 'eval', 'Function', 'getBuiltinModule', '_load', '_resolveFilename', 'dlopen',
  '_linkedBinding', 'runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction', 'SourceTextModule',
]);
// The only permitted non-literal module loads: the configured deployment binding in the service entry
// point, and the same load in the real-binding contract test. Matched by file and exact expression text;
// there is no source-comment escape hatch (AR XD-03).
const ALLOWED_DYNAMIC_IMPORTS = [
  { file: 'packages/core/src/bin/muster-api.ts', text: 'import(pathToFileURL(bindingModule).href)' },
  { file: 'packages/core/test/identity.test.ts', text: 'import(pathToFileURL(process.env.MUSTER_NEXUS_BINDING_PATH as string).href)' },
];

const violations = [];
const report = (file, line, message) => violations.push(`${relative(root, file)}${line ? `:${line}` : ''}: ${message}`);

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    if (name === 'node_modules' || name === 'dist' || name === '.git') return [];
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

function checkName(file, line, value, what) {
  for (const rule of FORBIDDEN) {
    if (rule.re.test(value)) report(file, line, `${what} "${value}" (${rule.name})`);
  }
}

function checkText(file, text) {
  text.split('\n').forEach((lineText, i) => {
    for (const rule of FORBIDDEN) {
      if (!rule.specifierOnly && rule.re.test(lineText)) report(file, i + 1, `references ${rule.name}`);
    }
  });
}

function checkDeps(file, manifest) {
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies']) {
    const deps = manifest[field];
    const names = Array.isArray(deps) ? deps : Object.keys(deps ?? {});
    for (const dep of names) checkName(file, 0, dep, `${field} entry`);
  }
}

/** Strips parentheses, casts, and non-null assertions, so `(process as any).binding` is still `process.binding`. */
function unwrap(node) {
  let current = node;
  while (
    current &&
    (ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isNonNullExpression(current) ||
      (ts.isSatisfiesExpression && ts.isSatisfiesExpression(current)))
  ) {
    current = current.expression;
  }
  return current;
}

function isStringLiteral(node) {
  return node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node));
}

// Test fixtures may name deployment tables (a stub claims table, the real-binding contract test);
// they are still held to every import rule.
const isTestFile = (file) => /(^|[/\\])(test|tests|__tests__)[/\\]/.test(relative(root, file));

function checkSource(file) {
  const text = readFileSync(file, 'utf8');
  if (!isTestFile(file)) checkText(file, text);
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const lineOf = (node) => source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
  const rel = relative(root, file).split('\\').join('/');
  const allowed = (node) =>
    ts.isCallExpression(node) &&
    ALLOWED_DYNAMIC_IMPORTS.some((a) => a.file === rel && node.getText(source).replace(/\s+/g, '') === a.text.replace(/\s+/g, ''));

  const checkSpecifier = (node, specifier) => {
    checkName(file, lineOf(node), specifier, 'import');
    if (LOADER_MODULES.has(specifier) && !allowed(node)) report(file, lineOf(node), `import of loader builtin "${specifier}" is not allowed`);
  };

  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && isStringLiteral(node.moduleSpecifier)) {
      checkSpecifier(node, node.moduleSpecifier.text);
    }
    if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      const expr = node.moduleReference.expression;
      if (isStringLiteral(expr)) checkSpecifier(node, expr.text);
      else if (!allowed(node)) report(file, lineOf(node), 'import = require() with a non-literal specifier');
    }
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const isDynamicImport = callee.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire =
        (ts.isIdentifier(callee) && callee.text === 'require') ||
        (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === 'require');
      if (isDynamicImport || isRequire) {
        const arg = node.arguments[0];
        if (isStringLiteral(arg)) checkSpecifier(node, arg.text);
        else if (!allowed(node)) report(file, lineOf(node), `${isDynamicImport ? 'import()' : 'require()'} with a non-literal specifier`);
      }
    }
    // Loaders that can hide a specifier from this scan are banned outright in core (AR XA-05 re-test):
    // createRequire and eval by any spelling, Function construction, `.require` on any object, and
    // computed member access on globals that expose a loader.
    if (ts.isIdentifier(node) && LOADER_IDENTIFIERS.has(node.text) && !allowed(node)) {
      report(file, lineOf(node), `${node.text} is not allowed`);
    }
    if (ts.isPropertyAccessExpression(node) && node.name.text === 'require' && !allowed(node)) {
      report(file, lineOf(node), '.require access is not allowed');
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(unwrap(node.expression)) &&
      unwrap(node.expression).text === 'process' &&
      ['binding', 'mainModule'].includes(node.name.text) &&
      !allowed(node)
    ) {
      report(file, lineOf(node), `process.${node.name.text} is not allowed`);
    }
    if (
      ts.isElementAccessExpression(node) &&
      ts.isIdentifier(unwrap(node.expression)) &&
      ['globalThis', 'global', 'module', 'process', 'require', 'self', 'window'].includes(unwrap(node.expression).text) &&
      !isStringLiteral(node.argumentExpression) &&
      !allowed(node)
    ) {
      report(file, lineOf(node), `computed access on ${unwrap(node.expression).text} is not allowed`);
    }
    if (ts.isElementAccessExpression(node) && isStringLiteral(node.argumentExpression) && (node.argumentExpression.text === 'require' || LOADER_IDENTIFIERS.has(node.argumentExpression.text)) && !allowed(node)) {
      report(file, lineOf(node), `["${node.argumentExpression.text}"] access is not allowed`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
}

const packagesDir = join(root, 'packages');
const packages = existsSync(packagesDir) ? readdirSync(packagesDir).filter((p) => statSync(join(packagesDir, p)).isDirectory()) : [];
if (packages.length === 0) {
  console.error(`[check-import-boundary] no packages found under ${packagesDir}`);
  process.exit(1);
}

for (const manifestPath of [join(root, 'package.json'), ...packages.map((p) => join(packagesDir, p, 'package.json'))]) {
  if (existsSync(manifestPath)) checkDeps(manifestPath, JSON.parse(readFileSync(manifestPath, 'utf8')));
}

const lockPath = join(root, 'package-lock.json');
if (existsSync(lockPath)) {
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  for (const key of Object.keys(lock.packages ?? {})) {
    const name = key.replace(/^.*node_modules\//, '');
    if (key.includes('node_modules/')) checkName(lockPath, 0, name, 'locked package');
  }
}

for (const pkg of packages) {
  for (const file of walk(join(packagesDir, pkg))) {
    if (SOURCE_EXT.test(file)) checkSource(file);
    else if (file.endsWith('.json') && !isTestFile(file)) checkText(file, readFileSync(file, 'utf8'));
  }
}

if (violations.length > 0) {
  console.error(`[check-import-boundary] ${violations.length} boundary violation(s):`);
  for (const v of violations) console.error(`  ${v}`);
  process.exit(1);
}
console.log(`[check-import-boundary] ok: ${packages.length} package(s) clean`);
