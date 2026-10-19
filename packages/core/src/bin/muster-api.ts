#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import pg from 'pg';
import { assertBinding } from '../binding.js';
import { createMusterServer } from '../http.js';
import { createNonceCache, type MusterContext } from '../identity.js';
import { readKillSwitch } from '../kill-switch.js';
import { createLogger } from '../logger.js';
import { RequestMetrics } from '../metrics.js';
import { DEFAULT_RATE_LIMITS, RateLimiter } from '../rate-limit.js';
import { RecentCredentials } from '../recent-credentials.js';
import { loadRolesFile } from '../roles.js';

const logger = createLogger('muster-api');

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  const pool = new pg.Pool({
    connectionString: requiredEnv('DATABASE_URL'),
    max: Number(process.env.MUSTER_DB_POOL_MAX ?? 10),
    application_name: 'muster-api',
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
  });
  pool.on('error', (err) => logger.logMinimal('idle database client error:', (err as { code?: string }).code ?? err.name));

  const adminUrl = process.env.MUSTER_ADMIN_DATABASE_URL;
  const adminPool = adminUrl
    ? new pg.Pool({
        connectionString: adminUrl,
        max: Number(process.env.MUSTER_ADMIN_DB_POOL_MAX ?? 5),
        application_name: 'muster-api-admin',
        connectionTimeoutMillis: 5_000,
        statement_timeout: 5_000,
      })
    : undefined;
  adminPool?.on('error', (err) => logger.logMinimal('idle admin database client error:', (err as { code?: string }).code ?? err.name));

  const rolesFile = requiredEnv('MUSTER_ROLES_FILE');
  const bindingModule = requiredEnv('MUSTER_BINDING_MODULE');
  // The deployment binding is loaded by configured path (design section 9); the boundary check allows exactly this expression.
  const loaded = (await import(pathToFileURL(bindingModule).href)) as { default?: unknown };

  const ctx: MusterContext = {
    pool,
    adminPool,
    roles: loadRolesFile(rolesFile),
    binding: assertBinding(loaded.default),
    nonces: createNonceCache(),
    limiter: new RateLimiter(),
    failureLimiter: new RateLimiter(20_000, true),
    recent: new RecentCredentials(),
    limits: DEFAULT_RATE_LIMITS,
    audience: requiredEnv('MUSTER_AUDIENCE'),
    startedAtSeconds: Math.floor(Date.now() / 1000),
    logger,
    metrics: new RequestMetrics(),
  };
  setInterval(() => {
    ctx.nonces.prune();
    ctx.limiter.prune();
    ctx.failureLimiter.prune();
    ctx.recent.prune();
  }, 60_000).unref();

  const host = requiredEnv('MUSTER_HOST');
  const port = Number(requiredEnv('MUSTER_PORT'));
  const server = createMusterServer(ctx);
  const killSwitchOn = await readKillSwitch(pool);
  server.listen(port, host, () => {
    logger.log(
      `listening on ${host}:${port}; audience=${ctx.audience} roles=${rolesFile} principals=${ctx.roles.principals.length} binding=${bindingModule} kill_switch=${killSwitchOn ? 'on' : 'off'}`,
    );
  });

  // A roles file change is a reviewed deploy; SIGHUP applies it without dropping the replay cache.
  process.on('SIGHUP', () => {
    try {
      ctx.roles = loadRolesFile(rolesFile);
      logger.log(`roles reloaded: principals=${ctx.roles.principals.length}`);
    } catch (err) {
      logger.logMinimal('roles reload failed; keeping previous roles:', err instanceof Error ? err.message : String(err));
    }
  });

  const shutdown = (signal: string) => {
    logger.log(`${signal} received; closing`);
    server.close(() => {
      Promise.all([pool.end(), adminPool?.end() ?? Promise.resolve()]).finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err: unknown) => {
  logger.logMinimal('startup failed:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
