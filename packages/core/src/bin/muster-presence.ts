#!/usr/bin/env node
// Keeps the configured persistent seats registered and live on muster-api (see presence.ts).
//   MUSTER_API_URL, MUSTER_AUDIENCE          the deployment
//   MUSTER_PRESENCE_AGENTS                   comma-separated agent ids
//   MUSTER_AGENT_KEY_<ID>                    each seat's private key (PEM or base64 PKCS#8 DER), from the vault
//   MUSTER_PRESENCE_INTERVAL_SECONDS         heartbeat period, default 300 (persistent presence TTL is 900)
import { loadPrivateKey } from '../client.js';
import { createLogger } from '../logger.js';
import { PresenceKeeper, seatKeyEnvName, type PresenceSeat } from '../presence.js';

const logger = createLogger('muster-presence');

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    logger.logMinimal(`${name} is required`);
    process.exit(2);
  }
  return value;
}

const baseUrl = requiredEnv('MUSTER_API_URL').replace(/\/$/, '');
const audience = requiredEnv('MUSTER_AUDIENCE');
const intervalMs = Number(process.env.MUSTER_PRESENCE_INTERVAL_SECONDS ?? '300') * 1000;
const agentIds = (process.env.MUSTER_PRESENCE_AGENTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);

const seats: PresenceSeat[] = [];
for (const agentId of agentIds) {
  const raw = process.env[seatKeyEnvName(agentId)];
  if (!raw || raw === 'pending') {
    logger.logMinimal(`${agentId}: no key in ${seatKeyEnvName(agentId)}; run scripts/muster-onboard-agent.mjs ${agentId}`);
    continue;
  }
  try {
    seats.push({ agentId, privateKey: loadPrivateKey(raw) });
  } catch (err) {
    logger.logMinimal(`${agentId}: unreadable key in ${seatKeyEnvName(agentId)}:`, err instanceof Error ? err.message : String(err));
  }
}
if (seats.length === 0) {
  // Not a failure: every seat may be held elsewhere (nexus-worker, the seat's own runtime). The unit is
  // Restart=on-failure, so it stays stopped until the onboarding script restarts it with a seat.
  logger.log('no seats configured (MUSTER_PRESENCE_AGENTS empty or no keys); nothing to hold, exiting');
  process.exit(0);
}

const keeper = new PresenceKeeper({
  audience,
  seats,
  intervalMs,
  logger,
  fetch: async (path, init) => {
    const res = await fetch(baseUrl + path, { ...init, signal: AbortSignal.timeout(10_000) });
    const text = await res.text();
    let json: Record<string, unknown> | null = null;
    try {
      json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
    } catch {
      logger.logDebug(`${path}: non-JSON response`, text.slice(0, 200));
    }
    return { status: res.status, json };
  },
});

let stopping = false;
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    logger.log(`${signal}: stopping`);
    stopping = true;
  });
}

logger.log(`keeping ${seats.length} seat(s) live on ${baseUrl}: ${seats.map((s) => s.agentId).join(', ')}; every ${intervalMs / 1000}s`);
while (!stopping) {
  const outcomes = await keeper.tick();
  logger.logDebug('outcomes', outcomes);
  await new Promise((resolve) => setTimeout(resolve, intervalMs));
}
process.exit(0);
