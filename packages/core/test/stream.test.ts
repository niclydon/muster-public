import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { RateLimiter } from '../src/rate-limit.js';
import {
  enrollAndRegisterPersistent,
  GENEROUS_LIMITS,
  hasDb,
  putPresence,
  resetDatabase,
  send,
  startHarness,
  tokenAuth,
  type Harness,
  type TestPrincipal,
} from './helpers.js';

// Roles for the stream suite (design 6 and 10.1 shape): bidirectional addressability, an owner that holds
// nothing (life/harbor), and one agent holding two roles.
const STREAM_ROLES_YAML = `
version: 1
roles:
  operator:
    owner: nic
    may_address: [pmo, fleet-ops, platform-health, life]
    addressable_by: [pmo, fleet-ops, platform-health]
  pmo:
    owner: project-manager
    may_address: [fleet-ops, platform-health, operator]
    addressable_by: [fleet-ops, platform-health, operator]
  fleet-ops:
    owner: fleet-controller
    may_address: [pmo, platform-health]
    addressable_by: [pmo, platform-health, operator]
  platform-health:
    owner: platform-ops
    may_address: [pmo, fleet-ops, operator, platform-health]
    addressable_by: [pmo, fleet-ops, operator, platform-health]
  life:
    owner: harbor
    addressable_by: [operator]
principals:
  - { agent_id: nic, runtime: claude_code, persistence_class: persistent, roles: [operator] }
  - { agent_id: project-manager, runtime: nexus_agent, persistence_class: persistent, roles: [pmo] }
  - { agent_id: fleet-controller, runtime: claude_code, persistence_class: persistent, roles: [fleet-ops] }
  - { agent_id: fleet-runner-2, runtime: claude_code, persistence_class: persistent, roles: [fleet-ops] }
  - { agent_id: platform-ops, runtime: nexus_agent, persistence_class: persistent, roles: [platform-health] }
  - { agent_id: dual-holder, runtime: codex, persistence_class: persistent, roles: [pmo, platform-health] }
  - { agent_id: harbor, runtime: nexus_agent, persistence_class: persistent, roles: [] }
`;

const AGENTS = ['nic', 'project-manager', 'fleet-controller', 'fleet-runner-2', 'platform-ops', 'dual-holder', 'harbor'] as const;
type AgentName = (typeof AGENTS)[number];

describe.skipIf(!hasDb)('Muster stream and conditions API (OB-60178)', () => {
  let h: Harness;
  const p = {} as Record<AgentName, TestPrincipal>;
  let seq = 0;

  const post = (from: TestPrincipal, body: Record<string, unknown>) =>
    send(h.baseUrl, {
      method: 'POST',
      path: '/v1/messages',
      body: { type: 'status', body: 'stream test', idempotency_key: `stream-test-${++seq}`, ...body },
      auth: tokenAuth(from),
    });
  const read = (who: TestPrincipal, query = '') => send(h.baseUrl, { method: 'GET', path: `/v1/messages${query}`, auth: tokenAuth(who) });
  const darken = (...agents: AgentName[]) =>
    h.adminPool.query(`UPDATE agent_bus.registry_entries SET last_seen_at = now() - interval '3 hours' WHERE agent_id = ANY ($1::text[])`, [agents]);
  const allDeliveries = async (messageId: string) =>
    (await h.adminPool.query<{ recipient_agent_id: string; route_id: string; adapter: string; state: string }>(
      `SELECT recipient_agent_id, route_id::text, adapter, state FROM agent_bus.deliveries WHERE message_id = $1 ORDER BY recipient_agent_id, route_id`,
      [messageId],
    )).rows;
  // Route-resolution assertions ignore the binding extra-push (discord:agents); dedicated tests use allDeliveries.
  const deliveries = async (messageId: string) =>
    (await allDeliveries(messageId)).filter((d) => d.recipient_agent_id !== 'discord:agents');

  beforeAll(async () => {
    await resetDatabase();
    h = await startHarness({ rolesYaml: STREAM_ROLES_YAML });
    for (const agent of AGENTS) p[agent] = await enrollAndRegisterPersistent(h, agent);
  });

  beforeEach(async () => {
    h.ctx.limits = { ...GENEROUS_LIMITS };
    // A test that drains a budget must not leave the next test's bucket empty.
    h.ctx.limiter = new RateLimiter();
    await h.adminPool.query(`TRUNCATE agent_bus.role_mailbox, agent_bus.delivery_outbox, agent_bus.deliveries, agent_bus.message_routes,
      agent_bus.message_envelopes, agent_bus.conditions, agent_bus.wake_queue, agent_bus.messages RESTART IDENTITY CASCADE`);
    await h.adminPool.query(`UPDATE agent_bus.registry_entries SET last_seen_at = now()`);
  });

  afterAll(async () => {
    await h?.close();
  });

  it('delivers to every live holder of a role, with the message, envelope, and wake row written (step 1)', async () => {
    const res = await post(p['project-manager'], { to_roles: ['fleet-ops'], work_ref: 'OB-60178' });
    expect(res.status, JSON.stringify(res.json)).toBe(201);
    expect(res.json.routes).toEqual([
      expect.objectContaining({ target_kind: 'role', target: 'fleet-ops', resolution: 'holders', recipients: ['fleet-controller', 'fleet-runner-2'] }),
    ]);
    expect((await deliveries(res.json.message_id)).map((d) => [d.recipient_agent_id, d.adapter, d.state])).toEqual([
      ['fleet-controller', 'api', 'pending'],
      ['fleet-runner-2', 'api', 'pending'],
    ]);
    const { rows } = await h.adminPool.query(
      `SELECT m.author, m.msg_type, e.author_agent_id, e.work_ref, e.spec_version, (SELECT count(*)::int FROM agent_bus.wake_queue w WHERE w.message_id = m.id) AS wakes
         FROM agent_bus.messages m JOIN agent_bus.message_envelopes e ON e.message_id = m.id WHERE m.id = $1`,
      [res.json.message_id],
    );
    expect(rows[0]).toMatchObject({ author: 'project-manager', msg_type: 'status', author_agent_id: 'project-manager', work_ref: 'OB-60178', spec_version: 'muster-stream/1', wakes: 1 });
  });

  it('falls back to the live owner and records a system flag when no holder is live (step 2)', async () => {
    const res = await post(p.nic, { to_roles: ['life'] });
    expect(res.status, JSON.stringify(res.json)).toBe(201);
    expect(res.json.routes[0]).toMatchObject({ resolution: 'owner', recipients: ['harbor'] });
    expect(await deliveries(res.json.message_id)).toEqual([expect.objectContaining({ recipient_agent_id: 'harbor', adapter: 'agent_inbox' })]);
    const { rows: outbox } = await h.adminPool.query(`SELECT adapter FROM agent_bus.delivery_outbox ORDER BY adapter, delivery_id`);
    expect(outbox.map((o) => o.adapter)).toEqual(['agent_inbox', 'agent_inbox', 'discord']);
    const { rows: flags } = await h.adminPool.query(
      `SELECT m.author, m.msg_type, m.in_reply_to::text AS in_reply_to, d.recipient_agent_id
         FROM agent_bus.messages m JOIN agent_bus.deliveries d ON d.message_id = m.id WHERE m.author = 'muster'`,
    );
    expect(flags).toEqual([{ author: 'muster', msg_type: 'flag', in_reply_to: res.json.message_id, recipient_agent_id: 'harbor' }]);
  });

  it('creates one Discord extra-push per client message and none for system flags (OB-60291)', async () => {
    const key = `stream-test-extra-${++seq}`;
    const res = await post(p.nic, { to_roles: ['life'], idempotency_key: key });
    expect(res.status, JSON.stringify(res.json)).toBe(201);
    expect(res.json.routes.map((r: { target: string }) => r.target)).toEqual(['life']);
    const extras = (await allDeliveries(res.json.message_id)).filter((d) => d.recipient_agent_id === 'discord:agents');
    expect(extras).toEqual([
      expect.objectContaining({ recipient_agent_id: 'discord:agents', adapter: 'discord', state: 'pending' }),
    ]);
    const { rows: clientOutbox } = await h.adminPool.query<{ adapter: string; recipient_agent_id: string }>(
      `SELECT o.adapter, d.recipient_agent_id
         FROM agent_bus.delivery_outbox o JOIN agent_bus.deliveries d ON d.delivery_id = o.delivery_id
        WHERE d.message_id = $1 ORDER BY o.adapter`,
      [res.json.message_id],
    );
    expect(clientOutbox).toEqual([
      { adapter: 'agent_inbox', recipient_agent_id: 'harbor' },
      { adapter: 'discord', recipient_agent_id: 'discord:agents' },
    ]);
    const { rows: flags } = await h.adminPool.query<{ id: string }>(
      `SELECT m.id::text AS id FROM agent_bus.messages m WHERE m.author = 'muster'`,
    );
    expect(flags).toHaveLength(1);
    expect((await allDeliveries(flags[0]!.id)).filter((d) => d.recipient_agent_id === 'discord:agents')).toEqual([]);
    const replay = await post(p.nic, { to_roles: ['life'], idempotency_key: key });
    expect(replay.status).toBe(200);
    expect(replay.json.routes.map((r: { target: string }) => r.target)).toEqual(['life']);
  });

  it('still commits when the client already addressed the extra-push agent (OB-60291)', async () => {
    const res = await post(p.nic, { to_agents: ['discord:agents'] });
    expect(res.status, JSON.stringify(res.json)).toBe(201);
    expect(res.json.routes.map((r: { target: string }) => r.target)).toEqual(['discord:agents']);
    const rows = await allDeliveries(res.json.message_id);
    expect(rows.filter((d) => d.adapter === 'discord')).toEqual([
      expect.objectContaining({ recipient_agent_id: 'discord:agents', adapter: 'discord', state: 'pending' }),
    ]);
  });

  it('holds messages in the role mailbox when holders and owner are dark, then the next live holder inherits in order (steps 3-4)', async () => {
    await darken('fleet-controller', 'fleet-runner-2');
    const first = await post(p['project-manager'], { to_roles: ['fleet-ops'], body: 'first' });
    const second = await post(p['project-manager'], { to_roles: ['fleet-ops'], body: 'second' });
    for (const res of [first, second]) {
      expect(res.status, JSON.stringify(res.json)).toBe(201);
      expect(res.json.routes[0]).toMatchObject({ resolution: 'mailbox', recipients: [] });
      expect(await deliveries(res.json.message_id)).toEqual([]);
    }
    const { rows: waiting } = await h.adminPool.query(`SELECT target_role, alarm_last_fired_at, inherited_at FROM agent_bus.role_mailbox ORDER BY mailbox_id`);
    expect(waiting).toEqual([
      { target_role: 'fleet-ops', alarm_last_fired_at: null, inherited_at: null },
      { target_role: 'fleet-ops', alarm_last_fired_at: null, inherited_at: null },
    ]);

    expect((await putPresence(h, p['fleet-runner-2'])).status).toBe(200);
    const { rows: inherited } = await h.adminPool.query(`SELECT inherited_by_agent_id FROM agent_bus.role_mailbox ORDER BY mailbox_id`);
    expect(inherited.map((r) => r.inherited_by_agent_id)).toEqual(['fleet-runner-2', 'fleet-runner-2']);
    const inbox = await read(p['fleet-runner-2']);
    expect(inbox.status).toBe(200);
    expect(inbox.json.messages.map((m: { body: string; state: string }) => [m.body, m.state])).toEqual([
      ['first', 'delivered'],
      ['second', 'delivered'],
    ]);
  });

  it('gives an agent holding two addressed roles two routes and two independent deliveries', async () => {
    const res = await post(p.nic, { to_roles: ['pmo', 'platform-health'] });
    expect(res.status, JSON.stringify(res.json)).toBe(201);
    expect(res.json.routes).toHaveLength(2);
    const dual = (await deliveries(res.json.message_id)).filter((d) => d.recipient_agent_id === 'dual-holder');
    expect(dual).toHaveLength(2);
    expect(new Set(dual.map((d) => d.route_id)).size).toBe(2);
  });

  it('enforces addressability in both directions', async () => {
    const res = await post(p['platform-ops'], { to_roles: ['life'] });
    expect(res.status).toBe(403);
    expect(res.json.error).toBe('not_addressable');
    const unknown = await post(p.nic, { to_roles: ['finance'] });
    expect(unknown.json.error).toBe('unknown_role');
  });

  it('rejects reserved and unknown types and every server-set field', async () => {
    expect((await post(p.nic, { to_roles: ['pmo'], type: 'dark' })).json.error).toBe('reserved_type');
    expect((await post(p.nic, { to_roles: ['pmo'], type: 'gossip' })).json.error).toBe('unknown_type');
    expect((await post(p.nic, { to_roles: ['pmo'], author: 'project-manager' })).json.error).toBe('unsupported_field');
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages`);
    expect(rows[0].n).toBe(0);
  });

  it('stores a typed alert_class on an authorized critical flag and never reads body JSON', async () => {
    const stored = await post(p['platform-ops'], {
      type: 'flag',
      to_roles: ['pmo'],
      alert_class: 'critical',
      body: JSON.stringify({ severity: 'low', body: 'platform incident' }),
    });
    expect(stored.status, JSON.stringify(stored.json)).toBe(201);
    const { rows } = await h.adminPool.query(
      `SELECT e.alert_class, m.body FROM agent_bus.message_envelopes e JOIN agent_bus.messages m ON m.id = e.message_id WHERE m.id = $1`,
      [stored.json.message_id],
    );
    expect(rows[0]).toMatchObject({ alert_class: 'critical', body: JSON.stringify({ severity: 'low', body: 'platform incident' }) });

    const bodyOnly = await post(p['platform-ops'], {
      type: 'flag',
      to_roles: ['pmo'],
      body: JSON.stringify({ severity: 'critical', body: 'not a classification' }),
    });
    expect(bodyOnly.status, JSON.stringify(bodyOnly.json)).toBe(201);
    const { rows: bodyRows } = await h.adminPool.query(
      `SELECT alert_class FROM agent_bus.message_envelopes WHERE message_id = $1`,
      [bodyOnly.json.message_id],
    );
    expect(bodyRows[0].alert_class).toBeNull();
  });

  it('rejects alert_class from a caller who does not hold an alert role', async () => {
    const res = await post(p['project-manager'], { type: 'flag', to_roles: ['fleet-ops'], alert_class: 'critical' });
    expect(res.status).toBe(403);
    expect(res.json.error).toBe('alert_class_not_permitted');
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages`);
    expect(rows[0].n).toBe(0);
  });

  it('returns the original message for an idempotent replay and writes it once', async () => {
    const body = { to_roles: ['pmo'], idempotency_key: 'replay-key-0001' };
    const first = await post(p.nic, body);
    const replay = await post(p.nic, body);
    expect(first.status).toBe(201);
    expect(replay.status).toBe(200);
    expect(replay.json).toMatchObject({ message_id: first.json.message_id, idempotent_replay: true });
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages`);
    expect(rows[0].n).toBe(1);
  });

  it('marks pull deliveries delivered on read, and only the recipient can ack', async () => {
    const res = await post(p['project-manager'], { to_roles: ['fleet-ops'] });
    const inbox = await read(p['fleet-controller'], '?since=0&limit=10');
    expect(inbox.status).toBe(200);
    const mine = inbox.json.messages[0];
    expect(mine).toMatchObject({ message_id: res.json.message_id, state: 'delivered', target: 'fleet-ops' });

    const ack = (who: TestPrincipal) => send(h.baseUrl, { method: 'POST', path: `/v1/deliveries/${mine.delivery_id}/ack`, body: {}, auth: tokenAuth(who) });
    expect((await ack(p['fleet-runner-2'])).status).toBe(404);
    expect((await ack(p['fleet-controller'])).json).toEqual({ delivery_id: mine.delivery_id, state: 'acked' });
    expect((await ack(p['fleet-controller'])).status).toBe(200);
    expect((await read(p['fleet-controller'], `?since=${res.json.message_id}`)).json.messages).toEqual([]);
  });

  it('rejects addressing a dark named agent unless the sender holds operator or cos', async () => {
    await darken('fleet-runner-2');
    const refused = await post(p['project-manager'], { to_agents: ['fleet-runner-2'] });
    expect(refused.status).toBe(403);
    expect(refused.json.error).toBe('recipient_dark');
    const operator = await post(p.nic, { to_agents: ['fleet-runner-2'] });
    expect(operator.status, JSON.stringify(operator.json)).toBe(201);
    expect(operator.json.routes[0]).toMatchObject({ target_kind: 'agent', resolution: 'agent', recipients: ['fleet-runner-2'] });
  });

  it('refuses new mailbox writes at capacity with a controlled 503 and writes nothing', async () => {
    h.ctx.limits = { ...GENEROUS_LIMITS, mailboxCapacityPerRole: 1 };
    await darken('fleet-controller', 'fleet-runner-2');
    expect((await post(p['project-manager'], { to_roles: ['fleet-ops'] })).status).toBe(201);
    const overloaded = await post(p['project-manager'], { to_roles: ['fleet-ops'] });
    expect(overloaded.status).toBe(503);
    expect(overloaded.json.error).toBe('overloaded');
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages`);
    expect(rows[0].n).toBe(1);
  });

  it('delivers to the author when it is the only live holder of the role it addresses, never to the mailbox (AR ZA-01)', async () => {
    await darken('dual-holder');
    const res = await post(p['platform-ops'], { to_roles: ['platform-health'] });
    expect(res.status, JSON.stringify(res.json)).toBe(201);
    expect(res.json.routes[0]).toMatchObject({ resolution: 'holders', recipients: ['platform-ops'] });
    expect(await deliveries(res.json.message_id)).toEqual([expect.objectContaining({ recipient_agent_id: 'platform-ops' })]);
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.role_mailbox`);
    expect(rows[0].n).toBe(0);
  });

  it('re-reads presence after taking the role lock, so a holder that became live meanwhile receives the message (AR ZA-02)', async () => {
    await darken('fleet-controller', 'fleet-runner-2');
    const holder = await h.adminPool.connect();
    try {
      await holder.query(`SELECT pg_advisory_lock(hashtextextended('muster:mailbox:fleet-ops', 0))`);
      const pending = post(p['project-manager'], { to_roles: ['fleet-ops'] });
      await new Promise((resolve) => setTimeout(resolve, 300));
      // A presence write lands while the post waits on the role lock.
      await h.adminPool.query(`UPDATE agent_bus.registry_entries SET last_seen_at = now() WHERE agent_id = 'fleet-runner-2'`);
      await holder.query(`SELECT pg_advisory_unlock(hashtextextended('muster:mailbox:fleet-ops', 0))`);
      const res = await pending;
      expect(res.status, JSON.stringify(res.json)).toBe(201);
      expect(res.json.routes[0]).toMatchObject({ resolution: 'holders', recipients: ['fleet-runner-2'] });
    } finally {
      holder.release();
    }
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.role_mailbox`);
    expect(rows[0].n).toBe(0);
  });

  it('counts a post\'s own pushed deliveries against outbox capacity under concurrency (AR ZA-03)', async () => {
    // A message to life reaches the owner harbor (inbox), the owner-fallback flag (inbox), and the Discord
    // extra-push: 2 agent_inbox rows + 1 discord row per post. Capacity is now per-adapter (OB-60413), but
    // the outcome here is unchanged from the global-cap era: the second post's 2 agent_inbox inserts alone
    // (2+2=4) already exceed capacity 3 for that adapter, so its whole transaction rolls back including its
    // discord row — same one-201/one-503, same 3 total rows, now via the agent_inbox partition specifically.
    h.ctx.limits = { ...GENEROUS_LIMITS, outboxCapacity: 3 };
    const results = await Promise.all([post(p.nic, { to_roles: ['life'] }), post(p.nic, { to_roles: ['life'] })]);
    expect(results.map((r) => r.status).sort()).toEqual([201, 503]);
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.delivery_outbox`);
    expect(rows[0].n).toBe(3);
  });

  it('spends no write budget on refused writes, so 503s cannot turn into a 429 denial of service (AR ZA-04)', async () => {
    h.ctx.limits = { ...GENEROUS_LIMITS, messagesPerRolePerMinute: 2, mailboxCapacityPerRole: 1 };
    await darken('fleet-controller', 'fleet-runner-2');
    expect((await post(p['project-manager'], { to_roles: ['fleet-ops'] })).status).toBe(201);
    for (let i = 0; i < 6; i += 1) {
      expect((await post(p['project-manager'], { to_roles: ['fleet-ops'] })).status).toBe(503);
    }
    // The waiting message is inherited, the mailbox drains, and a later valid post still has budget.
    expect((await putPresence(h, p['fleet-runner-2'])).status).toBe(200);
    const later = await post(p['project-manager'], { to_roles: ['fleet-ops'] });
    expect(later.status, JSON.stringify(later.json)).toBe(201);
  });

  it('admits a concurrent burst atomically: a one-token global budget yields one 201 and 429s (AR ZB-01)', async () => {
    // perMinute 0.5 gives a burst of exactly one token, and the refill over the test is far below one more.
    h.ctx.limits = { ...GENEROUS_LIMITS, messagesGlobalPerMinute: 0.5 };
    const results = await Promise.all(Array.from({ length: 8 }, () => post(p['project-manager'], { to_roles: ['fleet-ops'] })));
    expect(results.map((r) => r.status).sort()).toEqual([201, 429, 429, 429, 429, 429, 429, 429]);
    const { rows } = await h.adminPool.query(`SELECT count(*)::int AS n FROM agent_bus.messages`);
    expect(rows[0].n).toBe(1);
  });

  it('refunds a reservation when the write does not commit, so the token is still there for the next post (AR ZB-01)', async () => {
    h.ctx.limits = { ...GENEROUS_LIMITS, messagesGlobalPerMinute: 0.5, outboxCapacity: 0 };
    // life resolves to the owner harbor (inbox push), which an outbox capacity of 0 refuses with 503 —
    // unchanged by the per-adapter partition (OB-60413), since 0 capacity admits nothing on any adapter.
    expect((await post(p.nic, { to_roles: ['life'] })).status).toBe(503);
    h.ctx.limits = { ...h.ctx.limits, outboxCapacity: 10 };
    const ok = await post(p.nic, { to_roles: ['life'] });
    expect(ok.status, JSON.stringify(ok.json)).toBe(201);
  });

  it('stops mailbox inheritance at outbox capacity, scoped to its own adapter (OB-60413, AR ZB-02)', async () => {
    await darken('harbor');
    for (const body of ['first', 'second']) {
      const res = await post(p.nic, { to_roles: ['life'], body });
      expect(res.json.routes[0]).toMatchObject({ resolution: 'mailbox' });
    }
    // Two mailbox posts each create a Discord extra-push (adapter=discord) — irrelevant to harbor's own
    // adapter (agent_inbox) now that the outbox bound is partitioned per adapter, not summed globally.
    // Fill the agent_inbox adapter's own backlog directly: project-manager HOLDS role pmo (a live
    // agent_inbox recipient), but does not itself MAY_ADDRESS pmo, so posting as project-manager 403s —
    // post as nic (operator; may_address includes pmo) instead. Routing to holders is author-independent,
    // so this still delivers to project-manager, giving harbor's inherit room a real constraint from ITS
    // own adapter, not Discord's.
    expect((await post(p.nic, { to_roles: ['pmo'] })).status).toBe(201);
    expect((await post(p.nic, { to_roles: ['pmo'] })).status).toBe(201);
    const counts = async () =>
      (await h.adminPool.query(
        `SELECT (SELECT count(*)::int FROM agent_bus.delivery_outbox WHERE adapter = 'agent_inbox') AS inbox_outbox,
                (SELECT count(*)::int FROM agent_bus.role_mailbox WHERE target_role = 'life' AND inherited_at IS NULL) AS waiting`,
      )).rows[0];
    expect(await counts()).toEqual({ inbox_outbox: 2, waiting: 2 });

    // Room for the agent_inbox adapter = capacity 3 - 2 already there = 1; one of the two waiting life
    // messages inherits, the Discord backlog never enters the calculation.
    h.ctx.limits = { ...GENEROUS_LIMITS, outboxCapacity: 3 };
    expect((await putPresence(h, p.harbor)).status).toBe(200);
    expect(await counts()).toEqual({ inbox_outbox: 3, waiting: 1 });

    h.ctx.limits = { ...GENEROUS_LIMITS, outboxCapacity: 10 };
    expect((await putPresence(h, p.harbor)).status).toBe(200);
    expect(await counts()).toEqual({ inbox_outbox: 4, waiting: 0 });
  });

  it('stops mailbox inheritance at the per-adapter delivery budget and leaves the rest waiting in order (AR ZC-01)', async () => {
    await darken('harbor');
    for (const body of ['first', 'second', 'third']) {
      const res = await post(p.nic, { to_roles: ['life'], body });
      expect(res.json.routes[0]).toMatchObject({ resolution: 'mailbox' });
    }
    const counts = async () =>
      (await h.adminPool.query(
        `SELECT (SELECT count(*)::int FROM agent_bus.delivery_outbox) AS outbox,
                (SELECT count(*)::int FROM agent_bus.role_mailbox WHERE inherited_at IS NULL) AS waiting,
                (SELECT m.body FROM agent_bus.role_mailbox mb JOIN agent_bus.messages m ON m.id = mb.message_id
                  WHERE mb.inherited_at IS NOT NULL ORDER BY mb.mailbox_id LIMIT 1) AS first_inherited`,
      )).rows[0];

    // Three mailbox posts already created three Discord extra-pushes. perMinute 0.5 gives agent_inbox a burst of one.
    h.ctx.limits = { ...GENEROUS_LIMITS, deliveriesPerAdapterPerMinute: 0.5 };
    expect((await putPresence(h, p.harbor)).status).toBe(200);
    expect(await counts()).toEqual({ outbox: 4, waiting: 2, first_inherited: 'first' });

    h.ctx.limits = { ...GENEROUS_LIMITS };
    h.ctx.limiter = new RateLimiter();
    expect((await putPresence(h, p.harbor)).status).toBe(200);
    expect(await counts()).toMatchObject({ outbox: 6, waiting: 0 });
  });

  it('applies the per-role write budget', async () => {
    h.ctx.limits = { ...GENEROUS_LIMITS, messagesPerRolePerMinute: 1 };
    const statuses: number[] = [];
    for (let i = 0; i < 4; i += 1) statuses.push((await post(p.nic, { to_roles: ['pmo'] })).status);
    expect(statuses).toContain(429);
  });

  describe('conditions', () => {
    const declare = (who: TestPrincipal, body: Record<string, unknown>) =>
      send(h.baseUrl, { method: 'POST', path: '/v1/conditions', body, auth: tokenAuth(who) });
    const base = { kind: 'experiment', scope: { host: 'crucible', service: 'llama-swap' }, effect: { 'platform-health': 'annotate' } };

    it('rejects slice 2 effects with a clear error and accepts annotate', async () => {
      for (const effect of ['defer', 'suppress', { route_to: 'pmo' }]) {
        const res = await declare(p.nic, { ...base, effect: { 'platform-health': effect }, duration_seconds: 600 });
        expect(res.status).toBe(400);
        expect(res.json.error).toBe('effect_not_supported_in_slice_1');
      }
      const ok = await declare(p.nic, { ...base, duration_seconds: 600, work_ref: 'OB-60178' });
      expect(ok.status, JSON.stringify(ok.json)).toBe(201);
      expect(ok.json).toMatchObject({ kind: 'experiment', owner_agent_id: 'nic', effect: { 'platform-health': 'annotate' } });
      const list = await send(h.baseUrl, { method: 'GET', path: '/v1/conditions', auth: tokenAuth(p['platform-ops']) });
      expect(list.json.conditions.map((c: { condition_id: string }) => c.condition_id)).toEqual([ok.json.condition_id]);
    });

    it('requires authority over every role the effect names', async () => {
      const res = await declare(p['platform-ops'], { ...base, effect: { pmo: 'annotate' }, duration_seconds: 600 });
      expect(res.status).toBe(403);
      expect(res.json.error).toBe('no_authority_over_scope');
      expect((await declare(p['platform-ops'], { ...base, duration_seconds: 600 })).status).toBe(201);
    });

    it('caps the window per declarer class and the renewal chain at 12 hours', async () => {
      expect((await declare(p['platform-ops'], { ...base, duration_seconds: 13 * 3600 })).json.error).toBe('invalid_duration');
      const full = await declare(p['platform-ops'], { ...base, duration_seconds: 12 * 3600 });
      expect(full.status).toBe(201);
      const renewal = await declare(p['platform-ops'], { ...base, duration_seconds: 60, renews_condition_id: full.json.condition_id });
      expect(renewal.status).toBe(400);
      expect(renewal.json.error).toBe('renewal_cap_exceeded');

      const short = await declare(p['platform-ops'], { ...base, duration_seconds: 600 });
      const renewed = await declare(p['platform-ops'], { ...base, duration_seconds: 600, renews_condition_id: short.json.condition_id });
      expect(renewed.status, JSON.stringify(renewed.json)).toBe(201);
      const twice = await declare(p['platform-ops'], { ...base, duration_seconds: 600, renews_condition_id: short.json.condition_id });
      expect(twice.json.error).toBe('already_renewed');
    });

    it('lets only the owner or an operator clear, and a clear is final', async () => {
      const made = await declare(p['platform-ops'], { ...base, duration_seconds: 600 });
      const clear = (who: TestPrincipal) =>
        send(h.baseUrl, { method: 'POST', path: `/v1/conditions/${made.json.condition_id}/clear`, body: {}, auth: tokenAuth(who) });
      expect((await clear(p['project-manager'])).json.error).toBe('not_condition_owner');
      const cleared = await clear(p.nic);
      expect(cleared.status).toBe(200);
      expect(cleared.json).toMatchObject({ cleared_by: 'nic' });
      expect((await clear(p['platform-ops'])).json.error).toBe('condition_cleared');
    });
  });

  it('keeps the database role inside the widened allowlist (migration 1892 verifier)', async () => {
    const { rows } = await h.adminPool.query<{ v: string[] }>(`SELECT agent_bus.muster_api_privilege_violations('muster_api') AS v`);
    expect(rows[0]!.v).toEqual([]);
    const { rows: priv } = await h.adminPool.query(
      `SELECT has_table_privilege('muster_api', 'agent_bus.messages', 'UPDATE') AS msg_update,
              has_table_privilege('muster_api', 'agent_bus.messages', 'DELETE') AS msg_delete,
              has_any_column_privilege('muster_api', 'agent_bus.wake_queue', 'SELECT') AS wake_select`,
    );
    expect(priv[0]).toEqual({ msg_update: false, msg_delete: false, wake_select: false });
  });

  it('emits nexus.muster.* spans on message post, with the write span parented to the post span (OB-60178)', async () => {
    const { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } = await import(
      '@opentelemetry/sdk-trace-base'
    );
    const { trace } = await import('@opentelemetry/api');
    const exporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider();
    provider.addSpanProcessor(new SimpleSpanProcessor(exporter));
    trace.setGlobalTracerProvider(provider);
    try {
      const res = await post(p['project-manager'], { to_roles: ['fleet-ops'] });
      expect(res.status, JSON.stringify(res.json)).toBe(201);
      const spans = exporter.getFinishedSpans();
      const postSpan = spans.find((s) => s.name === 'nexus.muster.stream.post');
      const writeSpan = spans.find((s) => s.name === 'nexus.muster.stream.write');
      expect(postSpan).toBeDefined();
      expect(writeSpan).toBeDefined();
      // The write span is an explicit child of the post span, on the same trace.
      expect(writeSpan!.parentSpanId).toBe(postSpan!.spanContext().spanId);
      expect(writeSpan!.spanContext().traceId).toBe(postSpan!.spanContext().traceId);
      expect(postSpan!.attributes).toMatchObject({
        'muster.http.route': '/v1/messages',
        'muster.http.method': 'POST',
        'muster.message.type': 'status',
        'muster.result': 'created',
      });
      expect(writeSpan!.attributes).toMatchObject({
        'muster.message.type': 'status',
        'muster.author': 'project-manager',
        'muster.route.count': 1,
        'muster.recipient.count': 2,
        'muster.result': 'created',
      });
      // Span names are static literals: no bodies, ids, or other high-cardinality data in names.
      for (const s of spans) expect(s.name).toMatch(/^nexus\.muster\.[a-z.]+$/);

      // An idempotent replay emits only the post span, marked as a replay.
      const key = 'span-test-replay-1';
      const writesBefore = exporter.getFinishedSpans().filter((s) => s.name === 'nexus.muster.stream.write').length;
      expect((await post(p['project-manager'], { to_roles: ['fleet-ops'], idempotency_key: key })).status).toBe(201);
      expect((await post(p['project-manager'], { to_roles: ['fleet-ops'], idempotency_key: key })).status).toBe(200);
      const posts = exporter.getFinishedSpans().filter((s) => s.name === 'nexus.muster.stream.post');
      expect(posts.at(-1)!.attributes['muster.result']).toBe('replay');
      const writesAfter = exporter.getFinishedSpans().filter((s) => s.name === 'nexus.muster.stream.write').length;
      expect(writesAfter).toBe(writesBefore + 1); // only the creating post writes
    } finally {
      trace.disable();
      await provider.shutdown();
    }
  });
});
