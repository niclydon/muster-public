# Muster

Cross-runtime agent coordination: a registry, conditions, and a typed stream, served by one API that enforces identity, authority, and addressability. Design and review history live in the nexus monorepo at `docs/projects/2026-09-14-muster-design.md` and `docs/projects/2026-09-14-ob60176-identity-adversarial-review*.md`.

> **Public edition.** This repository is the public edition of the Muster
> core, snapshotted from the private working repository on October 18, 2026
> (private HEAD of September 22, 2026; the design has not changed since).
> It is published as a single-commit snapshot, not a mirror: the private
> repository keeps its history. See [SNAPSHOT.md](SNAPSHOT.md) for
> provenance, the scrub standard, and what was generalized.

This repository holds the core only. Deployment knowledge (the roles file and the binding that knows what a work hold is) lives with the deployment; for Nexus that is the `muster/` directory of the nexus monorepo. `npm run check:boundary` fails the build if core imports or references Nexus work-management, Discord, or agent_inbox code (see the script header for exactly what it parses).

## Status

Slice 1. OB-60176 shipped the service core, identity, and the registry skeleton. OB-60178 adds the stream and conditions. Endpoints:

| Method | Path | Auth |
|---|---|---|
| GET | `/health` | none (reports `kill_switch` / `mode`) |
| GET | `/metrics` | none (Prometheus text) |
| POST | `/v1/register` | seat key (persistent) or launcher token (ephemeral) |
| POST | `/v1/launch-grants` | launcher token |
| PUT | `/v1/presence` | token |
| GET | `/v1/registry` | token |
| POST | `/v1/messages` | token |
| GET | `/v1/messages?since=&limit=` | token |
| POST | `/v1/deliveries/{delivery_id}/ack` | token (recipient only) |
| GET | `/v1/conditions?include=active\|all` | token |
| POST | `/v1/conditions` | token |
| POST | `/v1/conditions/{condition_id}/clear` | token (owner, cos, or operator) |

Operator-interactive registration, the delivery reconciler, and the push adapters ship in later OBs.

## Stream

`POST /v1/messages` takes these fields:
- `type`: one of `status`, `intent`, `done`, `ask`, `flag`. `dark`, `delegate`, and `decide` are reserved; any other type is rejected.
- `to_roles` and/or `to_agents`: at most 16 targets in total.
- `body`: up to 16,000 characters, stored as data and never interpreted.
- `idempotency_key`: unique per author. A replay returns the original message with `200`.
- optional `task`, `work_ref`, `in_reply_to`.

The server sets author, id, and timestamp, and rejects any other field. The message lands in `agent_bus.messages` with a companion envelope. Each target becomes an append-only route, and each route's deliveries are the obligation ledger.

A message is delivered only if both sides allow it: the sender's roles list the target role in `may_address`, and the target role's `addressable_by` includes one of the sender's roles (design 6, rule 3).

Role resolution follows the normative slice 1 order:
1. every live holder of the role;
2. otherwise the live owner, plus a system-authored `flag` (author `muster`) recording the fallback;
3. otherwise the role's unassigned mailbox. The deployment raises a platform alarm from it; for Nexus, that is log-monitor.

When a holder, or the owner while no holder is live, next writes presence or registers, it inherits the mailbox in enqueue order.

A `to_agents` target that is dark or not registered is rejected unless the sender holds `cos` or `operator`.

The binding names the push adapter for a recipient runtime. Recipients with no push adapter read through `GET /v1/messages`, which returns only messages delivered to the caller and marks those pull deliveries delivered. Recipients ack their deliveries with `POST /v1/deliveries/{id}/ack`.

## Conditions

`POST /v1/conditions` takes:
- `kind`: `experiment`, `maintenance`, `freeze`, `incident`, `blocker`, `operator_wip`, `budget_park`, or `quiet_hours`.
- `scope`: an object.
- `effect`: an object mapping role to effect.
- `duration_seconds`.
- optional `work_ref` and `renews_condition_id`.

Rules:
- Slice 1 accepts only `annotate` effects. `defer`, `suppress`, and `route_to` return `effect_not_supported_in_slice_1`.
- Windows are server-timed, capped per declarer class: 12 h persistent, 2 h ephemeral, 4 h operator-interactive.
- The declarer must hold or own every role the effect names, or hold `cos` or `operator`.
- Renewals form an immutable chain, capped at 12 h cumulative. The renewal must match the renewed condition's kind, scope, and effect, and each condition can be renewed only once.
- A clear is final.

## Identity

Every principal holds an Ed25519 key. Muster stores only public keys (`agent_bus.principal_keys`).

A token (`mst_...`) names one registered key, agent, and session. It is not a bearer secret: every request must be signed by the private key the token names, so a copied token is useless without that key. The database stores only `sha256(token)` as the jti.

Request signature. The client signs these lines joined by `\n` and sends the base64 signature:

```
muster-request-v1
<audience, the deployment's MUSTER_AUDIENCE>
<METHOD>
<path with query, exactly as sent>
<unix seconds, header Muster-Timestamp>
<nonce, header Muster-Nonce, 16-128 base64url chars>
<sha256 hex of the raw body>
<credential: the token, or key:<public key sha256> for seat registration>
```

Headers: `Authorization: Muster-PoP <token>` (or `Muster-Key <sha256>`), `Muster-Timestamp`, `Muster-Nonce`, `Muster-Signature`. The server rejects timestamps more than 60 s from server time, timestamps in or before the process start second (so a restart cannot reopen the replay window), and any nonce a credential already used.

On every token request the API checks, against live state: signature, revocation (`token_revocations` and the token row), token and key expiry, registry entry and tombstone, the launcher that brokered the token, roles-file enrollment, and for ephemeral runners that the binding still sees at least one live hold for that exact agent. Any database or binding failure fails closed with 503.

### Persistent seats

The operator generates a key (`muster-admin keygen`), stores the private key in secrets-vault, and enrolls the public key (`muster-admin enroll-persistent`). The seat registers with `POST /v1/register` `{ "persistence_class": "persistent", "agent_id": ... }`, signed with `Authorization: Muster-Key <sha256>`. Keys expire after 90 days by default; `--rotate` replaces a key and revokes the old key and its tokens. Enrollment also reinstates a revoked seat.

### Ephemeral runners (brokered)

1. Before spawning, the launcher records a launch grant for the exact agent_id: `POST /v1/launch-grants { "agent_id": ... }`. Only a persistent launcher listed in that agent's `launched_by` can do this, one grant exists per agent_id, and grants are append-only.
2. The runner generates its own key and claims its work.
3. The launcher calls `POST /v1/register` with its own token and signature:

```json
{
  "persistence_class": "ephemeral",
  "agent_id": "codex:furnace:projectworker-...",
  "claim_id": "<uuid>",
  "public_key": "<runner SPKI base64>",
  "nonce": "<single-use>",
  "key_proof": "<runner signature over muster-key-proof-v1\\naudience\\nagent_id\\nclaim_id\\nnonce\\npublic_key_sha256>"
}
```

Muster accepts it only if this launcher holds the agent's launch grant, the runner proved possession of the key, and the binding confirms the claim is active, held by exactly that agent_id, and was created after the grant. A first registration must happen, with a claim created, inside the grant's 30-minute claim window; later re-registrations by the same launcher (a restart, a new claim pack) may use any later claim. Every check is repeated inside the issuance transaction. Launchers never mint tokens. A launcher can necessarily act for runners it launched; it cannot act for another launcher's runners.

### Sessions and revocation

Each registration starts a new session and revokes every older token of that agent (and older non-persistent keys), so a superseded session's writes are rejected with `session_superseded`. Every issue, rotation, revocation, supersession, launch grant, and rejected brokered request writes `agent_bus.principal_audit_events`, which rejects UPDATE and DELETE.

`muster-admin revoke-token`, `revoke-key`, and `revoke-agent` revoke immediately. Revoking an agent tombstones it so it cannot register again until an operator re-enrolls it, and also revokes every runner it brokered; the API independently rejects any runner token whose launcher is tombstoned. `muster-admin revoke-all --confirm` is the break-glass command: it revokes every key and token.

### Onboarding a Nexus agent (persistent seat)

The Nexus agents (`project-manager`, `platform-ops`, `aria`, ...) run as worker cycles and have no
process of their own to speak Muster, so the `muster-presence` unit holds their seats: it registers each
configured seat with its key and heartbeats `PUT /v1/presence` every 5 minutes (persistent presence TTL
is 15 minutes), re-registering on `session_superseded`, token expiry, or after a freeze. The registry then
shows the seat `live` first-hand (`proxied_by` null), which is what role ownership and fallback read.

One command onboards a seat from Furnace, with no secret printed or asked for:

```bash
node /services/muster/scripts/muster-onboard-agent.mjs <agent_id> [--holder presence|worker|self] [--expires-days 90] [--no-restart]
```

It (1) checks the agent is a persistent principal in the reviewed roles file, (2) generates an Ed25519
key, (3) merges the private key into vault secret `muster/agent-keys` under the agent id, (4) enrolls the
public key through `POST /v1/principals/enroll` as `operator-console` with `rotate: true` (any earlier key
and its tokens are revoked), (5) adds `MUSTER_AGENT_KEY_<ID>={aws:secret:muster/agent-keys#<agent_id>}`
to `/services/muster/presence/.env.secrets` and `MUSTER_PRESENCE_AGENTS`, rematerializes
`/etc/homelab/secrets/muster-presence.env`, restarts `muster-presence`, and (6) waits for the registry to
show the seat live first-hand. Re-running it rotates the key. `--holder` names who keeps the session: `presence`
(default) is the muster-presence unit; `worker` puts the seat in `MUSTER_WORKER_SEATS` for the nexus-worker seat keeper
(the agent's own tool calls are then signed with its seat) and restarts nexus-worker; `self` stores the key only, for a seat
whose runtime registers itself (launchers, aria-grok, nova). One holder per seat: two holders supersede each other's sessions. If the agent is not in the roles file, it
stops at step 1 and says what to add (nexus `muster/roles.yaml` PR, deploy, `SIGHUP` muster-api). Off-boarding
is `muster_principal_revoke` (tombstone) or `muster-admin revoke-agent`, plus removing the seat from
`MUSTER_PRESENCE_AGENTS`.

### Limits

Every budget below returns 429 with `Retry-After`.

**Identity:** token buckets per agent (60 requests/min persistent, 20 ephemeral, burst 2x), per launcher for grants and registrations (30/min), per seat key for registration (10/min), and a global ingress cap. The replay cache has a per-credential quota, so one principal cannot exhaust it for others.

**Stream (OB-60178), set from the M-03 baseline:**
- **Baseline:** 7 days to 2026-09-14. Nexus agent inbox peaked at 476 rows/h (mean 42/h, p95 180/h); claims peaked at 65/h.
- **Soak target:** 10x the inbox peak, about 80 writes/min.
- **Write budgets:**
  - 120 message writes/min globally
  - 60/min per addressed role
  - 60/min shared by every runner one launcher brokered, so many exact ephemeral ids cannot sum past it
  - 600 deliveries/min per adapter
- **Capacity limits:** an unassigned mailbox holds at most 200 waiting messages per role, and the delivery outbox at most 5,000 unclaimed rows. At either limit, writes return a controlled `503 overloaded`, and nothing from the refused message is written. A post's own pushed deliveries count toward the outbox limit, and the count and inserts run under one outbox lock.
- **Charging:** stream budgets are checked before a write and charged only after it commits, so an idempotent replay or a refused write (429 or 503) spends nothing.

Concurrency: a post takes the outbox lock and then its addressed roles' locks in sorted order before it resolves presence; mailbox inheritance takes the same locks in the same order. A holder whose presence lands while a post is resolving either receives the message directly or inherits the mailbox row as soon as it commits.

## Database role

The API runs as `muster_api`, created out of band by the database superuser. It gets only what the API needs, and `agent_bus.muster_api_privilege_violations(role)` fails each granting migration on anything more.

**Migration 1889 grants:**
- column-scoped writes on the identity and registry tables
- inserts on launch grants and the audit trail
- six columns of `operator_backlog_claims`

**Migration 1892 adds (OB-60178):**
- INSERT and SELECT on the content columns of `agent_bus.messages`; never UPDATE, DELETE, or the server-set id
- INSERT on the two `agent_bus.wake_queue` columns the legacy wake trigger writes as the inserting role
- SELECT and INSERT on envelopes, routes, deliveries, the outbox, the role mailbox, and conditions
- column-scoped UPDATE for delivery state, mailbox inheritance, and condition clears

`muster_api` cannot enroll persistent keys (a trigger rejects them), clear a tombstone, or change a delivery's identity or a condition's scope or effect. `muster-admin` runs under the admin role.

## Binding contract

`MUSTER_BINDING_MODULE` points at an ES module whose default export implements `MusterBinding` (`packages/core/src/binding.ts`):

- `verifyHold(db, { claimId, agentId })` returns `{ ok: true, claimedAt, ttlSeconds }` (ttl is the time left on the hold) or `{ ok: false, reason }` with reason `claim_not_found`, `claim_not_active`, or `claim_agent_mismatch`.
- `hasLiveHold(db, { agentId })` returns whether the agent holds any active hold.
- `deliveryAdapterFor(runtime)` (optional) returns the push delivery adapter name for a recipient runtime, or null for pull delivery through the API. The Nexus binding maps `nexus_agent` to its inbox adapter and `discord` to the Discord adapter; the core knows no adapter names.
- `extraPushRecipients()` (optional) returns extra `{ agentId, runtime }` pushes inserted in the same `POST /v1/messages` transaction as a client-authored message (OB-60291, design 12). The Nexus binding returns the Discord `#agents` mirror. System-authored owner-fallback flags are not mirrored. The Discord adapter still fans `#alerts` only for high/critical flags from platform-health, platform-ops, or security.

## Configuration

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | Postgres as `muster_api`, with nexus migrations 1884, 1889, 1892, 1895, 1896, and 1897 |
| `MUSTER_ADMIN_DATABASE_URL` | Postgres as `muster_admin` (vault secret `muster/admin-database`). Required for the 1895 admin routes and `POST /v1/admin/kill-switch` (1897); if unset, those routes return 503 (`admin_unavailable`) and the rest of the API still starts. Operator prerequisite, as the schema owner (`postgres`), before applying 1895: `CREATE ROLE muster_admin LOGIN PASSWORD ...` and `GRANT USAGE ON SCHEMA agent_bus TO muster_admin`; the migrations' own `GRANT USAGE` is a no-op because they run as `ariaadmin`, which does not own the schema (the same out-of-band grant `muster_api` needed for 1889) |
| `MUSTER_AUDIENCE` | Deployment identity bound into signatures, e.g. `muster:furnace` |
| `MUSTER_HOST`, `MUSTER_PORT` | Listen address (Tailnet only) |
| `MUSTER_ROLES_FILE` | Reviewed roles file; `SIGHUP` reloads it |
| `MUSTER_BINDING_MODULE` | Deployment binding module |
| `LOG_LEVEL` | `minimal`, `normal`, `verbose`, `debug` |

`muster-presence` (unit `deploy/muster-presence.service`, env `/etc/homelab/secrets/muster-presence.env`
materialized from `/services/muster/presence/.env.secrets`):

| Variable | Meaning |
|---|---|
| `MUSTER_API_URL`, `MUSTER_AUDIENCE` | The deployment to register against |
| `MUSTER_PRESENCE_AGENTS` | Comma-separated persistent agent ids to keep live |
| `MUSTER_AGENT_KEY_<ID>` | Each seat's private key (base64 PKCS#8 DER or PEM) from vault secret `muster/agent-keys`; `<ID>` is the agent id upper-cased with non-alphanumerics as `_` |
| `MUSTER_PRESENCE_INTERVAL_SECONDS` | Heartbeat period, default 300 |

Operator `POST /v1/admin/kill-switch` `{enabled, reason}` writes the shared
`agent_bus.operational_controls` row (fail-closed). Actor is the authenticated
operator principal. `muster-admin kill-switch status` still reads the row.
The Nexus inbox adapter and delivery reconciler read the same row before claiming
work. Runbooks live in the nexus repo at `docs/runbooks/muster.md`.

## Development

```bash
npm ci
npm run check:boundary
npm run typecheck
MUSTER_TEST_DATABASE_URL=postgres://user@host:port/muster_test npm test
```

Integration tests rebuild the schema from verbatim copies of nexus migrations 1884, 1889, 1892, 1896, 1895, and 1897 in `packages/core/test/fixtures/` and run the API under the `muster_api` role. They drop and recreate `agent_bus` in the target database, and they log in as `muster_api` with the well-known password `muster_api` and as `muster_admin` with the well-known password `muster_admin`. Create those roles only in a disposable test cluster, never in a production cluster (it would replace the production credential). The suite refuses any database whose name is not `muster_test` or `*_test`. Set `MUSTER_NEXUS_BINDING_PATH` to a nexus checkout's `muster/nexus-binding.mjs` to also run the real binding SQL. CI runs the suite against a Postgres 16 service container.
