-- Migration number 1884 RESERVED via migration_registry
-- (nexus_lease_allocate, slug 'ob60175-muster-companion-schema', floor 1883).
-- Do not renumber.
--
-- OB-60175: Muster slice 1 companion schema in agent_bus
-- (docs/projects/2026-09-14-muster-design.md, sections 4, 20.1, 20.2).
-- Additive only: agent_bus.messages, high_water_marks, cos_memory, wake_queue,
-- and wake_deliveries are not altered, and no grant is issued to the *_bus
-- roles (slice 1 has no SQL fast-path writes).
--
-- Invariants enforced in the database, not only the API (adversarial review
-- docs/projects/2026-09-14-ob60175-*-review.md):
--   * route provenance has one source of truth (message_routes) (DS-01)
--   * deliveries are created pending and follow the legal transitions (DS-02)
--   * registration requests follow a single-use state machine (DS-03)
--   * slice 1 condition effects are annotate-only and conditions are immutable (DS-05)
--   * companion history is never cascade-deleted from agent_bus.messages (MS-02, DS-06)
--   * token, key, and request identities must agree; keys are immutable (DT-01)
--   * the principal audit trail rejects UPDATE and DELETE (DT-02)
-- Compare-and-set (`WHERE version = $n`) is the API data layer's job; the
-- triggers enforce that each accepted update advances version by exactly 1.

BEGIN;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
  IF NOT has_schema_privilege(current_user, 'agent_bus', 'CREATE') THEN
    RAISE EXCEPTION 'OB-60175: % lacks CREATE on schema agent_bus', current_user;
  END IF;
END;
$$;

-- Registry (design 4.1, 5) ------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_bus.registry_entries (
  agent_id           TEXT PRIMARY KEY CHECK (length(btrim(agent_id)) > 0),
  runtime            TEXT NOT NULL CHECK (length(btrim(runtime)) > 0),
  persistence_class  TEXT NOT NULL CHECK (persistence_class IN ('persistent', 'ephemeral', 'operator_interactive')),
  roles              TEXT[] NOT NULL DEFAULT '{}' CHECK ('' <> ALL (roles)),
  may_address        TEXT[] NOT NULL DEFAULT '{}' CHECK ('' <> ALL (may_address)),
  addressable_by     TEXT[] NOT NULL DEFAULT '{}' CHECK ('' <> ALL (addressable_by)),
  scope              JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(scope) = 'object'),
  capacity           JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(capacity) = 'object'),
  holds              JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(holds) = 'array'),
  holds_projected_at TIMESTAMPTZ,
  last_seen_at       TIMESTAMPTZ,
  ttl_seconds        INTEGER NOT NULL CHECK (ttl_seconds > 0),
  presence_state     TEXT NOT NULL DEFAULT 'stale' CHECK (presence_state IN ('live', 'stale', 'dark')),
  proxied_by         TEXT CHECK (proxied_by IS NULL OR length(btrim(proxied_by)) > 0),
  tombstoned_at      TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS registry_entries_roles_gin
  ON agent_bus.registry_entries USING gin (roles);
CREATE INDEX IF NOT EXISTS registry_entries_presence_idx
  ON agent_bus.registry_entries (presence_state, last_seen_at)
  WHERE tombstoned_at IS NULL;

-- Conditions (design 4.2) ------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_bus.conditions (
  condition_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind                TEXT NOT NULL CHECK (length(btrim(kind)) > 0),
  scope               JSONB NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
  starts_at           TIMESTAMPTZ NOT NULL,
  ends_at             TIMESTAMPTZ NOT NULL,
  owner_agent_id      TEXT NOT NULL CHECK (length(btrim(owner_agent_id)) > 0),
  effect              JSONB NOT NULL,
  work_ref            TEXT,
  renews_condition_id UUID REFERENCES agent_bus.conditions (condition_id) ON DELETE RESTRICT,
  cleared_by          TEXT CHECK (cleared_by IS NULL OR length(btrim(cleared_by)) > 0),
  cleared_at          TIMESTAMPTZ,
  version             INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (ends_at > starts_at),
  CHECK ((cleared_at IS NULL) = (cleared_by IS NULL)),
  -- Slice 1: effect maps role -> "annotate" only. A slice 2 migration relaxes this.
  CONSTRAINT conditions_slice1_annotate_only CHECK (
    jsonb_typeof(effect) = 'object'
    AND effect <> '{}'::jsonb
    AND NOT jsonb_path_exists(effect, '$.* ? (@.type() != "string" || @ != "annotate")')
  )
);

CREATE INDEX IF NOT EXISTS conditions_active_idx
  ON agent_bus.conditions (ends_at)
  WHERE cleared_at IS NULL;

CREATE OR REPLACE FUNCTION agent_bus.conditions_guard_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW IS NOT DISTINCT FROM OLD THEN
    RETURN OLD;
  END IF;
  IF NEW.condition_id IS DISTINCT FROM OLD.condition_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.scope IS DISTINCT FROM OLD.scope
     OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
     OR NEW.ends_at IS DISTINCT FROM OLD.ends_at
     OR NEW.owner_agent_id IS DISTINCT FROM OLD.owner_agent_id
     OR NEW.effect IS DISTINCT FROM OLD.effect
     OR NEW.work_ref IS DISTINCT FROM OLD.work_ref
     OR NEW.renews_condition_id IS DISTINCT FROM OLD.renews_condition_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'agent_bus.conditions are immutable; renew by inserting a new condition (condition %)', OLD.condition_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.cleared_at IS NOT NULL THEN
    RAISE EXCEPTION 'agent_bus.conditions clear is final (condition %)', OLD.condition_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'agent_bus.conditions update must advance version by exactly 1 (condition %)', OLD.condition_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$fn$;

-- Stream companions (design 4.3, 20.2) -----------------------------------
-- Foreign keys onto agent_bus.messages are added at the end (AR MS-01).
CREATE TABLE IF NOT EXISTS agent_bus.message_envelopes (
  message_id      BIGINT PRIMARY KEY,
  author_agent_id TEXT NOT NULL CHECK (length(btrim(author_agent_id)) > 0),
  idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) > 0),
  spec_version    TEXT NOT NULL CHECK (length(btrim(spec_version)) > 0),
  thread_id       BIGINT,
  reference_ids   BIGINT[] NOT NULL DEFAULT '{}',
  provider        TEXT,
  model           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (author_agent_id, idempotency_key)
);

-- One durable, append-only route per addressed role or named agent. Route
-- provenance lives only here (AR S-01, DS-01).
CREATE TABLE IF NOT EXISTS agent_bus.message_routes (
  route_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  message_id      BIGINT NOT NULL,
  target_kind     TEXT NOT NULL CHECK (target_kind IN ('role', 'agent')),
  target_role     TEXT CHECK (target_role IS NULL OR length(btrim(target_role)) > 0),
  target_agent_id TEXT CHECK (target_agent_id IS NULL OR length(btrim(target_agent_id)) > 0),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (
    (target_kind = 'role' AND target_role IS NOT NULL AND target_agent_id IS NULL)
    OR (target_kind = 'agent' AND target_agent_id IS NOT NULL AND target_role IS NULL)
  ),
  CONSTRAINT message_routes_target_unique
    UNIQUE NULLS NOT DISTINCT (message_id, target_kind, target_role, target_agent_id),
  CONSTRAINT message_routes_route_message_unique UNIQUE (route_id, message_id),
  CONSTRAINT message_routes_route_message_role_unique UNIQUE (route_id, message_id, target_role)
);

CREATE OR REPLACE FUNCTION agent_bus.reject_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
    USING ERRCODE = 'check_violation';
END;
$fn$;

CREATE TABLE IF NOT EXISTS agent_bus.deliveries (
  delivery_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  route_id              BIGINT NOT NULL,
  message_id            BIGINT NOT NULL,
  recipient_agent_id    TEXT NOT NULL CHECK (length(btrim(recipient_agent_id)) > 0),
  adapter               TEXT NOT NULL CHECK (length(btrim(adapter)) > 0),
  resolution_generation INTEGER NOT NULL DEFAULT 0 CHECK (resolution_generation >= 0),
  state                 TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'delivered', 'acked', 'failed', 'dead', 'superseded')),
  version               INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  attempts              INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at       TIMESTAMPTZ,
  adapter_ref           TEXT,
  delivered_at          TIMESTAMPTZ,
  acked_at              TIMESTAMPTZ,
  superseded_at         TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (state NOT IN ('delivered', 'acked') OR delivered_at IS NOT NULL),
  CHECK (state <> 'acked' OR acked_at IS NOT NULL),
  CHECK (state <> 'superseded' OR superseded_at IS NOT NULL),
  CONSTRAINT deliveries_route_fk FOREIGN KEY (route_id, message_id)
    REFERENCES agent_bus.message_routes (route_id, message_id) ON DELETE RESTRICT,
  CONSTRAINT deliveries_route_recipient_unique
    UNIQUE (route_id, recipient_agent_id, adapter, resolution_generation)
);

CREATE INDEX IF NOT EXISTS deliveries_retry_idx
  ON agent_bus.deliveries (next_attempt_at)
  WHERE state IN ('pending', 'failed');
CREATE INDEX IF NOT EXISTS deliveries_recipient_idx
  ON agent_bus.deliveries (recipient_agent_id, state, message_id);
CREATE INDEX IF NOT EXISTS deliveries_message_idx
  ON agent_bus.deliveries (message_id);

CREATE OR REPLACE FUNCTION agent_bus.deliveries_guard_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW.state <> 'pending' OR NEW.version <> 1 OR NEW.attempts <> 0
     OR NEW.adapter_ref IS NOT NULL OR NEW.delivered_at IS NOT NULL
     OR NEW.acked_at IS NOT NULL OR NEW.superseded_at IS NOT NULL THEN
    RAISE EXCEPTION 'agent_bus.deliveries rows are created pending, version 1, with no delivery side effects'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$fn$;

CREATE OR REPLACE FUNCTION agent_bus.deliveries_enforce_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  -- An identical replay is a no-op, not an error (AR MS-04).
  IF NEW IS NOT DISTINCT FROM OLD THEN
    RETURN OLD;
  END IF;

  IF NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
     OR NEW.route_id IS DISTINCT FROM OLD.route_id
     OR NEW.message_id IS DISTINCT FROM OLD.message_id
     OR NEW.recipient_agent_id IS DISTINCT FROM OLD.recipient_agent_id
     OR NEW.adapter IS DISTINCT FROM OLD.adapter
     OR NEW.resolution_generation IS DISTINCT FROM OLD.resolution_generation
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'agent_bus.deliveries identity is immutable; supersede and create a new generation instead (delivery %)', OLD.delivery_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.state IN ('acked', 'dead', 'superseded') THEN
    RAISE EXCEPTION 'agent_bus.deliveries state % is terminal (delivery %)', OLD.state, OLD.delivery_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'agent_bus.deliveries update must advance version by exactly 1 (delivery %, % -> %)', OLD.delivery_id, OLD.version, NEW.version
      USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.attempts < OLD.attempts THEN
    RAISE EXCEPTION 'agent_bus.deliveries attempts cannot decrease (delivery %)', OLD.delivery_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'pending'   AND NEW.state IN ('delivered', 'failed', 'superseded'))
    OR (OLD.state = 'failed'    AND NEW.state IN ('pending', 'dead', 'superseded'))
    OR (OLD.state = 'delivered' AND NEW.state IN ('acked', 'superseded'))
  ) THEN
    RAISE EXCEPTION 'illegal agent_bus.deliveries transition % -> % (delivery %)', OLD.state, NEW.state, OLD.delivery_id
      USING ERRCODE = 'check_violation';
  END IF;

  -- Side-effect fields change only on their own transition (AR DS-02).
  IF (NEW.delivered_at IS DISTINCT FROM OLD.delivered_at OR NEW.adapter_ref IS DISTINCT FROM OLD.adapter_ref)
     AND NOT (OLD.state = 'pending' AND NEW.state = 'delivered') THEN
    RAISE EXCEPTION 'delivered_at and adapter_ref are set only on pending -> delivered (delivery %)', OLD.delivery_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.acked_at IS DISTINCT FROM OLD.acked_at
     AND NOT (OLD.state = 'delivered' AND NEW.state = 'acked') THEN
    RAISE EXCEPTION 'acked_at is set only on delivered -> acked (delivery %)', OLD.delivery_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.superseded_at IS DISTINCT FROM OLD.superseded_at AND NEW.state <> 'superseded' THEN
    RAISE EXCEPTION 'superseded_at is set only on a transition to superseded (delivery %)', OLD.delivery_id
      USING ERRCODE = 'check_violation';
  END IF;

  -- Without a state change, only retry bookkeeping on pending or failed rows may change.
  IF NEW.state = OLD.state THEN
    IF OLD.state NOT IN ('pending', 'failed') THEN
      RAISE EXCEPTION 'agent_bus.deliveries in state % can only change by transition (delivery %)', OLD.state, OLD.delivery_id
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.attempts IS NOT DISTINCT FROM OLD.attempts
       AND NEW.next_attempt_at IS NOT DISTINCT FROM OLD.next_attempt_at THEN
      RAISE EXCEPTION 'agent_bus.deliveries update changes nothing but version (delivery %)', OLD.delivery_id
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$;

CREATE TABLE IF NOT EXISTS agent_bus.delivery_outbox (
  delivery_id UUID PRIMARY KEY REFERENCES agent_bus.deliveries (delivery_id) ON DELETE CASCADE,
  adapter     TEXT NOT NULL CHECK (length(btrim(adapter)) > 0),
  enqueued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  claimed_at  TIMESTAMPTZ,
  claimed_by  TEXT,
  CHECK ((claimed_at IS NULL) = (claimed_by IS NULL))
);

CREATE INDEX IF NOT EXISTS delivery_outbox_unclaimed_idx
  ON agent_bus.delivery_outbox (adapter, enqueued_at)
  WHERE claimed_at IS NULL;

-- Unassigned-role mailbox (design 20.2, AR R-04). Tied to its role route (DS-01).
CREATE TABLE IF NOT EXISTS agent_bus.role_mailbox (
  mailbox_id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  route_id              BIGINT NOT NULL UNIQUE,
  message_id            BIGINT NOT NULL,
  target_role           TEXT NOT NULL CHECK (length(btrim(target_role)) > 0),
  enqueued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  alarm_last_fired_at   TIMESTAMPTZ,
  inherited_by_agent_id TEXT CHECK (inherited_by_agent_id IS NULL OR length(btrim(inherited_by_agent_id)) > 0),
  inherited_at          TIMESTAMPTZ,
  CHECK ((inherited_at IS NULL) = (inherited_by_agent_id IS NULL)),
  CONSTRAINT role_mailbox_route_fk FOREIGN KEY (route_id, message_id, target_role)
    REFERENCES agent_bus.message_routes (route_id, message_id, target_role) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS role_mailbox_waiting_idx
  ON agent_bus.role_mailbox (target_role, enqueued_at)
  WHERE inherited_at IS NULL;

-- Identity (design 20.1, AR R-01, S-02, DS-03, DS-04) --------------------
CREATE TABLE IF NOT EXISTS agent_bus.registration_requests (
  request_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce                     TEXT NOT NULL UNIQUE CHECK (length(nonce) >= 16),
  public_key_sha256         TEXT NOT NULL CHECK (public_key_sha256 ~ '^[0-9a-f]{64}$'),
  requested_agent_id        TEXT NOT NULL CHECK (length(btrim(requested_agent_id)) > 0),
  persistence_class         TEXT NOT NULL CHECK (persistence_class IN ('persistent', 'ephemeral', 'operator_interactive')),
  claim_id                  UUID,
  launcher_agent_id         TEXT CHECK (launcher_agent_id IS NULL OR length(btrim(launcher_agent_id)) > 0),
  approval_challenge_sha256 TEXT CHECK (approval_challenge_sha256 IS NULL OR approval_challenge_sha256 ~ '^[0-9a-f]{64}$'),
  approval_expires_at       TIMESTAMPTZ,
  status                    TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'consumed', 'expired', 'rejected')),
  approved_at               TIMESTAMPTZ,
  consumed_at               TIMESTAMPTZ,
  consumed_token_jti        TEXT,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (persistence_class <> 'ephemeral' OR (claim_id IS NOT NULL AND launcher_agent_id IS NOT NULL)),
  CHECK (persistence_class <> 'operator_interactive' OR (approval_challenge_sha256 IS NOT NULL AND approval_expires_at IS NOT NULL)),
  CHECK (approval_expires_at IS NULL OR approval_expires_at > created_at),
  CHECK (status NOT IN ('approved', 'consumed') OR persistence_class <> 'operator_interactive' OR approved_at IS NOT NULL),
  CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
  CHECK ((status = 'consumed') = (consumed_token_jti IS NOT NULL)),
  CONSTRAINT registration_requests_identity_unique
    UNIQUE (request_id, requested_agent_id, public_key_sha256, persistence_class)
);

CREATE OR REPLACE FUNCTION agent_bus.registration_requests_guard_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW.status <> 'pending' OR NEW.approved_at IS NOT NULL
     OR NEW.consumed_at IS NOT NULL OR NEW.consumed_token_jti IS NOT NULL THEN
    RAISE EXCEPTION 'agent_bus.registration_requests rows are created pending with no approval or consumption'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$fn$;

CREATE OR REPLACE FUNCTION agent_bus.registration_requests_guard_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW IS NOT DISTINCT FROM OLD THEN
    RETURN OLD;
  END IF;

  IF NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.public_key_sha256 IS DISTINCT FROM OLD.public_key_sha256
     OR NEW.requested_agent_id IS DISTINCT FROM OLD.requested_agent_id
     OR NEW.persistence_class IS DISTINCT FROM OLD.persistence_class
     OR NEW.claim_id IS DISTINCT FROM OLD.claim_id
     OR NEW.launcher_agent_id IS DISTINCT FROM OLD.launcher_agent_id
     OR NEW.approval_challenge_sha256 IS DISTINCT FROM OLD.approval_challenge_sha256
     OR NEW.approval_expires_at IS DISTINCT FROM OLD.approval_expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'agent_bus.registration_requests identity is immutable (request %)', OLD.request_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.status IN ('consumed', 'expired', 'rejected') THEN
    RAISE EXCEPTION 'agent_bus.registration_requests status % is terminal (request %)', OLD.status, OLD.request_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF NOT (
       (OLD.status = 'pending'  AND NEW.status = 'approved' AND OLD.persistence_class = 'operator_interactive')
    OR (OLD.status = 'pending'  AND NEW.status = 'consumed' AND OLD.persistence_class <> 'operator_interactive')
    OR (OLD.status = 'pending'  AND NEW.status IN ('expired', 'rejected'))
    OR (OLD.status = 'approved' AND NEW.status IN ('consumed', 'expired'))
  ) THEN
    RAISE EXCEPTION 'illegal agent_bus.registration_requests transition % -> % for % (request %)', OLD.status, NEW.status, OLD.persistence_class, OLD.request_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.approved_at IS DISTINCT FROM OLD.approved_at AND NEW.status <> 'approved' THEN
    RAISE EXCEPTION 'approved_at is set only on pending -> approved (request %)', OLD.request_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF (NEW.consumed_at IS DISTINCT FROM OLD.consumed_at OR NEW.consumed_token_jti IS DISTINCT FROM OLD.consumed_token_jti)
     AND NEW.status <> 'consumed' THEN
    RAISE EXCEPTION 'consumed_at and consumed_token_jti are set only on consumption (request %)', OLD.request_id
      USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.status IN ('approved', 'consumed') AND OLD.approval_expires_at IS NOT NULL
     AND now() > OLD.approval_expires_at THEN
    RAISE EXCEPTION 'agent_bus.registration_requests approval expired at % (request %)', OLD.approval_expires_at, OLD.request_id
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END;
$fn$;

CREATE TABLE IF NOT EXISTS agent_bus.principal_keys (
  key_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id          TEXT NOT NULL CHECK (length(btrim(agent_id)) > 0),
  request_id        UUID,
  public_key        TEXT NOT NULL CHECK (length(btrim(public_key)) > 0),
  public_key_sha256 TEXT NOT NULL UNIQUE CHECK (public_key_sha256 ~ '^[0-9a-f]{64}$'),
  key_kind          TEXT NOT NULL CHECK (key_kind IN ('persistent', 'ephemeral', 'operator_interactive')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ,
  revoked_at        TIMESTAMPTZ,
  CHECK (key_kind = 'persistent' OR request_id IS NOT NULL),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  CONSTRAINT principal_keys_key_agent_unique UNIQUE (key_id, agent_id),
  -- A request-backed key must carry the request's exact agent, key hash, and class (DT-01).
  CONSTRAINT principal_keys_request_fk FOREIGN KEY (request_id, agent_id, public_key_sha256, key_kind)
    REFERENCES agent_bus.registration_requests (request_id, requested_agent_id, public_key_sha256, persistence_class)
    ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS principal_keys_active_idx
  ON agent_bus.principal_keys (agent_id)
  WHERE revoked_at IS NULL;

-- One row per issued token, linking key, request, session, and claim (AR DS-04).
CREATE TABLE IF NOT EXISTS agent_bus.issued_tokens (
  jti               TEXT PRIMARY KEY CHECK (length(btrim(jti)) > 0),
  agent_id          TEXT NOT NULL CHECK (length(btrim(agent_id)) > 0),
  key_id            UUID NOT NULL,
  request_id        UUID REFERENCES agent_bus.registration_requests (request_id) ON DELETE RESTRICT,
  session_id        TEXT NOT NULL CHECK (length(btrim(session_id)) > 0),
  claim_id          UUID,
  issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ NOT NULL,
  revoked_at        TIMESTAMPTZ,
  revoke_reason     TEXT,
  superseded_by_jti TEXT REFERENCES agent_bus.issued_tokens (jti) ON DELETE RESTRICT,
  CHECK (expires_at > issued_at),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
  CHECK (superseded_by_jti IS NULL OR revoked_at IS NOT NULL),
  -- A token's agent must be its key's agent (DT-01).
  CONSTRAINT issued_tokens_key_agent_fk FOREIGN KEY (key_id, agent_id)
    REFERENCES agent_bus.principal_keys (key_id, agent_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS issued_tokens_active_session_idx
  ON agent_bus.issued_tokens (agent_id, session_id)
  WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION agent_bus.issued_tokens_guard_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW IS NOT DISTINCT FROM OLD THEN
    RETURN OLD;
  END IF;
  IF NEW.jti IS DISTINCT FROM OLD.jti
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
     OR NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.claim_id IS DISTINCT FROM OLD.claim_id
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'agent_bus.issued_tokens identity is immutable (jti %)', OLD.jti
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'agent_bus.issued_tokens revocation is final (jti %)', OLD.jti
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$fn$;

-- Issuance must bind the token to its key's request, claim, and live key (DT-01).
CREATE OR REPLACE FUNCTION agent_bus.issued_tokens_guard_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
DECLARE
  k agent_bus.principal_keys%ROWTYPE;
  r agent_bus.registration_requests%ROWTYPE;
BEGIN
  SELECT * INTO k FROM agent_bus.principal_keys WHERE key_id = NEW.key_id;
  IF NOT FOUND OR k.agent_id IS DISTINCT FROM NEW.agent_id THEN
    RAISE EXCEPTION 'issued token % must use a key registered to agent %', NEW.jti, NEW.agent_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF k.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'issued token % uses revoked key %', NEW.jti, NEW.key_id
      USING ERRCODE = 'check_violation';
  END IF;
  -- A token can never outlive its key (AR DU-01).
  IF k.expires_at IS NOT NULL AND k.expires_at <= now() THEN
    RAISE EXCEPTION 'issued token % uses key % that expired at %', NEW.jti, NEW.key_id, k.expires_at
      USING ERRCODE = 'check_violation';
  END IF;
  IF k.expires_at IS NOT NULL AND NEW.expires_at > k.expires_at THEN
    RAISE EXCEPTION 'issued token % expiry % exceeds key % expiry %', NEW.jti, NEW.expires_at, NEW.key_id, k.expires_at
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.request_id IS DISTINCT FROM k.request_id THEN
    RAISE EXCEPTION 'issued token % request must match the key''s registration request', NEW.jti
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.request_id IS NOT NULL THEN
    SELECT * INTO r FROM agent_bus.registration_requests WHERE request_id = NEW.request_id;
    IF NEW.claim_id IS DISTINCT FROM r.claim_id THEN
      RAISE EXCEPTION 'issued token % claim must match its registration request claim', NEW.jti
        USING ERRCODE = 'check_violation';
    END IF;
    IF r.status NOT IN ('pending', 'approved') THEN
      RAISE EXCEPTION 'issued token % cannot be issued against a % registration request', NEW.jti, r.status
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$fn$;

CREATE OR REPLACE FUNCTION agent_bus.principal_keys_guard_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = agent_bus, pg_catalog
AS $fn$
BEGIN
  IF NEW IS NOT DISTINCT FROM OLD THEN
    RETURN OLD;
  END IF;
  IF NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
     OR NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.public_key_sha256 IS DISTINCT FROM OLD.public_key_sha256
     OR NEW.key_kind IS DISTINCT FROM OLD.key_kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'agent_bus.principal_keys identity is immutable; rotate by issuing a new key (key %)', OLD.key_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'agent_bus.principal_keys revocation is final (key %)', OLD.key_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$fn$;

-- Fast revocation lookup; rows may be pruned once the token has expired.
CREATE TABLE IF NOT EXISTS agent_bus.token_revocations (
  jti        TEXT PRIMARY KEY REFERENCES agent_bus.issued_tokens (jti) ON DELETE RESTRICT,
  agent_id   TEXT NOT NULL CHECK (length(btrim(agent_id)) > 0),
  reason     TEXT NOT NULL CHECK (length(btrim(reason)) > 0),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS token_revocations_expires_idx
  ON agent_bus.token_revocations (expires_at);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'registration_requests_consumed_token_fk') THEN
    ALTER TABLE agent_bus.registration_requests
      ADD CONSTRAINT registration_requests_consumed_token_fk
      FOREIGN KEY (consumed_token_jti) REFERENCES agent_bus.issued_tokens (jti)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS agent_bus.principal_audit_events (
  event_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_type TEXT NOT NULL CHECK (event_type IN ('key_issued', 'key_rotated', 'key_revoked', 'token_issued', 'token_revoked', 'registration_requested', 'registration_approved', 'registration_rejected', 'registration_consumed', 'session_superseded')),
  agent_id   TEXT NOT NULL CHECK (length(btrim(agent_id)) > 0),
  key_id     UUID,
  jti        TEXT,
  request_id UUID,
  session_id TEXT,
  actor      TEXT NOT NULL CHECK (length(btrim(actor)) > 0),
  detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS principal_audit_events_agent_idx
  ON agent_bus.principal_audit_events (agent_id, created_at DESC);

-- Reconciler freshness (design 20.2, AR S-03). Leadership uses coordination_leases.
CREATE TABLE IF NOT EXISTS agent_bus.reconciler_heartbeats (
  heartbeat_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  reconciler_agent_id  TEXT NOT NULL CHECK (length(btrim(reconciler_agent_id)) > 0),
  fencing_token        TEXT NOT NULL CHECK (length(btrim(fencing_token)) > 0),
  pass_started_at      TIMESTAMPTZ NOT NULL,
  pass_completed_at    TIMESTAMPTZ,
  invariant_violations JSONB NOT NULL DEFAULT '{}'::jsonb,
  CHECK (pass_completed_at IS NULL OR pass_completed_at >= pass_started_at)
);

CREATE INDEX IF NOT EXISTS reconciler_heartbeats_completed_idx
  ON agent_bus.reconciler_heartbeats (pass_completed_at DESC);

-- Triggers ------------------------------------------------------------------
DROP TRIGGER IF EXISTS conditions_guard_update ON agent_bus.conditions;
CREATE TRIGGER conditions_guard_update
  BEFORE UPDATE ON agent_bus.conditions
  FOR EACH ROW EXECUTE FUNCTION agent_bus.conditions_guard_update();

DROP TRIGGER IF EXISTS message_routes_append_only ON agent_bus.message_routes;
CREATE TRIGGER message_routes_append_only
  BEFORE UPDATE ON agent_bus.message_routes
  FOR EACH ROW EXECUTE FUNCTION agent_bus.reject_update();

DROP TRIGGER IF EXISTS deliveries_guard_insert ON agent_bus.deliveries;
CREATE TRIGGER deliveries_guard_insert
  BEFORE INSERT ON agent_bus.deliveries
  FOR EACH ROW EXECUTE FUNCTION agent_bus.deliveries_guard_insert();

DROP TRIGGER IF EXISTS deliveries_enforce_transition ON agent_bus.deliveries;
CREATE TRIGGER deliveries_enforce_transition
  BEFORE UPDATE ON agent_bus.deliveries
  FOR EACH ROW EXECUTE FUNCTION agent_bus.deliveries_enforce_transition();

DROP TRIGGER IF EXISTS registration_requests_guard_insert ON agent_bus.registration_requests;
CREATE TRIGGER registration_requests_guard_insert
  BEFORE INSERT ON agent_bus.registration_requests
  FOR EACH ROW EXECUTE FUNCTION agent_bus.registration_requests_guard_insert();

DROP TRIGGER IF EXISTS registration_requests_guard_update ON agent_bus.registration_requests;
CREATE TRIGGER registration_requests_guard_update
  BEFORE UPDATE ON agent_bus.registration_requests
  FOR EACH ROW EXECUTE FUNCTION agent_bus.registration_requests_guard_update();

DROP TRIGGER IF EXISTS issued_tokens_guard_insert ON agent_bus.issued_tokens;
CREATE TRIGGER issued_tokens_guard_insert
  BEFORE INSERT ON agent_bus.issued_tokens
  FOR EACH ROW EXECUTE FUNCTION agent_bus.issued_tokens_guard_insert();

DROP TRIGGER IF EXISTS issued_tokens_guard_update ON agent_bus.issued_tokens;
CREATE TRIGGER issued_tokens_guard_update
  BEFORE UPDATE ON agent_bus.issued_tokens
  FOR EACH ROW EXECUTE FUNCTION agent_bus.issued_tokens_guard_update();

DROP TRIGGER IF EXISTS principal_keys_guard_update ON agent_bus.principal_keys;
CREATE TRIGGER principal_keys_guard_update
  BEFORE UPDATE ON agent_bus.principal_keys
  FOR EACH ROW EXECUTE FUNCTION agent_bus.principal_keys_guard_update();

DROP TRIGGER IF EXISTS principal_audit_events_append_only ON agent_bus.principal_audit_events;
CREATE TRIGGER principal_audit_events_append_only
  BEFORE UPDATE OR DELETE ON agent_bus.principal_audit_events
  FOR EACH ROW EXECUTE FUNCTION agent_bus.reject_update();

REVOKE ALL ON FUNCTION agent_bus.conditions_guard_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.reject_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.deliveries_guard_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.deliveries_enforce_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.registration_requests_guard_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.registration_requests_guard_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.issued_tokens_guard_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.issued_tokens_guard_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_bus.principal_keys_guard_update() FROM PUBLIC;

COMMENT ON TABLE agent_bus.registry_entries IS 'OB-60175 Muster registry: one entry per agent_id; presence, roles, addressability, projected holds and capacity.';
COMMENT ON TABLE agent_bus.conditions IS 'OB-60175 Muster conditions: immutable declared time-bounded platform facts. Slice 1 effects are annotate-only (CHECK).';
COMMENT ON TABLE agent_bus.message_envelopes IS 'OB-60175 Muster envelope for agent_bus.messages: server-authored identity, idempotency key, thread and provenance.';
COMMENT ON TABLE agent_bus.message_routes IS 'OB-60175 Muster append-only route per addressed role or named agent; the single source of route provenance (AR S-01, DS-01).';
COMMENT ON TABLE agent_bus.deliveries IS 'OB-60175 Muster delivery ledger keyed by route. Created pending; identity immutable; legal transitions and side effects enforced by trigger.';
COMMENT ON TABLE agent_bus.delivery_outbox IS 'OB-60175 Muster transactional outbox consumed by delivery adapters.';
COMMENT ON TABLE agent_bus.role_mailbox IS 'OB-60175 Muster unassigned-role mailbox tied to its role route, inherited by the next live holder or owner (AR R-04).';
COMMENT ON TABLE agent_bus.registration_requests IS 'OB-60175 Muster brokered and operator-approved registration requests; single-use state machine enforced by trigger (AR DS-03).';
COMMENT ON TABLE agent_bus.principal_keys IS 'OB-60175 Muster proof-of-possession public keys, linked to the registration request that produced them (AR S-02, DS-04).';
COMMENT ON TABLE agent_bus.issued_tokens IS 'OB-60175 Muster issued tokens linking key, request, session, and claim; revocation is final (AR DS-04).';
COMMENT ON TABLE agent_bus.token_revocations IS 'OB-60175 Muster revoked token lookup checked on every API request; prunable after expires_at.';
COMMENT ON TABLE agent_bus.principal_audit_events IS 'OB-60175 Muster append-only audit trail for key, token, registration, and session events.';
COMMENT ON TABLE agent_bus.reconciler_heartbeats IS 'OB-60175 Muster reconciler pass heartbeats for freshness alarms (AR S-03).';

-- Lineage: register objects before consumers (FK) -------------------------
INSERT INTO aurora_data_objects
  (object_name, layer, object_kind, canonical_name, source_key, domain, lifecycle_state, notes)
VALUES
  ('agent_bus.registry_entries', 'registry', 'table', 'agent_bus.registry_entries', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster registry.'),
  ('agent_bus.conditions', 'registry', 'table', 'agent_bus.conditions', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster conditions.'),
  ('agent_bus.message_envelopes', 'registry', 'table', 'agent_bus.message_envelopes', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster message envelopes.'),
  ('agent_bus.message_routes', 'registry', 'table', 'agent_bus.message_routes', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster message routes.'),
  ('agent_bus.deliveries', 'registry', 'table', 'agent_bus.deliveries', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster delivery ledger.'),
  ('agent_bus.delivery_outbox', 'registry', 'table', 'agent_bus.delivery_outbox', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster delivery outbox.'),
  ('agent_bus.role_mailbox', 'registry', 'table', 'agent_bus.role_mailbox', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster unassigned-role mailbox.'),
  ('agent_bus.registration_requests', 'registry', 'table', 'agent_bus.registration_requests', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster registration requests.'),
  ('agent_bus.principal_keys', 'registry', 'table', 'agent_bus.principal_keys', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster principal keys.'),
  ('agent_bus.issued_tokens', 'registry', 'table', 'agent_bus.issued_tokens', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster issued tokens.'),
  ('agent_bus.token_revocations', 'registry', 'table', 'agent_bus.token_revocations', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster token revocations.'),
  ('agent_bus.principal_audit_events', 'registry', 'table', 'agent_bus.principal_audit_events', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster identity audit trail.'),
  ('agent_bus.reconciler_heartbeats', 'registry', 'table', 'agent_bus.reconciler_heartbeats', 'agent_bus', 'coordination', 'active', 'OB-60175 Muster reconciler heartbeats.')
ON CONFLICT (object_name) DO UPDATE
  SET notes = EXCLUDED.notes, lifecycle_state = 'active', updated_at = now();

INSERT INTO aurora_data_object_consumers
  (object_name, column_name, consumer_kind, consumer_name, access_kind, evidence, lifecycle_state)
SELECT t.object_name, '*', c.consumer_kind, c.consumer_name, c.access_kind, c.evidence, 'active'
FROM (VALUES
  ('agent_bus.registry_entries'), ('agent_bus.conditions'), ('agent_bus.message_envelopes'),
  ('agent_bus.message_routes'), ('agent_bus.deliveries'), ('agent_bus.delivery_outbox'),
  ('agent_bus.role_mailbox'), ('agent_bus.registration_requests'), ('agent_bus.principal_keys'),
  ('agent_bus.issued_tokens'), ('agent_bus.token_revocations'), ('agent_bus.principal_audit_events'),
  ('agent_bus.reconciler_heartbeats')
) AS t(object_name)
CROSS JOIN (VALUES
  ('migration', 'ob60175-muster-companion-schema', 'writes', 'OB-60175 creates the Muster slice 1 companion table.'),
  ('api_route', 'muster-api', 'reads', 'Muster API (OB-60176, OB-60178, OB-60180) reads Muster slice 1 state.'),
  ('api_route', 'muster-api', 'writes', 'Muster API (OB-60176, OB-60178, OB-60180) writes Muster slice 1 state.')
) AS c(consumer_kind, consumer_name, access_kind, evidence)
ON CONFLICT (object_name, column_name, consumer_kind, consumer_name, access_kind)
DO UPDATE SET evidence = EXCLUDED.evidence, lifecycle_state = 'active', updated_at = now();

INSERT INTO aurora_data_object_consumers
  (object_name, column_name, consumer_kind, consumer_name, access_kind, evidence, lifecycle_state)
VALUES
  ('agent_bus.registry_entries', '*', 'worker_handler', 'muster-nexus-bridge', 'reads', 'OB-60177 bridge reads registry state for presence and dark detection.', 'active'),
  ('agent_bus.registry_entries', '*', 'worker_handler', 'muster-nexus-bridge', 'writes', 'OB-60177 bridge writes holds, capacity, and presence projections.', 'active'),
  ('agent_bus.message_routes', '*', 'worker_handler', 'muster-nexus-bridge', 'reads', 'OB-60181 reconciler checks per-route invariants.', 'active'),
  ('agent_bus.deliveries', '*', 'worker_handler', 'muster-nexus-bridge', 'reads', 'OB-60181 reconciler and agent_inbox adapter read deliveries.', 'active'),
  ('agent_bus.deliveries', '*', 'worker_handler', 'muster-nexus-bridge', 'writes', 'OB-60181 adapter and reconciler advance delivery state.', 'active'),
  ('agent_bus.delivery_outbox', '*', 'worker_handler', 'muster-nexus-bridge', 'reads', 'OB-60181 agent_inbox adapter consumes the outbox.', 'active'),
  ('agent_bus.delivery_outbox', '*', 'worker_handler', 'muster-nexus-bridge', 'writes', 'OB-60181 agent_inbox adapter claims outbox rows.', 'active'),
  ('agent_bus.role_mailbox', '*', 'worker_handler', 'muster-nexus-bridge', 'reads', 'OB-60181 reconciler checks mailbox entries.', 'active'),
  ('agent_bus.role_mailbox', '*', 'worker_handler', 'muster-nexus-bridge', 'writes', 'OB-60181 reconciler records mailbox inheritance.', 'active'),
  ('agent_bus.reconciler_heartbeats', '*', 'worker_handler', 'muster-nexus-bridge', 'writes', 'OB-60181 reconciler writes a heartbeat per completed pass.', 'active'),
  ('agent_bus.reconciler_heartbeats', '*', 'worker_handler', 'muster-nexus-bridge', 'reads', 'OB-60179 freshness alarm reads the latest reconciler pass.', 'active')
ON CONFLICT (object_name, column_name, consumer_kind, consumer_name, access_kind)
DO UPDATE SET evidence = EXCLUDED.evidence, lifecycle_state = 'active', updated_at = now();

-- Foreign keys onto the live bus table last, so the SHARE ROW EXCLUSIVE lock
-- they take on agent_bus.messages is held for the shortest time before COMMIT
-- (AR MS-01). RESTRICT, never CASCADE: deleting a bus message must not erase
-- Muster delivery history (AR MS-02, DS-06).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'message_envelopes_message_fk') THEN
    ALTER TABLE agent_bus.message_envelopes
      ADD CONSTRAINT message_envelopes_message_fk
      FOREIGN KEY (message_id) REFERENCES agent_bus.messages (id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'message_envelopes_thread_fk') THEN
    ALTER TABLE agent_bus.message_envelopes
      ADD CONSTRAINT message_envelopes_thread_fk
      FOREIGN KEY (thread_id) REFERENCES agent_bus.messages (id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'message_routes_message_fk') THEN
    ALTER TABLE agent_bus.message_routes
      ADD CONSTRAINT message_routes_message_fk
      FOREIGN KEY (message_id) REFERENCES agent_bus.messages (id) ON DELETE RESTRICT;
  END IF;
END;
$$;

INSERT INTO nexus_schema_version (version, description)
VALUES (1884, 'OB-60175 Muster slice 1 companion schema in agent_bus')
ON CONFLICT (version) DO NOTHING;

UPDATE migration_registry
   SET status = 'applied', applied_at = now()
 WHERE version = 1884
   AND slug = 'ob60175-muster-companion-schema'
   AND status = 'reserved';

COMMIT;
