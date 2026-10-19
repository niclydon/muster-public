# Snapshot Provenance

## What this repository is

`muster-public` is the public edition of Muster: cross-runtime agent
coordination in three layers (Registry for identity, roles, presence, and
addressability; Conditions for declared, time-bounded platform facts; and
a typed Stream for coordination messages), served by one API that enforces
identity, authority, and addressability.

Muster is the coordination layer for a private multi-agent platform. This
edition publishes the core implementation (slice 1: service core, identity,
registry, stream, conditions, north-star state) so the design can be read
and the code studied.

## Edition facts

- Snapshot date: **October 18, 2026**
- Source: the private `muster` repository, HEAD of September 22, 2026
  (23 commits; the design has been stable since)
- Form: single-commit snapshot. The private history is not published.
- Tests and test fixtures are included; fixtures are schema DDL only.

## The scrub

The private tree was already close to publishable; the audit (pattern
scans plus gitleaks over the tree) found one class to generalize:

- The production deployment's private network address (a Tailscale
  address) appeared in the deploy script, the systemd unit, two env
  templates, the smoke test, and one test fixture. All instances are
  generalized to `127.0.0.1` in this edition; the code takes the real
  address from the environment at deploy time.
- The deployment codename for the production host is retained in test
  fixtures and examples (agent ids like `codex:furnace:runner-*`): it is
  a bare hostname with no address, the same disclosure class as the
  codenames in the nexus-public edition.
- Secret values were never in the source tree: env templates carry
  `<redacted>` placeholders, and signing material is generated at
  runtime. One gitleaks finding (a version-string constant in
  signing.ts) is a false positive, verified by reading the file.

## What is not here, by the design's own boundary

This repository holds the core only, deliberately. Deployment knowledge
(the roles file, the binding that maps roles to a work system) lives with
the deployment, and the core refuses to import it (`npm run
check:boundary` enforces that in the build). Production data (the live
registry, message stream, and north-star contents) lives in the
deployment's database and was never in the source tree.

## Refresh policy

Refreshed deliberately, not mirrored, in the same pattern as the other
public editions in this account: re-audit the private tree, re-apply the
scrub, update this page and the snapshot date.
