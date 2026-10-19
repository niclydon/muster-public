#!/usr/bin/env bash
# Deploy muster-api on Furnace from a clean checkout of niclydon/muster main.
# Usage: deploy/deploy.sh [--source-dir <checkout>]
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "${1:-}" == "--source-dir" ]]; then SOURCE_DIR="$(cd "$2" && pwd)"; fi
TARGET=/services/muster
ENV_FILE=/etc/homelab/secrets/muster.env
UNIT=muster-api.service
PRESENCE_UNIT=muster-presence.service

log() { echo "[muster-deploy] $*"; }

case "$PWD/" in "$SOURCE_DIR"/*) echo "[muster-deploy] run from outside the source dir" >&2; exit 2 ;; esac
if [[ -n "$(git -C "$SOURCE_DIR" status --porcelain)" ]]; then
  echo "[muster-deploy] source checkout is dirty; refusing" >&2; exit 2
fi
COMMIT=$(git -C "$SOURCE_DIR" rev-parse --short HEAD)
log "[1/6] verify $COMMIT"
(cd "$SOURCE_DIR" && npm ci --no-audit --no-fund && npm run check:boundary && npm run build)

log "[2/6] sync to $TARGET"
sudo -n mkdir -p "$TARGET"
sudo -n chown niclydon:niclydon "$TARGET"
# operator-console/ and presence/ exist only on the target (secret placeholders for the two client env files).
rsync -a --delete --exclude .git --exclude .env.secrets --exclude /operator-console/ --exclude /presence/ "$SOURCE_DIR"/ "$TARGET"/
if [[ ! -f "$TARGET/.env.secrets" ]]; then
  install -m 0640 "$SOURCE_DIR/deploy/env.secrets.template" "$TARGET/.env.secrets"
fi
echo "$COMMIT" > "$TARGET/DEPLOYED_COMMIT"

log "[3/6] production dependencies"
(cd "$TARGET" && npm ci --omit=dev --no-audit --no-fund)

log "[4/6] materialize $ENV_FILE"
# sudo resets the environment; sv needs the operator's AWS profile to resolve vault URIs (same as nexus deploy.sh).
sudo -n env HOME=/home/niclydon AWS_PROFILE="${AWS_PROFILE:-secrets}" AWS_REGION="${AWS_REGION:-us-east-1}" \
  /home/niclydon/projects/secrets-vault/bin/sv materialize \
  --cwd "$TARGET" --output "$ENV_FILE" --owner root --group niclydon --mode 0640 --backup-previous

# OB-60221: the nexus-mcp management tools sign as operator-console. Its seat key and token are
# materialized into a separate file the nexus-mcp unit loads (EnvironmentFile=-...), so the
# nexus service secrets never mix with muster-api's own DATABASE_URL.
CONSOLE_DIR="$TARGET/operator-console"
CONSOLE_ENV_FILE=/etc/homelab/secrets/muster-operator-console.env
mkdir -p "$CONSOLE_DIR"
install -m 0640 "$SOURCE_DIR/deploy/operator-console.env.secrets.template" "$CONSOLE_DIR/.env.secrets"
log "[4/6] materialize $CONSOLE_ENV_FILE"
sudo -n env HOME=/home/niclydon AWS_PROFILE="${AWS_PROFILE:-secrets}" AWS_REGION="${AWS_REGION:-us-east-1}" \
  /home/niclydon/projects/secrets-vault/bin/sv materialize \
  --cwd "$CONSOLE_DIR" --output "$CONSOLE_ENV_FILE" --owner root --group niclydon --mode 0640 --backup-previous

# Agent onboarding: muster-presence keeps persistent Nexus seats registered first-hand. Its env file
# gains one vault-backed key line per seat from scripts/muster-onboard-agent.mjs, so the deploy seeds
# the placeholder file once and never overwrites it.
PRESENCE_DIR="$TARGET/presence"
PRESENCE_ENV_FILE=/etc/homelab/secrets/muster-presence.env
mkdir -p "$PRESENCE_DIR"
if [[ ! -f "$PRESENCE_DIR/.env.secrets" ]]; then
  install -m 0640 "$SOURCE_DIR/deploy/presence.env.secrets.template" "$PRESENCE_DIR/.env.secrets"
fi
log "[4/6] materialize $PRESENCE_ENV_FILE"
sudo -n env HOME=/home/niclydon AWS_PROFILE="${AWS_PROFILE:-secrets}" AWS_REGION="${AWS_REGION:-us-east-1}" \
  /home/niclydon/projects/secrets-vault/bin/sv materialize \
  --cwd "$PRESENCE_DIR" --output "$PRESENCE_ENV_FILE" --owner root --group niclydon --mode 0640 --backup-previous

log "[5/6] install units and restart"
for unit in "$UNIT" "$PRESENCE_UNIT"; do
  sudo -n install -m 0644 "$SOURCE_DIR/deploy/$unit" /etc/systemd/system/$unit
done
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now $UNIT >/dev/null
sudo -n systemctl restart $UNIT
# The presence unit exits 2 until the first seat is onboarded; enable it so it runs once one exists.
sudo -n systemctl enable $PRESENCE_UNIT >/dev/null
sudo -n systemctl restart $PRESENCE_UNIT || true

log "[6/6] health"
for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 http://127.0.0.1:7880/health >/dev/null; then
    log "healthy at $COMMIT (muster-presence: $(systemctl is-active $PRESENCE_UNIT || true))"; exit 0
  fi
  sleep 1
done
echo "[muster-deploy] health check failed" >&2
sudo -n systemctl status $UNIT --no-pager | tail -20 >&2
exit 1
