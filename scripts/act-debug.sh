#!/usr/bin/env bash
# Local pipeline debugger using act.
# Run from the repo root: bash scripts/act-debug.sh [job]
# If no job is given, runs all jobs in order.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTEST_SRC="/home/hunor/Documents/GitHub/devsecops-attestation"
BINS_DIR="/tmp/act-bins"
KEYS_DIR="/tmp/act-keys-rust"
ARTIFACTS_DIR="/tmp/act-artifacts"
SECRETS_FILE="$REPO_DIR/.secrets"

cd "$REPO_DIR"

# ── Detect Docker socket ───────────────────────────────────────────────────────
if [ -S /home/hunor/.docker/desktop/docker.sock ]; then
  export DOCKER_HOST="unix:///home/hunor/.docker/desktop/docker.sock"
elif [ -S /var/run/docker.sock ]; then
  export DOCKER_HOST="unix:///var/run/docker.sock"
else
  echo "ERROR: No Docker socket found. Is Docker running?"
  exit 1
fi
echo "Using Docker: $DOCKER_HOST"

# ── Build attestation binaries if missing ─────────────────────────────────────
if [ ! -f "$BINS_DIR/sign" ] || [ ! -f "$BINS_DIR/gate" ] || [ ! -f "$BINS_DIR/keygen" ]; then
  echo "Building devsecops-attestation binaries..."
  mkdir -p "$BINS_DIR"
  cd "$ATTEST_SRC"
  go build -o "$BINS_DIR/sign"   ./cmd/sign
  go build -o "$BINS_DIR/gate"   ./cmd/gate
  go build -o "$BINS_DIR/keygen" ./cmd/keygen
  cd "$REPO_DIR"
  echo "Binaries built in $BINS_DIR"
fi

# ── Generate per-check-type test keys if .secrets is missing ─────────────────
if [ ! -f "$SECRETS_FILE" ]; then
  echo "Generating per-check-type signing keys..."
  mkdir -p "$KEYS_DIR"
  for check in sast sca config secret; do
    "$BINS_DIR/keygen" --out "$KEYS_DIR/$check" --force
  done
  {
    echo "SAST_SIGNING_KEY=$(cat "$KEYS_DIR/sast/private.hex")"
    echo "SCA_SIGNING_KEY=$(cat "$KEYS_DIR/sca/private.hex")"
    echo "CONFIG_SIGNING_KEY=$(cat "$KEYS_DIR/config/private.hex")"
    echo "SECRET_SCANNING_SIGNING_KEY=$(cat "$KEYS_DIR/secret/private.hex")"
    echo "SAST_PUBLIC_KEY=$(cat "$KEYS_DIR/sast/public.hex")"
    echo "SCA_PUBLIC_KEY=$(cat "$KEYS_DIR/sca/public.hex")"
    echo "CONFIG_PUBLIC_KEY=$(cat "$KEYS_DIR/config/public.hex")"
    echo "SECRET_SCANNING_PUBLIC_KEY=$(cat "$KEYS_DIR/secret/public.hex")"
  } > "$SECRETS_FILE"
  echo "Keys written to $SECRETS_FILE"
fi

mkdir -p "$ARTIFACTS_DIR"

# ── Run act ───────────────────────────────────────────────────────────────────
JOB="${1:-}"
ACT_CMD=(act push -e push.json)

if [ -n "$JOB" ]; then
  ACT_CMD+=(-j "$JOB")
  echo "Running job: $JOB"
else
  echo "Running full pipeline..."
fi

"${ACT_CMD[@]}"
