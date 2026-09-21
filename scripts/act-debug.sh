#!/usr/bin/env bash
# Local pipeline debugger using act.
# Run from the repo root: bash scripts/act-debug.sh [job]
# If no job is given, runs all jobs in order.
#
# The deploy-gate job now pulls its logic from the composite actions in
# MemerGamer/devsecops-attestation/actions (setup, normalize-sign, gate)
# instead of cloning and building this repo's own copy of the CLI. Those
# composite actions download a tagged release archive by default, so a
# local act run needs one of:
#
#   1. A real network connection to GitHub, so act can resolve
#      MemerGamer/devsecops-attestation/actions/*@v0.4.0 and the
#      setup action can download the matching release archive; or
#   2. act's --local-repository flag (added in act v0.2.60), which maps a
#      "uses:" reference to a local checkout instead of fetching it. Check
#      whether your installed act supports it with `act --help | grep
#      local-repository`. If it does, point every actions/* reference at a
#      local checkout of devsecops-attestation:
#
#        act push -e push.json \
#          --local-repository MemerGamer/devsecops-attestation@v0.4.0="$ATTESTATION_SRC"
#
#      Combine this with the setup action's `version: source` input (edit
#      the workflow temporarily, or override via act's -e/--input support)
#      so setup.sh builds the CLI from that checkout instead of trying to
#      download a release archive that does not exist yet.
#
#   3. If your installed act has neither --local-repository nor network
#      access, run the scanner jobs (build, sast, sca, config-scan,
#      secret-scan) individually with `-j <job>`, and exercise the
#      deploy-gate logic separately with devsecops-attestation's own
#      actions/test/run-local.sh against this repo's raw scan output
#      instead of through act.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Sibling checkout of devsecops-attestation, overridable for machines where
# the two repos are not checked out side by side.
ATTESTATION_SRC="${ATTESTATION_SRC:-$(git -C "$REPO_DIR" rev-parse --show-toplevel)/../devsecops-attestation}"
BINS_DIR="${BINS_DIR:-/tmp/act-bins}"
KEYS_DIR="${KEYS_DIR:-/tmp/act-keys-rust}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/act-artifacts}"
SECRETS_FILE="$REPO_DIR/.secrets"

cd "$REPO_DIR"

# ── Detect Docker socket (overridable for non-standard setups) ────────────
if [ -n "${DOCKER_HOST:-}" ]; then
  echo "Using pre-set DOCKER_HOST: $DOCKER_HOST"
elif [ -S "${DOCKER_SOCKET:-/var/run/docker.sock}" ]; then
  export DOCKER_HOST="unix://${DOCKER_SOCKET:-/var/run/docker.sock}"
elif [ -S "$HOME/.docker/desktop/docker.sock" ]; then
  export DOCKER_HOST="unix://$HOME/.docker/desktop/docker.sock"
else
  echo "ERROR: No Docker socket found. Is Docker running?"
  echo "Set DOCKER_SOCKET or DOCKER_HOST to override the default lookup."
  exit 1
fi
echo "Using Docker: $DOCKER_HOST"

# ── Build attestation binaries from a local checkout, for ad hoc use ─────
# (not required by the workflow itself, which now uses the setup composite
# action; kept here for manual testing of the CLI against this repo's
# fixtures without pulling a release archive).
if [ -d "$ATTESTATION_SRC" ]; then
  if [ ! -f "$BINS_DIR/attest" ] || [ ! -f "$BINS_DIR/gate" ] || [ ! -f "$BINS_DIR/keygen" ]; then
    echo "Building devsecops-attestation binaries from $ATTESTATION_SRC..."
    mkdir -p "$BINS_DIR"
    (cd "$ATTESTATION_SRC" && go build -o "$BINS_DIR/" ./cmd/...)
    [ -f "$BINS_DIR/sign" ] && mv "$BINS_DIR/sign" "$BINS_DIR/attest"
    echo "Binaries built in $BINS_DIR"
  fi
else
  echo "NOTE: ATTESTATION_SRC ($ATTESTATION_SRC) not found; skipping local CLI build."
  echo "Set ATTESTATION_SRC to a devsecops-attestation checkout if you need it."
fi

# ── Generate per-check-type test keys if .secrets is missing ─────────────
if [ ! -f "$SECRETS_FILE" ] && [ -f "$BINS_DIR/keygen" ]; then
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
  echo "NOTE: the deploy-gate job needs network access to GitHub (to resolve"
  echo "MemerGamer/devsecops-attestation/actions/*@v0.4.0) unless your act"
  echo "supports --local-repository -- see the comment block at the top of"
  echo "this script."
fi

"${ACT_CMD[@]}"
