#!/usr/bin/env bash
# Local pipeline debugger using act.
# Run from the repo root: bash scripts/act-debug.sh [job]
# If no job is given, runs all jobs in order.
#
# The deploy-gate job pulls its logic from the composite actions in
# MemerGamer/devsecops-attestation/actions (setup, normalize-sign, gate),
# pinned to the commit SHA of the published v0.4.1 release, instead of
# cloning and building this repo's own copy of the CLI. Since that release
# exists on GitHub, act resolves the `uses:` reference over the network like
# any other action, and deploy-gate runs end-to-end under act with no extra
# flags, given network access to GitHub Releases (for the CLI binaries) and
# the cosign Sigstore transparency log (for checksum verification).
#
# This script additionally passes act's --local-repository flag (added in
# act v0.2.60) whenever a local devsecops-attestation checkout is found at
# $ATTESTATION_SRC (default: ../devsecops-attestation next to this
# repository), mapping every MemerGamer/devsecops-attestation/actions/*
# reference pinned to that release's commit SHA to that local checkout's
# action definitions instead of asking GitHub to resolve them:
#
#   act push -e push.json \
#     --local-repository MemerGamer/devsecops-attestation@<sha>="$ATTESTATION_SRC"
#
# This is only useful for testing *unreleased* changes to the composite
# actions themselves (i.e. editing devsecops-attestation locally and
# exercising those edits against this workflow before they are tagged and
# pushed) -- for the pinned v0.4.1 release itself, act needs no such
# redirect. IMPORTANT: --local-repository only redirects where the action
# *definition* (action.yml) is read from. It does not change what setup.sh
# does once it runs: with `version: 0.4.1` (the version this workflow
# currently pins), setup.sh still downloads the real v0.4.1 release archive
# over the network regardless of --local-repository. So testing an
# unreleased local change to setup.sh's own install logic additionally needs
# the workflow's `version:` input switched to "source" (which builds the CLI
# from the checkout instead of downloading anything). To use
# `version: source`, the setup action's own docs say it requires Go on PATH
# inside the job that runs it: add an `actions/setup-go` step *before* the
# `actions/setup` step (this workflow's deploy-gate job does not install Go
# today, since the default `version: 0.4.1` path only downloads a prebuilt
# binary and needs no compiler). The `version:` value is a `with:` input on
# the composite action, fed from the workflow's own YAML, not an event
# field -- it cannot be overridden via act's -e/--input support. Edit the
# workflow file temporarily (set `version: source`) to exercise this path
# locally.
#
# If you have no network access to GitHub at all, run the scanner jobs
# (build, sast, sca, config-scan, secret-scan) individually with `-j <job>`
# -- these do not touch devsecops-attestation at all -- and exercise the
# deploy-gate logic separately by calling the attest/gate CLIs (built with
# `go build` from a local devsecops-attestation checkout, see below)
# directly against this repo's raw scan output, instead of through act.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Sibling checkout of devsecops-attestation, overridable for machines where
# the two repos are not checked out side by side.
ATTESTATION_SRC="${ATTESTATION_SRC:-$(git -C "$REPO_DIR" rev-parse --show-toplevel)/../devsecops-attestation}"
# Commit SHA the workflow's MemerGamer/devsecops-attestation/actions/*
# references are pinned to (the v0.4.1 release). Must match the `uses:` refs
# in .github/workflows/devsecops-pipeline.yml exactly, since --local-repository
# below maps by this same ref.
ATTESTATION_SHA="43a819d52e705bbd2aad2e6be5c34bf9584880af"
# BINS_DIR/KEYS_DIR/ARTIFACTS_DIR default to freshly created, randomly named
# directories (mktemp -d) rather than fixed shared paths like /tmp/act-bins:
# a fixed, predictable path under a world-writable directory is a symlink /
# pre-planted-file target on a shared machine. Override any of the three to
# reuse a specific directory across runs, at your own risk.
BINS_DIR="${BINS_DIR:-$(mktemp -d -t rust-devsecops-demo-bins.XXXXXX)}"
KEYS_DIR="${KEYS_DIR:-$(mktemp -d -t rust-devsecops-demo-keys.XXXXXX)}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$(mktemp -d -t rust-devsecops-demo-artifacts.XXXXXX)}"
SECRETS_FILE="$REPO_DIR/.secrets"
PUSH_EVENT_FILE="$REPO_DIR/push.json"
# Set ALLOW_NO_SECRETS=1 to run act without a .secrets file on purpose (for
# example to exercise only the scanner jobs, which need no signing keys).
ALLOW_NO_SECRETS="${ALLOW_NO_SECRETS:-0}"

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
# (not required by the workflow itself, which uses the setup composite
# action; kept here for manual testing of the CLI against this repo's
# fixtures without pulling a release archive, and to generate local test
# keys below). Always built fresh into BINS_DIR above -- this script never
# executes a binary that was already sitting in a shared/reused directory
# without having built it itself in this invocation.
if [ -d "$ATTESTATION_SRC" ]; then
  echo "Building devsecops-attestation binaries from $ATTESTATION_SRC..."
  (cd "$ATTESTATION_SRC" && go build -o "$BINS_DIR/" ./cmd/...)
  [ -f "$BINS_DIR/sign" ] && mv "$BINS_DIR/sign" "$BINS_DIR/attest"
  echo "Binaries built in $BINS_DIR"
else
  echo "NOTE: ATTESTATION_SRC ($ATTESTATION_SRC) not found; skipping local CLI build."
  echo "Set ATTESTATION_SRC to a devsecops-attestation checkout if you need it."
fi

# ── Generate per-check-type test keys if .secrets is missing ─────────────
if [ ! -f "$SECRETS_FILE" ] && [ -f "$BINS_DIR/keygen" ]; then
  echo "Generating per-check-type signing keys..."
  for check in sast sca config secret; do
    "$BINS_DIR/keygen" --out "$KEYS_DIR/$check" --force
  done
  # umask 077 for the duration of the write below: .secrets holds Ed25519
  # private keys, so it must never be created group/world readable, even
  # transiently between creation and any later chmod.
  (
    umask 077
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
  )
  echo "Keys written to $SECRETS_FILE"
fi

# ── Fail closed if we still have no .secrets file ─────────────────────────
# Without a .secrets file, act runs every job with the *_SIGNING_KEY and
# *_PUBLIC_KEY secrets unset, so normalize-sign and gate fail (or worse,
# silently misbehave) for reasons unrelated to the security findings this
# demo is about. Only proceed without secrets when that is explicitly
# requested (e.g. to run just the scanner jobs, which need none).
if [ ! -f "$SECRETS_FILE" ] && [ "$ALLOW_NO_SECRETS" != "1" ]; then
  echo "ERROR: $SECRETS_FILE not found and could not be generated" \
    "(no devsecops-attestation checkout / keygen binary at $BINS_DIR)."
  echo "Either set ATTESTATION_SRC to a devsecops-attestation checkout so" \
    "this script can build keygen and generate test keys, create" \
    "$SECRETS_FILE by hand (see README.md), or set ALLOW_NO_SECRETS=1 to" \
    "run act without signing keys on purpose (e.g. -j build/sast/sca/" \
    "config-scan/secret-scan only)."
  exit 1
fi

# ── Ensure an act push event file exists ──────────────────────────────────
# push.json is normally committed, but fall back to generating a minimal
# one so the script still works if it is ever missing or deliberately
# left untracked.
if [ ! -f "$PUSH_EVENT_FILE" ]; then
  echo "NOTE: $PUSH_EVENT_FILE not found; generating a minimal push event."
  PUSH_EVENT_FILE="$ARTIFACTS_DIR/push.json"
  cat > "$PUSH_EVENT_FILE" <<'EOF'
{
  "ref": "refs/heads/main",
  "repository": { "full_name": "MemerGamer/Rust-DevSecOps-Demo" },
  "head_commit": { "id": "0000000000000000000000000000000000000000" }
}
EOF
fi

# ── Run act ───────────────────────────────────────────────────────────────────
JOB="${1:-}"
# --artifact-server-path is required for upload-artifact/download-artifact
# to work under act; without it, artifacts uploaded by the scanner jobs
# are not available to deploy-gate's download-artifact step.
ACT_CMD=(act push -e "$PUSH_EVENT_FILE" --artifact-server-path "$ARTIFACTS_DIR")

# Map the pinned MemerGamer/devsecops-attestation/actions/*@$ATTESTATION_SHA
# reference to a local checkout whenever one is available, so local edits to
# the composite actions can be exercised without tagging and pushing a new
# release first. Since v0.4.1 is published, act can resolve the reference
# from GitHub on its own even without this -- --local-repository is only
# needed here for testing unreleased action changes (see the comment block
# at the top of this file).
if [ -d "$ATTESTATION_SRC" ]; then
  ACT_CMD+=(--local-repository "MemerGamer/devsecops-attestation@$ATTESTATION_SHA=$ATTESTATION_SRC")
fi

if [ -n "$JOB" ]; then
  ACT_CMD+=(-j "$JOB")
  echo "Running job: $JOB"
else
  echo "Running full pipeline..."
  if [ ! -d "$ATTESTATION_SRC" ]; then
    echo "NOTE: ATTESTATION_SRC ($ATTESTATION_SRC) not found, so"
    echo "--local-repository is not being passed; the deploy-gate job will"
    echo "resolve MemerGamer/devsecops-attestation/actions/*@$ATTESTATION_SHA"
    echo "from GitHub over the network instead."
  else
    echo "NOTE: --local-repository is being passed, redirecting action"
    echo "definitions to $ATTESTATION_SRC. This only affects unreleased local"
    echo "edits to the composite actions; see the comment block at the top"
    echo "of this script for what else 'version: source' needs."
  fi
fi

"${ACT_CMD[@]}"
