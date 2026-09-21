# Rust TicTacToe DevSecOps Demo

[![DevSecOps Attested Pipeline](../../actions/workflows/devsecops-pipeline.yml/badge.svg)](../../actions/workflows/devsecops-pipeline.yml)

A Rust CLI tic-tac-toe game wired into the
[devsecops-attestation](https://github.com/MemerGamer/devsecops-attestation)
cryptographic pipeline. This repository reuses that project's composite
GitHub Actions instead of reimplementing the attestation and gate logic:
[`MemerGamer/devsecops-attestation/actions`](https://github.com/MemerGamer/devsecops-attestation/tree/main/actions).

**Purpose**: Demonstrate the pipeline actively blocking a deployment when
security checks detect real vulnerabilities. The `feat: add game statistics
webhook` commit introduces four intentional security issues -- one per check
type -- causing the deploy gate to BLOCK, with the reasons recorded
cryptographically in the attestation chain.

---

## What the pipeline catches

| Check | Tool | Issue introduced | Severity |
|-------|------|-----------------|----------|
| SAST | semgrep | Shell injection (unsanitized `format!` into `sh -c`) + unnecessary `unsafe` block in `stats.rs` | high / medium |
| SCA | cargo-audit | `time = "0.1"` -- RUSTSEC-2020-0071 | high |
| Config | Checkov | Dockerfile: no `USER`, no `HEALTHCHECK`, `EXPOSE 22` | high / medium |
| Secret | Gitleaks | Hardcoded AWS-shaped key `AKIAIOSFODNN7EXAMPLE` in `stats.rs` | n/a (see note below) |

All four issues are marked in place with `INTENTIONAL:` comments (Dockerfile,
`Cargo.toml`, `src/stats.rs`) and must not be "fixed" -- that would defeat the
point of the demo. `.github/dependabot.yml` explicitly ignores upgrades of
the `time` crate for the same reason.

### Expected deny reasons

The devsecops-attestation composite actions run the **bundled default deploy
policy** (no repository-local policy file, no `--policy-hash`). That policy's
blocking severity threshold is `critical`, and none of this demo's issues are
scored that high by the normalize adapters (semgrep's `ERROR` maps to
`high`; RUSTSEC-2020-0071's CVSS vector maps to `high`; checkov findings
without a tool-reported severity map to `medium`). The `deploy-gate` job
therefore passes `fail-on-severity: medium` to `actions/gate` to lower the
blocking threshold -- still the bundled policy, just a stricter threshold --
so these real, non-critical-but-real findings actually block deployment.
Each `normalize-sign` step also passes `fail-on: medium`, matching the
gate's threshold, so the `passed` field recorded in each signed attestation
agrees with what the gate ultimately decides; `normalize-sign` defaults
`fail-on` to `critical`, and leaving that default in place would have
signed `passed: true` attestations for findings the gate then denies on.

Also note: gitleaks' own default rule set allowlists the specific example
key used here (`AKIAIOSFODNN7EXAMPLE` is AWS's documented placeholder
value), so a real gitleaks scan of this repository reports **zero** secret
findings. The secret check type therefore passes and is not what causes the
deny. If you swap in a key that is not on gitleaks' allowlist, the
zero-tolerance `secret` check type would additionally contribute a
"hardcoded credential finding(s)" deny reason.

With the fixtures used in local validation (see "Validation" below), the
observed deny reason was:

```
found 8 finding(s) at or above "medium" severity
```

covering the SAST, SCA, and config findings described above. CI is **green**
when the gate denies as expected (`expect: deny` on the `actions/gate` step)
and **red** if the vulnerable build is ever allowed through.

---

## Pipeline overview

```mermaid
flowchart TD
    A([Push / PR]) --> B["Build & Test\ncargo build --release · cargo test"]
    B --> C["SAST\nsemgrep auto"]
    B --> D["SCA\ncargo-audit"]
    B --> E["Config Scan\nCheckov"]
    B --> F["Secret Scan\nGitleaks"]
    C --> G[semgrep-raw.json]
    D --> H[cargo-audit-raw.json]
    E --> I[checkov-raw.json]
    F --> J[gitleaks-raw.json]
    G & H & I & J --> K["actions/setup\ninstall attest/verify/gate CLIs"]
    K --> L["actions/normalize-sign x4\nnormalize + Ed25519 sign per check type"]
    L --> M["actions/gate\nverify chain + OPA policy eval (expect: deny)"]
    M --> N{Decision}
    N -->|deny as expected| O[CI green -- pipeline correctly BLOCKED]
    N -->|allow| P[CI red -- vulnerable build would have deployed]
```

Raw scanner output is uploaded as-is; all normalization into the canonical
finding shape happens inside `attest normalize` / `attest sign
--tool-format` (via `actions/normalize-sign`), not in this repository's
workflow.

---

## CI/CD setup (GitHub Actions)

### 1. Generate four key pairs

```bash
git clone https://github.com/MemerGamer/devsecops-attestation
cd devsecops-attestation
for check in sast sca config secret; do
  go run ./cmd/keygen --out "keys/$check"
done
```

### 2. Add all eight secrets to this repository

**Settings -> Secrets and variables -> Actions -> New repository secret**

| Secret | Value |
|---|---|
| `SAST_SIGNING_KEY` | Contents of `keys/sast/private.hex` |
| `SCA_SIGNING_KEY` | Contents of `keys/sca/private.hex` |
| `CONFIG_SIGNING_KEY` | Contents of `keys/config/private.hex` |
| `SECRET_SCANNING_SIGNING_KEY` | Contents of `keys/secret/private.hex` |
| `SAST_PUBLIC_KEY` | Contents of `keys/sast/public.hex` |
| `SCA_PUBLIC_KEY` | Contents of `keys/sca/public.hex` |
| `CONFIG_PUBLIC_KEY` | Contents of `keys/config/public.hex` |
| `SECRET_SCANNING_PUBLIC_KEY` | Contents of `keys/secret/public.hex` |

The pipeline uses the bundled default deploy policy shipped inside the
devsecops-attestation release archive (installed by `actions/setup`), so
there is no policy file to pin or hash in this repository.

---

## Local development

```bash
# Build
cargo build --release

# Run
./target/release/tictactoe

# Tests
cargo test
```

### Local pipeline simulation (act)

```bash
bash scripts/act-debug.sh
```

The `deploy-gate` job resolves `MemerGamer/devsecops-attestation/actions/*`
composite actions from GitHub, and `actions/setup` downloads a release
archive by default, so a fully offline `act` run needs either network
access or act's `--local-repository` flag (see the comment block at the top
of `scripts/act-debug.sh`) pointed at a local checkout via the
`ATTESTATION_SRC` environment variable (defaults to
`../devsecops-attestation` next to this repository).

---

## Forgejo

`devsecops-attestation`'s composite actions are pure bash (`shell: bash`
only, no Node.js runtime), so they run unmodified on Forgejo Actions
runners. Reference them by full URL instead of the GitHub `owner/repo`
shorthand, e.g.:

```yaml
- uses: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/actions/setup@v0.4.0
  with:
    version: "0.4.0"
    download-base-url: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/releases/download
```

`download-base-url` must be set explicitly on Forgejo since the action's own
default points at the GitHub release.

---

## License

MIT
