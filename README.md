# Rust TicTacToe DevSecOps Demo

[![DevSecOps Attested Pipeline](../../actions/workflows/devsecops-pipeline.yml/badge.svg)](../../actions/workflows/devsecops-pipeline.yml)

A Rust CLI tic-tac-toe game wired into the
[devsecops-attestation](https://github.com/MemerGamer/devsecops-attestation)
cryptographic pipeline.

**Purpose**: Demonstrate the pipeline actively blocking a deployment when security
checks detect real vulnerabilities. The `feat: add game statistics webhook` commit
introduces four intentional security issues -- one per check type -- causing the
deploy gate to BLOCK with detailed reasons.

---

## What the pipeline catches

| Check | Tool | Issue introduced | Severity |
|-------|------|-----------------|----------|
| SAST | semgrep | Command injection + unsafe block in `stats.rs` | high |
| SCA | cargo-audit | `time = "0.1"` -- RUSTSEC-2020-0071 | medium |
| Config | Checkov | Dockerfile: no USER, no HEALTHCHECK, EXPOSE 22 | medium |
| Secret | Gitleaks | Hardcoded AWS key `AKIAIOSFODNN7EXAMPLE` in `stats.rs` | high |

The gate blocks because `sast_passed == false` and `sca_passed == false` (policy
requires both to pass outright). Secret and config findings are logged as additional
deny reasons.

---

## Pipeline overview

```mermaid
flowchart TD
    A([Push / PR]) --> B["Build & Test\ncargo build --release · cargo test"]
    B --> C["SAST\nsemgrep auto"]
    B --> D["SCA\ncargo-audit"]
    B --> E["Config Scan\nCheckov"]
    B --> F["Secret Scan\nGitleaks"]
    C --> G[results/sast.json]
    D --> H[results/sca.json]
    E --> I[results/config.json]
    F --> J[results/secret.json]
    G & H & I & J --> K[Deploy Gate]
    K --> L["Sign x4 -- Ed25519 per-check-type keys"]
    L --> M["gate evaluate -- chain + OPA policy"]
    M --> N{Decision}
    N -->|allow| O[Deploy]
    N -->|block| P[Pipeline BLOCKED]
```

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

### 3. Policy hash

The gate pins the SHA-256 of `deploy.rego`. Current value (already set in workflow):

```
08ae75548b9bb3b414079fabbdff11af3bed95f720d3c0b039615dd0b19868c5
```

If you modify the policy, recompute: `sha256sum .github/policies/deploy.rego`

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

---

## License

MIT
