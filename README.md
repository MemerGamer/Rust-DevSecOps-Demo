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
type. Three of the four cause the deploy gate to BLOCK (the secret finding
is allowlisted by gitleaks, as explained later); the reasons are recorded
cryptographically in the attestation chain.

---

## What the pipeline catches

| Check | Tool | Issue introduced | Severity |
|-------|------|-----------------|----------|
| SAST | semgrep (repo-local rules in `.semgrep/demo.yml` only) | Shell injection (unsanitized `format!` into `sh -c`) + unnecessary `unsafe` block around `from_raw_parts`/`from_utf8_unchecked` in `stats.rs` | high (shell injection) / medium (two `unsafe`-block findings, one per flagged line) |
| SCA | cargo-audit | `time = "0.1"` -- RUSTSEC-2020-0071 (CVSS 6.2) | medium |
| Config | Checkov | Dockerfile: no `USER`, no `HEALTHCHECK`, `EXPOSE 22` | medium (checkov's Dockerfile checks report no severity of their own; the normalize adapter maps a null severity to medium) |
| Secret | Gitleaks | Hardcoded AWS-shaped key `AKIAIOSFODNN7EXAMPLE` in `stats.rs` | n/a (see note below) |

All four issues are marked in place with `INTENTIONAL:` comments (Dockerfile,
`Cargo.toml`, `src/stats.rs`) and must not be "fixed" -- that would defeat the
point of the demo. `.github/dependabot.yml` explicitly ignores upgrades of
the `time` crate for the same reason.

The SAST issues are caught by two repo-local semgrep rules written for this
demo's exact code, `.semgrep/demo.yml`:

- `rust-shell-injection` (severity `ERROR`, normalizes to `high`): flags a
  `format!`-built string reaching `Command::new("sh").arg("-c").arg(...)`
  (command/shell injection, CWE-78). The rule's `pattern-sinks` uses
  `focus-metavariable` on the sink argument, so it matches once, at the
  `.arg(&cmd)` sink in `stats.rs`, not on the `format!` call itself.
- `rust-unsafe-from-utf8-unchecked` (severity `WARNING`, normalizes to
  `medium`): flags `unsafe` blocks built around
  `std::str::from_utf8_unchecked` / `std::slice::from_raw_parts`. The
  `unsafe` block in `stats.rs` calls both functions, so this rule matches
  twice -- once per flagged line -- for two medium findings.

The workflow runs only these repo-local rules (`--config .semgrep/`), not
`--config=auto` and not a registry pack such as `p/rust`. Registry packs are
resolved from the Semgrep Registry over the network at scan time and are not
pinned to a version, so which rules run (and therefore which findings
appear) can change between runs without any change to this repository. The
repo-local ruleset is fully deterministic for a given semgrep version:
running the same semgrep version against the same code always produces the
same three findings.

### Expected deny reasons

The `actions/gate` step below sets no `policy:` input, so `gate evaluate`
runs without a `--policy` flag and falls back to the **policy compiled into
the gate binary itself** (the bundled default deploy policy) -- not a
repository-local policy file, and not the separate `deploy.rego` file
`actions/setup` installs alongside the binaries for callers who do want to
pin/hash a policy file with `--policy-hash`. That compiled-in default
policy's blocking severity threshold is `high`, and semgrep's `ERROR`-level
command-injection finding already scores that high by the normalize
adapters' mapping: semgrep's `ERROR` maps to `high` and its `WARNING` to
`medium`; RUSTSEC-2020-0071's CVSS 6.2 vector maps to `medium`, not `high`;
checkov's Dockerfile checks (`CKV_DOCKER_*`) report no severity of their
own, and a null severity normalizes to `medium`. So the default `high`
threshold alone would already deny on the SAST finding. The `deploy-gate`
job additionally passes `fail-on-severity: medium` to `actions/gate` to
lower the blocking threshold further -- still the bundled policy, just a
stricter threshold -- so the medium-rated SCA (RUSTSEC-2020-0071) and
config (checkov) findings also block deployment, which is why the deny
reasons list `sast`, `sca`, and `config`. Each `normalize-sign` step also
passes `fail-on: medium`, matching the gate's threshold, so the `passed`
field recorded in each signed attestation agrees with what the gate
ultimately decides; `normalize-sign` already defaults `fail-on` to `high`,
but leaving that default in place on the SCA and config steps would have
signed `passed: true` attestations for their medium findings that the gate
then denies on.

Also note: gitleaks' own default rule set allowlists the specific example
key used here (`AKIAIOSFODNN7EXAMPLE` is AWS's documented placeholder
value), so a real gitleaks scan of this repository reports **zero** secret
findings. The secret check type therefore passes and is not what causes the
deny. If you swap in a key that is not on gitleaks' allowlist, the
zero-tolerance `secret` check type would additionally contribute a
"hardcoded credential finding(s)" deny reason.

With the current scanner output reproduced by a CI run of this pipeline, the
gate denied with both of these reasons:

```
failed checks: ["sast", "sca", "config"]
found N finding(s) at or above "medium" severity
```

Both deny reasons come from **OPA policy evaluation** against the compiled-in
default policy, not from the gate's earlier Go-level chain verification
step (signatures, chain linkage, subject consistency, timestamp ordering --
that step passes cleanly here; nothing about it fails). The first reason,
`failed checks`, is the policy's `passed == false` rule: `normalize-sign`'s
`fail-on: medium` on each step above signs an attestation with
`passed: false` whenever it carries a medium-or-higher finding, and the
policy denies deployment for every check type recorded that way. The second
reason, the finding-count line, is the policy's blocking severity-threshold
rule evaluated against `fail-on-severity: medium` on the `actions/gate`
step. Both rules are evaluated by OPA against the same signed, verified
chain -- one flags failing check types, the other counts qualifying
findings directly -- so the same underlying findings typically produce both
reasons together. The exact count `N` is not pinned here on purpose -- it
depends on the installed versions of semgrep, cargo-audit and checkov
(scanner rule sets and CVE databases both change over time), so
re-running the scanners can shift which and how many findings appear
without changing whether the gate denies. Both reasons cover the SAST, SCA, and config
findings described above; the secret check type passes (see the gitleaks
note) and does not contribute either reason. CI is **green** when the gate
denies as expected (`expect: deny` on the `actions/gate` step) and **red**
if the vulnerable build is ever allowed through.

---

## Pipeline overview

```mermaid
flowchart TD
    A([Push / PR]) --> B["Build & Test\ncargo build --release · cargo test"]
    B --> C["SAST\nsemgrep .semgrep/ only"]
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

The four scanner jobs always run, including on dependabot's own pull
requests. (Dependabot's own commits are pushed to `dependabot/*` branches,
which this workflow's `push:` trigger does not match -- only `main` and
`develop` -- so in practice dependabot only ever triggers the
`pull_request` event here, not `push`.) The `deploy-gate` job is skipped
for two cases where repository secrets are unavailable to it:
`github.actor != 'dependabot[bot]'` excludes dependabot pull requests (see
above), and the `pull_request.head.repo.full_name` check excludes pull
requests from forks. GitHub Actions withholds repository secrets from both
kinds of runs, so the `*_SIGNING_KEY` inputs would be empty and
`normalize-sign` would fail for a reason unrelated to any security finding.
See the `if:` condition and its comment on the `deploy-gate` job in
`.github/workflows/devsecops-pipeline.yml` for the exact expression.

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

The pipeline sets no `policy:` input on `actions/gate`, so it uses the
policy compiled into the `gate` binary itself (the bundled default deploy
policy), not a file this repository would need to pin or hash.

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
composite actions from GitHub at the pinned commit SHA of the published
`v0.4.1` release. Since that release exists on GitHub, act can resolve the
reference over the network like any other action, and `deploy-gate` runs
end-to-end under `act` with no extra flags, as long as `actions/setup`'s
`verify-signature` check can reach the network -- GitHub Releases (for the
CLI binaries) and the cosign Sigstore transparency log (for checksum
verification) both need to be available.
`scripts/act-debug.sh` additionally passes act's `--local-repository` flag
whenever a local `devsecops-attestation` checkout is available (via the
`ATTESTATION_SRC` environment variable, defaulting to
`../devsecops-attestation` next to this repository), which redirects the
`uses:` reference to that local checkout's action definitions instead of
asking GitHub to resolve them. This is only useful for testing *unreleased*
changes to the composite actions themselves (i.e. editing
`devsecops-attestation` locally and exercising those edits against this
workflow before they are tagged and pushed) -- `--local-repository` only
redirects where the action *definition* (`action.yml`) is read from, it does
not change what `setup.sh` itself does once it runs. With the workflow's
default `version: 0.4.1`, `setup.sh` still downloads the real v0.4.1 release
archive over the network regardless of `--local-repository`, so testing an
unreleased local change to `setup.sh`'s own install logic additionally needs
the workflow's `version:` input switched to `source` (which builds the CLI
from the checkout instead of downloading anything, and needs Go on `PATH`
inside the job -- add an `actions/setup-go` step before `actions/setup`,
since the default `version: 0.4.1` path needs no compiler and this workflow
does not install Go today). The scanner jobs (`build`, `sast`, `sca`,
`config-scan`, `secret-scan`) do not depend on devsecops-attestation at all
and run fine under `act` on their own, e.g. `bash scripts/act-debug.sh sast`.

`scripts/act-debug.sh` requires a `.secrets` file (generated automatically
from a local devsecops-attestation checkout, or write your own from the
table above) before it will run `act`; set `ALLOW_NO_SECRETS=1` to run
without one on purpose (e.g. when only exercising a scanner job). The
script writes `.secrets` with `umask 077`, so it is created readable only
by your own user; it holds the same Ed25519 private keys as the repository
secrets above and should be treated the same way (never commit it -- it is
already gitignored).

---

## Forgejo

`devsecops-attestation`'s composite actions are pure bash (`shell: bash`
only, no Node.js runtime), so they run unmodified on Forgejo Actions
runners. Reference them by full URL instead of the GitHub `owner/repo`
shorthand, e.g.:

```yaml
- uses: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/actions/setup@v0.4.1
  with:
    version: "0.4.1"
    download-base-url: https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation/releases/download
```

`download-base-url` must be set explicitly on Forgejo since the action's own
default points at the GitHub release.

---

## Trust boundaries and recommended repository settings

- **Signing keys are repository secrets.** As configured today, any
  same-repository branch that can edit a workflow file can also read
  `SAST_SIGNING_KEY`, `SCA_SIGNING_KEY`, `CONFIG_SIGNING_KEY`, and
  `SECRET_SCANNING_SIGNING_KEY` at run time -- repository secrets are
  available to any workflow run on a branch of the repository itself
  (forks and dependabot are excluded by the `deploy-gate` job's `if:`
  condition, but a same-repo feature branch is not). Recommended
  hardening: move the eight `*_SIGNING_KEY`/`*_PUBLIC_KEY` secrets from
  repository secrets into the `production` environment's own secrets, and
  restrict that environment to `main` with a deployment branch policy (and
  optionally required reviewers, under **Settings -> Environments ->
  production**). After that change, PR and feature-branch runs of
  `deploy-gate` (which references `environment: production`) do not skip
  signing -- they FAIL, because GitHub rejects the environment outright
  ("Branch ... is not allowed to deploy to production due to environment
  protection rules"). The signing keys remain unexposed on those runs, but
  to keep PR CI green under this hardening, the `deploy-gate` job's `if:`
  condition would also need to exclude `pull_request` events and non-main
  refs, so the job simply does not run on branches that are not permitted
  to use the environment's secrets.
- **Dependabot PRs skip the gate.** The `if:` condition on `deploy-gate`
  excludes `github.actor == 'dependabot[bot]'` runs (see "Pipeline
  overview" above), so a dependabot version bump never actually exercises
  signing or policy evaluation, even though the four scanner jobs still
  run and upload raw results. To let dependabot PRs exercise the full
  supply-chain-bump path, add the same eight secrets as [Dependabot
  secrets](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/configuring-access-to-private-registries-for-dependabot#storing-credentials-for-dependabot-to-use)
  (**Settings -> Secrets and variables -> Dependabot**) and relax the
  `if:` condition to stop excluding `dependabot[bot]`. This is a
  deliberate trade-off the current configuration does not make by default:
  it grants a bot-authored PR path access to the signing keys.
- **Signatures attest to what the gate job saw, not to the artifacts in
  transit.** Each signed attestation proves that the `deploy-gate` job
  observed a particular raw scanner JSON document (`semgrep-raw.json`,
  `cargo-audit-raw.json`, `checkov-raw.json`, `gitleaks-raw.json`) at
  signing time. The raw JSON travels between the scanner jobs and
  `deploy-gate` as a plain `actions/upload-artifact` /
  `actions/download-artifact` artifact, which is not itself signed or
  encrypted in transit -- anyone able to write to the workflow run's
  artifact store between upload and download could in principle alter it
  before `deploy-gate` signs it. The cryptographic guarantee here is "this
  is what the signer saw and signed," not "this is what the scanner
  originally produced, unmodified end to end."

---

## License

MIT
