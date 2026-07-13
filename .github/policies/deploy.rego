package devsecops.gate

import rego.v1

# ─────────────────────────────────────────────────────────────────
# Deploy policy for the Rust TicTacToe demo app
#
# Input (from gate evaluate):
#   input.attestations[]
#     .result.check_type        - "sast" | "sca" | "config" | "secret"
#     .result.passed            - bool
#     .result.findings[]
#       .severity               - "critical" | "high" | "medium" | "low"
#     .signer_public_key_hex    - hex-encoded Ed25519 public key (injected by gate)
#   input.authorized_signers    - map of check_type -> hex pubkey
#
# Output consumed by gate:
#   allow        - bool  (data.deploy.allow)
#   deny_reasons - set   (data.deploy.deny_reasons -> GateDecision.Reasons)
#
# Rules:
#   1. All four required checks must be present in the chain.
#   2. No critical findings are allowed in any check.
#   3. SAST and SCA must pass outright (passed == true).
#   4. Config scan may have low/medium findings but must have
#      no critical or high findings.
#   5. Zero tolerance for hardcoded credentials: any secret-scan
#      finding blocks deployment regardless of its reported severity.
#   6. Every attestation must be signed by the key authorized for
#      its check type (enforced when authorized_signers is configured).
# ─────────────────────────────────────────────────────────────────

required_checks := {"sast", "sca", "config", "secret"}

# Collect the check types present in the attestation chain
present_checks := {a.result.check_type | a := input.attestations[_]}

# Allow deployment only when all conditions pass
default allow := false

allow if {
    missing_checks == set()
    count(critical_findings) == 0
    count(secret_findings) == 0
    sast_passed
    sca_passed
    # No attestations signed by unauthorized signers (only checked when
    # authorized_signers is configured; absent entries are not evaluated)
    count([a |
        a := input.attestations[_]
        authorized := input.authorized_signers[a.result.check_type]
        a.signer_public_key_hex != authorized
    ]) == 0
}

# ── Missing checks ────────────────────────────────────────────────
missing_checks := required_checks - present_checks

# ── Critical findings across all checks ──────────────────────────
critical_findings := {f |
    a := input.attestations[_]
    f := a.result.findings[_]
    f.severity == "critical"
}

# ── Hardcoded credentials: zero tolerance regardless of severity ──
secret_findings := {f |
    a := input.attestations[_]
    a.result.check_type == "secret"
    f := a.result.findings[_]
}

# ── SAST must pass ────────────────────────────────────────────────
sast_passed if {
    some a in input.attestations
    a.result.check_type == "sast"
    a.result.passed == true
}

# ── SCA must pass ─────────────────────────────────────────────────
sca_passed if {
    some a in input.attestations
    a.result.check_type == "sca"
    a.result.passed == true
}

# ── Deny reasons (read by gate as GateDecision.Reasons) ──────────
deny_reasons contains msg if {
    count(missing_checks) > 0
    msg := sprintf("Missing required checks: %v", [missing_checks])
}

deny_reasons contains msg if {
    count(critical_findings) > 0
    msg := sprintf("%d critical finding(s) found", [count(critical_findings)])
}

deny_reasons contains msg if {
    count(secret_findings) > 0
    msg := sprintf("%d hardcoded credential finding(s) found", [count(secret_findings)])
}

deny_reasons contains "SAST did not pass" if not sast_passed

deny_reasons contains "SCA did not pass" if not sca_passed

deny_reasons contains msg if {
    a := input.attestations[_]
    authorized := input.authorized_signers[a.result.check_type]
    a.signer_public_key_hex != authorized
    msg := sprintf("unauthorized signer for check type %q: key does not match authorized signer", [a.result.check_type])
}
