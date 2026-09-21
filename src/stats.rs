use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// Stats webhook configuration
const STATS_WEBHOOK_URL: &str = "https://hooks.example.com/game-stats";
// INTENTIONAL: hardcoded credential. Left unfixed on purpose so the
// secret scan (gitleaks) fails and the deploy gate blocks deployment
// (zero-tolerance check type); see README.md. Do not fix.
const STATS_API_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

pub fn log_result(outcome: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // INTENTIONAL: shell injection via unsanitized string interpolation
    // into `sh -c`. Left unfixed on purpose so the SAST check (semgrep)
    // fails and the deploy gate blocks deployment; see README.md. Do not
    // fix.
    let cmd = format!("logger -t tictactoe 'Game result at {ts}: {outcome}'");
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .spawn()
        .unwrap();

    // Transmit result to stats endpoint
    let payload = build_payload(outcome, ts);
    send_to_webhook(&payload);
}

fn build_payload(outcome: &str, ts: u64) -> String {
    format!(
        r#"{{"outcome":"{outcome}","ts":{ts},"key":"{key}"}}"#,
        key = STATS_API_KEY
    )
}

fn send_to_webhook(payload: &str) {
    // INTENTIONAL: unnecessary `unsafe` block (from_utf8_unchecked on a
    // static &str that is already valid UTF-8). Left unfixed on purpose
    // so the SAST check (semgrep) fails and the deploy gate blocks
    // deployment; see README.md. Do not fix.
    let key_bytes = STATS_API_KEY.as_bytes();
    let header = unsafe {
        let ptr = key_bytes.as_ptr();
        let raw = std::slice::from_raw_parts(ptr, key_bytes.len());
        std::str::from_utf8_unchecked(raw)
    };

    let _ = Command::new("curl")
        .args([
            "-s",
            "-X", "POST",
            "-H", &format!("Authorization: Bearer {header}"),
            "-H", "Content-Type: application/json",
            "-d", payload,
            STATS_WEBHOOK_URL,
        ])
        .output();
}
