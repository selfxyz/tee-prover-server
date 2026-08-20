//! Generic pre-check delegate: shells out to the JS `signature-verifier`
//! sidecar for every circuit `dispatch` does not route natively (i.e.
//! everything except `register_kyc` -- see `mod.rs`'s `dispatch`).
//!
//! Plan A, Task 4: this replaces `primitives::brainpool`, which spoke a
//! brainpool-only, curve/hash/coordinate wire contract. The JS side now
//! covers RSA, RSA-PSS, and ECDSA (both NIST and brainpool curves) through
//! `node:crypto`'s single `crypto.verify` entry point, so the Rust client no
//! longer needs to know anything about schemes, curves, or limb layouts at
//! all -- it just hands over the circuit name and the path to the already-
//! written `input.json`, and the sidecar does its own parsing on its side of
//! the wire (see `signature-verifier/verify.mjs`'s `main()`).
//!
//! Wire contract, pinned by this task's brief:
//!   stdin:  `{"circuit":"<name>","inputPath":"/tmp/.../input.json"}`
//!   stdout: `{"verdict":"valid"}`
//!         | `{"verdict":"invalid","reason":"..."}`
//!         | `{"verdict":"skipped","reason":"..."}`
//!
//! The governing asymmetry carried over unchanged from `primitives::
//! brainpool` (this module's direct predecessor): every way this client
//! fails to get a clean verdict out of the sidecar PROCESS itself -- a spawn
//! failure, a timeout, a non-zero exit, an I/O error, or output that is not
//! one of the three well-formed verdict shapes above -- must produce
//! `Verdict::Skipped`, never `Verdict::Invalid`. Only an explicit
//! `{"verdict":"invalid",...}` may become `Verdict::Invalid`. A single one of
//! those failure modes landing on `Invalid` instead of `Skipped` would reject
//! every request the moment the sidecar breaks -- a mass false-reject, this
//! project's defined production outage. Every branch below that produces
//! `Skipped` for a process-level reason (as opposed to `verify.mjs` itself
//! choosing to skip) also calls `metrics::record_sidecar_unavailable`, same
//! convention as `primitives::brainpool` -- see this module's tests for the
//! full enumeration.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::metrics;
use super::Verdict;

/// The in-image sidecar path, matching `Dockerfile.tee`'s final stage
/// (`COPY signature-verifier /signature-verifier`). `resolved_sidecar_script`
/// uses this when present; tests that want an explicit stub still point
/// `verify_with` at one directly.
pub const DEFAULT_SIDECAR_SCRIPT: &str = "/signature-verifier/verify.mjs";

/// Generous relative to a Groth16 proving step measured in minutes -- this
/// only needs to bound a `node` process doing a handful of `node:crypto`
/// calls, not compete with proving on latency.
const DEFAULT_SIDECAR_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolves the script path `verify` hands to the sidecar.
///
/// `DEFAULT_SIDECAR_SCRIPT` exists only inside the production container:
/// `Dockerfile.tee`'s builder stage compiles with `WORKDIR /src`, so
/// `CARGO_MANIFEST_DIR` (baked into the binary at *build* time by the `env!`
/// macro below) is `/src` there, but the final stage never copies `/src`
/// into the image -- only the compiled binary and, separately,
/// `COPY signature-verifier /signature-verifier`. So `DEFAULT_SIDECAR_SCRIPT`
/// is reachable in the real container and nowhere else: not a laptop, not
/// CI, not this crate's own `cargo test` run.
///
/// `real_fixtures.rs`'s tests need `verify` itself (not just this module's
/// own `verify_with`-parameterised tests) to reach the *real* sidecar,
/// because they go through the full public `verify_inputs` entry point --
/// the only way to prove the fixture guarantees end to end, not just against
/// stub scripts. So when `DEFAULT_SIDECAR_SCRIPT` is absent, this falls back
/// to the crate's own checked-in `signature-verifier/verify.mjs`, resolved
/// from `CARGO_MANIFEST_DIR` -- a compile-time constant, not a runtime
/// environment-variable read, so there is no test-order race: for any given
/// build of this binary the choice is fixed once, identically for every
/// test, before any test body runs.
///
/// A production container always has `DEFAULT_SIDECAR_SCRIPT` present, so
/// this changes nothing there: `exists()` is true on the very first branch,
/// every time, and `resolved_sidecar_script()` returns exactly
/// `DEFAULT_SIDECAR_SCRIPT` unchanged.
fn resolved_sidecar_script() -> String {
    if std::path::Path::new(DEFAULT_SIDECAR_SCRIPT).exists() {
        DEFAULT_SIDECAR_SCRIPT.to_string()
    } else {
        format!("{}/signature-verifier/verify.mjs", env!("CARGO_MANIFEST_DIR"))
    }
}

/// The sidecar's response shape, tagged on its own `verdict` field -- unlike
/// `primitives::brainpool`'s old `{"valid":bool}`/`{"error":...}` contract,
/// there is no ambiguity to guard against here: `#[serde(tag = "verdict")]`
/// picks the variant directly off the field's value, so a payload that
/// somehow carried extra keys still resolves unambiguously rather than
/// falling through an untagged match order.
#[derive(Deserialize, Debug)]
#[serde(tag = "verdict", rename_all = "lowercase")]
enum SidecarResponse {
    Valid,
    Invalid { reason: String },
    Skipped { reason: String },
}

/// Parses the sidecar's stdout into a `Verdict` directly. Empty output,
/// output that isn't JSON, or JSON that isn't one of the three tagged
/// shapes above all become `Verdict::Skipped` (and count as a sidecar-
/// unavailable event) -- only a well-formed `{"verdict":"invalid",...}`
/// produces `Verdict::Invalid`.
fn parse_response(raw: &[u8]) -> Verdict {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        metrics::record_sidecar_unavailable();
        return Verdict::Skipped("signature-verifier sidecar produced no output".to_string());
    }
    match serde_json::from_str::<SidecarResponse>(trimmed) {
        Ok(SidecarResponse::Valid) => Verdict::Valid,
        Ok(SidecarResponse::Invalid { reason }) => Verdict::Invalid(reason),
        Ok(SidecarResponse::Skipped { reason }) => Verdict::Skipped(reason),
        Err(e) => {
            metrics::record_sidecar_unavailable();
            Verdict::Skipped(format!(
                "signature-verifier sidecar returned unparseable output: {e} (raw: {trimmed:?})"
            ))
        }
    }
}

/// Writes `stdin_bytes` to the child, closes its stdin so the sidecar's own
/// `stdin.on('end', ...)` fires, reads stdout to completion, then waits for
/// exit. Takes `&mut Child` (rather than owning it) specifically so a caller
/// wrapping this in `tokio::time::timeout` still holds the child after a
/// timeout, and can kill it -- see `talk_to_sidecar`'s only caller,
/// `run_sidecar`, for why that matters.
async fn talk_to_sidecar(
    child: &mut Child,
    stdin_bytes: Vec<u8>,
) -> std::io::Result<(Vec<u8>, std::process::ExitStatus)> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("child has no piped stdin"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("child has no piped stdout"))?;

    stdin.write_all(&stdin_bytes).await?;
    // Dropping the write half closes the pipe, which is what makes the
    // sidecar's stdin 'end' event fire.
    drop(stdin);

    let mut out = Vec::new();
    stdout.read_to_end(&mut out).await?;
    let status = child.wait().await?;
    Ok((out, status))
}

/// Spawns `node <script_path>`, feeds it `stdin_bytes`, and returns its
/// stdout -- or a `Verdict::Skipped` for every way that can fail to produce
/// a clean answer within `sidecar_timeout`: the spawn itself failing (missing
/// script, missing `node`), a non-zero exit, an I/O error talking to the
/// child, or the whole exchange not finishing in time. On a timeout this
/// kills the child rather than leaving it running -- `talk_to_sidecar`
/// borrows `child` rather than consuming it for exactly this reason: once
/// `timeout` drops the timed-out future, that borrow ends and `child` is
/// still here to kill.
async fn run_sidecar(
    script_path: &str,
    sidecar_timeout: Duration,
    stdin_bytes: Vec<u8>,
) -> Result<Vec<u8>, Verdict> {
    let mut child = Command::new("node")
        .arg(script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            metrics::record_sidecar_unavailable();
            Verdict::Skipped(format!(
                "failed to spawn signature-verifier sidecar (node {script_path}): {e}"
            ))
        })?;

    match timeout(sidecar_timeout, talk_to_sidecar(&mut child, stdin_bytes)).await {
        Ok(Ok((stdout, status))) => {
            if !status.success() {
                metrics::record_sidecar_unavailable();
                return Err(Verdict::Skipped(format!(
                    "signature-verifier sidecar exited with status {status}"
                )));
            }
            Ok(stdout)
        }
        Ok(Err(io_err)) => {
            let _ = child.kill().await;
            metrics::record_sidecar_unavailable();
            Err(Verdict::Skipped(format!(
                "signature-verifier sidecar I/O error: {io_err}"
            )))
        }
        Err(_elapsed) => {
            // The `talk_to_sidecar` future (and its borrow of `child`) was
            // just dropped by `timeout`, so `child` is available again here.
            let _ = child.kill().await;
            metrics::record_sidecar_unavailable();
            Err(Verdict::Skipped(format!(
                "signature-verifier sidecar timed out after {sidecar_timeout:?}"
            )))
        }
    }
}

/// The fully-parameterised entry point: `verify` is this with the
/// production script path and timeout baked in. Tests call this directly to
/// point at stub scripts or the checked-in real sidecar explicitly.
async fn verify_with(
    script_path: &str,
    sidecar_timeout: Duration,
    circuit_name: &str,
    input_path: &Path,
) -> Verdict {
    let payload = serde_json::json!({
        "circuit": circuit_name,
        "inputPath": input_path.to_string_lossy(),
    });
    let stdin_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            return Verdict::Skipped(format!(
                "failed to encode signature-verifier sidecar request: {e}"
            ))
        }
    };

    match run_sidecar(script_path, sidecar_timeout, stdin_bytes).await {
        Ok(stdout) => parse_response(&stdout),
        Err(verdict) => verdict,
    }
}

/// Verifies `circuit_name` against `input_path` (the already-written
/// `input.json`) via the Node `signature-verifier` sidecar at
/// `resolved_sidecar_script()` (`DEFAULT_SIDECAR_SCRIPT` in production; see
/// that function's doc comment for the dev-checkout fallback). Called from
/// `dispatch`'s generic branch (every circuit except `register_kyc`).
pub async fn verify(circuit_name: &str, input_path: &Path) -> Verdict {
    verify_with(&resolved_sidecar_script(), DEFAULT_SIDECAR_TIMEOUT, circuit_name, input_path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generous enough to absorb `node`'s own cold-start cost under a busy
    // test run. Production uses `DEFAULT_SIDECAR_TIMEOUT` via `verify`.
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    // Deliberately much shorter than `TEST_TIMEOUT`, used only by the "sidecar
    // hangs" test below -- that stub never exits on its own, so this is the
    // one test that actually waits out its timeout; keeping it short keeps
    // the suite fast without weakening the other tests' headroom.
    const HANG_TEST_TIMEOUT: Duration = Duration::from_millis(300);

    fn stub_path(name: &str) -> String {
        format!("{}/tests/fixtures/sidecar-stubs/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    // The real sidecar script, for the tests that exercise it directly
    // rather than through a stub.
    fn real_sidecar_path() -> String {
        format!("{}/signature-verifier/verify.mjs", env!("CARGO_MANIFEST_DIR"))
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
    }

    /// Writes `inputs` to a fresh temp dir as `input.json`, returning its
    /// path. Callers are responsible for nothing -- these are scratch files
    /// under the OS temp dir, not the crate's own `tmp_<uuid>` convention
    /// (that convention belongs to `mod.rs`'s `verify_inputs`, exercised
    /// separately in `real_fixtures.rs`).
    fn write_temp_input(inputs: &serde_json::Value) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sidecar-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("input.json");
        std::fs::write(&path, inputs.to_string()).expect("write input.json");
        path
    }

    // -------------------------------------------------------------------
    // End-to-end against the real sidecar: proves the whole wire contract
    // (circuit name + inputPath in, a valid/invalid verdict out), not just
    // that stub scripts are handled correctly.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn a_real_fixture_verifies_valid_through_the_real_sidecar() {
        let raw = std::fs::read_to_string(fixture_path("register_passport.json")).expect("fixture present");
        let inputs: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let path = write_temp_input(&inputs);

        let v = verify_with(
            &real_sidecar_path(),
            TEST_TIMEOUT,
            "register_sha256_sha256_sha256_rsa_3_4096",
            &path,
        )
        .await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert_eq!(v, Verdict::Valid, "expected a real, untampered fixture to verify");
    }

    #[tokio::test]
    async fn a_tampered_fixture_is_invalid_through_the_real_sidecar() {
        let raw = std::fs::read_to_string(fixture_path("register_passport.json")).expect("fixture present");
        let mut inputs: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let arr = inputs["signature_passport"].as_array_mut().expect("array field");
        arr[0] = serde_json::Value::String("1".to_string());
        let path = write_temp_input(&inputs);

        let v = verify_with(
            &real_sidecar_path(),
            TEST_TIMEOUT,
            "register_sha256_sha256_sha256_rsa_3_4096",
            &path,
        )
        .await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Invalid(_)), "expected a tampered signature to be Invalid, got {v:?}");
    }

    // -------------------------------------------------------------------
    // The eight proven sidecar-process failure modes, carried over from
    // `primitives::brainpool`: every one must produce `Verdict::Skipped`,
    // never `Verdict::Invalid`.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn a_missing_script_is_skipped() {
        let path = write_temp_input(&serde_json::json!({}));
        let v = verify_with(
            "/does/not/exist/verify.mjs",
            TEST_TIMEOUT,
            "register_sha256_sha256_sha256_rsa_3_4096",
            &path,
        )
        .await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Skipped(_)), "expected Skipped, got {v:?}");
    }

    #[tokio::test]
    async fn a_hanging_sidecar_is_skipped() {
        let path = write_temp_input(&serde_json::json!({}));
        let v = verify_with(&stub_path("hang.mjs"), HANG_TEST_TIMEOUT, "any_circuit", &path).await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Skipped(_)), "expected Skipped, got {v:?}");
    }

    #[tokio::test]
    async fn garbage_stdout_is_skipped() {
        let path = write_temp_input(&serde_json::json!({}));
        let v = verify_with(&stub_path("garbage.mjs"), TEST_TIMEOUT, "any_circuit", &path).await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Skipped(_)), "expected Skipped, got {v:?}");
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_skipped() {
        let path = write_temp_input(&serde_json::json!({}));
        let v = verify_with(&stub_path("nonzero-exit.mjs"), TEST_TIMEOUT, "any_circuit", &path).await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Skipped(_)), "expected Skipped, got {v:?}");
    }

    #[tokio::test]
    async fn a_malformed_response_is_skipped() {
        // Well-formed JSON, but not one of the three tagged verdict shapes.
        let path = write_temp_input(&serde_json::json!({}));
        let v = verify_with(&stub_path("error-response.mjs"), TEST_TIMEOUT, "any_circuit", &path).await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Skipped(_)), "expected Skipped, got {v:?}");
    }

    #[tokio::test]
    async fn empty_stdout_is_skipped() {
        let path = write_temp_input(&serde_json::json!({}));
        let v = verify_with(&stub_path("empty.mjs"), TEST_TIMEOUT, "any_circuit", &path).await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Skipped(_)), "expected Skipped, got {v:?}");
    }

    #[tokio::test]
    async fn every_sidecar_unavailable_failure_mode_increments_the_counter() {
        let cases: &[&str] = &["hang.mjs", "garbage.mjs", "nonzero-exit.mjs", "error-response.mjs", "empty.mjs"];
        for name in cases {
            let path = write_temp_input(&serde_json::json!({}));
            let before = metrics::sidecar_unavailable_count();
            let sidecar_timeout = if *name == "hang.mjs" { HANG_TEST_TIMEOUT } else { TEST_TIMEOUT };
            let v = verify_with(&stub_path(name), sidecar_timeout, "any_circuit", &path).await;
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
            assert!(matches!(v, Verdict::Skipped(_)), "{name}: expected Skipped, got {v:?}");
            assert!(
                metrics::sidecar_unavailable_count() >= before + 1,
                "{name}: must increment the sidecar-unavailable counter"
            );
        }

        // A missing script also counts -- covered by the non-zero-exit path
        // in run_sidecar (node itself spawns fine, but MODULE_NOT_FOUND exits
        // 1), not a spawn failure, since `node` itself is present on this
        // machine.
        let path = write_temp_input(&serde_json::json!({}));
        let before = metrics::sidecar_unavailable_count();
        let v = verify_with("/does/not/exist/verify.mjs", TEST_TIMEOUT, "any_circuit", &path).await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(matches!(v, Verdict::Skipped(_)));
        assert!(metrics::sidecar_unavailable_count() >= before + 1);
    }

    // -------------------------------------------------------------------
    // resolved_sidecar_script / the public entry point's dev-checkout
    // fallback.
    // -------------------------------------------------------------------

    #[test]
    fn resolved_sidecar_script_falls_back_to_the_checked_in_copy() {
        assert!(!std::path::Path::new(DEFAULT_SIDECAR_SCRIPT).exists());
        assert_eq!(resolved_sidecar_script(), real_sidecar_path());
    }

    #[tokio::test]
    async fn verify_falls_back_to_the_checked_in_sidecar_when_the_image_path_is_absent() {
        assert!(
            !std::path::Path::new(DEFAULT_SIDECAR_SCRIPT).exists(),
            "this test's premise is that the in-image path is absent on a dev checkout; if \
             that ever changes, the fallback branch this test exercises would go untested \
             instead of failing loudly"
        );
        let raw = std::fs::read_to_string(fixture_path("register_passport.json")).expect("fixture present");
        let inputs: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let path = write_temp_input(&inputs);

        let v = verify("register_sha256_sha256_sha256_rsa_3_4096", &path).await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert_eq!(v, Verdict::Valid, "expected the fallback path to genuinely verify a valid fixture");
    }
}
