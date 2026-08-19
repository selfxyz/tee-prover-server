//! Native ECDSA pre-check for the brainpoolP{224,256,384,512}r1 circuits.
//!
//! No usable Rust crate covers these curves (see `brainpool-verifier/verify.mjs`'s
//! header comment for the survey), so this module shells out to a Node
//! sidecar that leans on OpenSSL's own brainpool support instead. This module
//! is the Rust side of that contract: it hex-encodes the limb-reassembled
//! coordinates, spawns `node <script>` per request, and maps the sidecar's
//! `{"valid":true|false}` / `{"error":...}` response onto `EcdsaError`.
//!
//! The governing asymmetry (see `primitives::ecdsa`'s module doc) still
//! applies here, harder than anywhere else in this crate: brainpool circuits
//! are skipped entirely today, so *any* way this client fails to get a clean
//! answer out of the sidecar -- missing script, hung process, garbage
//! output, non-zero exit, an `{"error":...}` payload -- must land on
//! `EcdsaError::Structural`, which the caller maps to `Verdict::Skipped`,
//! exactly where production already is. Only an explicit `{"valid":false}`
//! may become `EcdsaError::Failed`, which the caller maps to
//! `Verdict::Invalid`. A single failure mode here landing on `Failed` instead
//! of `Structural` would reject every brainpool request the moment the
//! sidecar breaks -- a mass false-reject, this project's defined production
//! outage.
//!
//! Wired into `passport.rs`/`dsc.rs`'s dispatch as of Task 3, via
//! `Scheme::EcdsaBrainpool`. Both call sites are synchronous, so they reach
//! `verify_brainpool` through `tokio::runtime::Handle::current().block_on(...)`
//! -- safe only because `mod::verify_inputs` now runs `dispatch` inside
//! `tokio::task::spawn_blocking`, a blocking-pool thread rather than an async
//! worker thread. See `mod.rs`'s `verify_inputs` for the full reasoning and
//! its own doc comment / tests for the no-deadlock proof.
//!
//! Task 4 (Plan 4): every one of `run_sidecar`/`parse_response`'s
//! `Structural` returns that stems from the sidecar process itself --
//! spawn failure, non-zero exit, an I/O error talking to it, a timeout, or
//! output that isn't a clean `{"valid":bool}`/`{"error":...}` response --
//! also calls `metrics::record_sidecar_unavailable()`, on top of (never
//! instead of) the ordinary `Verdict::Skipped` accounting the caller in
//! `passport.rs`/`dsc.rs` already does. This is the one place production can
//! tell "the sidecar has been dead for a day" apart from "no brainpool
//! traffic arrived today" -- both would otherwise print an identical
//! `skipped=N` line, since brainpool is the only thing the sidecar serves.
//! Request-shape problems caught before a process is ever spawned (an
//! oversized coordinate, an unmappable hash width) are deliberately NOT
//! counted here -- those are not evidence the sidecar is unreachable.

use std::process::Stdio;
use std::time::Duration;

use num_bigint::BigUint;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::ecdsa::EcdsaError;
use crate::verifier::metrics;

/// The four brainpool curves used by the 20 circuits no Rust crate covers.
/// Constructed by `passport.rs`/`dsc.rs`'s dispatch (via `from_name`, from
/// `Scheme::EcdsaBrainpool`'s curve name) as of Task 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrainpoolCurve {
    P224r1,
    P256r1,
    P384r1,
    P512r1,
}

impl BrainpoolCurve {
    /// Parses the circuit name's own trailing curve component, e.g.
    /// `"brainpoolP256r1"` -- the same string `params.rs` extracts for the
    /// NIST curves' `Curve::from_name` (`ecdsa.rs`), and, not by accident,
    /// exactly the sidecar's own `curve` key (see `verify.mjs`'s `CURVES`
    /// map): both sides read the identical circuit-name substring, so no
    /// translation table is needed between them.
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "brainpoolP224r1" => BrainpoolCurve::P224r1,
            "brainpoolP256r1" => BrainpoolCurve::P256r1,
            "brainpoolP384r1" => BrainpoolCurve::P384r1,
            "brainpoolP512r1" => BrainpoolCurve::P512r1,
            _ => return None,
        })
    }

    /// Field width in bytes: 28 / 32 / 48 / 64 -- unlike the NIST curves'
    /// secp521r1 (66 bytes), every brainpool field width here is byte-aligned
    /// to begin with, per RFC 5639.
    pub fn field_bytes(self) -> usize {
        match self {
            BrainpoolCurve::P224r1 => 28,
            BrainpoolCurve::P256r1 => 32,
            BrainpoolCurve::P384r1 => 48,
            BrainpoolCurve::P512r1 => 64,
        }
    }

    /// The sidecar's `curve` wire name. Kept as a separate method from
    /// `from_name`'s match (rather than deriving one from the other) so
    /// either direction stays a straightforward literal `match`, matching
    /// this module's other curve tables.
    fn wire_name(self) -> &'static str {
        match self {
            BrainpoolCurve::P224r1 => "brainpoolP224r1",
            BrainpoolCurve::P256r1 => "brainpoolP256r1",
            BrainpoolCurve::P384r1 => "brainpoolP384r1",
            BrainpoolCurve::P512r1 => "brainpoolP512r1",
        }
    }
}

/// The in-image sidecar path, matching Task 1's `Dockerfile.tee` placement
/// (`COPY brainpool-verifier /brainpool-verifier` in its final stage).
/// `resolved_sidecar_script` uses this when present; tests that want an
/// explicit stub still point `verify_brainpool_with` at one directly.
pub const DEFAULT_SIDECAR_SCRIPT: &str = "/brainpool-verifier/verify.mjs";

/// Generous relative to a Groth16 proving step measured in minutes -- this
/// only needs to bound a `node` process doing one OpenSSL call, not compete
/// with it on latency.
const DEFAULT_SIDECAR_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolves the script path `verify_brainpool` -- the function `passport.rs`/
/// `dsc.rs`'s dispatch arms actually call -- hands to the sidecar.
///
/// `DEFAULT_SIDECAR_SCRIPT` exists only inside the production container:
/// `Dockerfile.tee`'s builder stage compiles with `WORKDIR /src`, so
/// `CARGO_MANIFEST_DIR` (baked into the binary at *build* time by the `env!`
/// macro below) is `/src` there, but the final stage never copies `/src`
/// into the image -- only the compiled binary and, separately,
/// `COPY brainpool-verifier /brainpool-verifier`. So `DEFAULT_SIDECAR_SCRIPT`
/// is reachable in the real container and nowhere else: not a laptop, not
/// CI, not this crate's own `cargo test` run.
///
/// Task 4 (Plan 4)'s real-fixture gate needs `verify_brainpool` itself (not
/// just this module's own `verify_brainpool_with`-parameterised tests) to
/// reach the *real* sidecar, because `real_fixtures.rs`'s brainpool tests
/// and its tamper-table guarantee both go through the full `passport::verify`
/// / `dsc::verify` dispatch chain -- the only way to also prove the tamper
/// test's guarantee for these rows, not just this module's own unit tests.
/// So when `DEFAULT_SIDECAR_SCRIPT` is absent, this falls back to the
/// crate's own checked-in `brainpool-verifier/verify.mjs`, resolved from
/// `CARGO_MANIFEST_DIR` -- a compile-time constant, not a runtime
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
        format!("{}/brainpool-verifier/verify.mjs", env!("CARGO_MANIFEST_DIR"))
    }
}

/// Left-pads `v` to exactly `width` bytes, big-endian, then hex-encodes it.
/// `Err(Structural)` if `v` needs more than `width` bytes -- silently
/// truncating instead would let an oversized coordinate masquerade as a
/// valid, different (and shorter) one, which is exactly the false-reject
/// shape this module exists to avoid; see `ecdsa.rs`'s `coord_bytes` for the
/// same reasoning applied to the NIST curves.
fn hex_field(v: &BigUint, width: usize) -> Result<String, EcdsaError> {
    let raw = v.to_bytes_be();
    if raw.len() > width {
        return Err(EcdsaError::Structural(format!(
            "coordinate is {} bytes, wider than the field ({width})",
            raw.len()
        )));
    }
    let mut out = vec![0u8; width - raw.len()];
    out.extend_from_slice(&raw);
    Ok(to_hex(&out))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Maps a `sig_hash` bit width (`params.rs`'s `CircuitParams::sig_hash`) to
/// the sidecar's hash name. `None` for an unmappable width -- the caller
/// turns that into `Structural`, never a guess.
fn hash_name(hash_bits: u32) -> Option<&'static str> {
    Some(match hash_bits {
        160 => "sha1",
        224 => "sha224",
        256 => "sha256",
        384 => "sha384",
        512 => "sha512",
        _ => return None,
    })
}

/// The sidecar's response shape: `{"valid":true|false}` or `{"error":...}`.
/// `untagged` tries each variant in declaration order against the same JSON
/// value, so this one `enum` covers both without a wrapper struct.
///
/// `Error` is declared first, deliberately: serde's untagged deserializer
/// tries variants top-to-bottom and commits to the first one whose fields
/// all match, so a malformed payload that happens to carry both keys --
/// e.g. `{"valid":false,"error":"spawn broke"}`, which the checked-in
/// `verify.mjs` never emits, but nothing in this type stopped it either --
/// would previously have matched `Result` first and silently become
/// `Ok(false)`/`EcdsaError::Failed` (a false reject) instead of `Structural`.
/// With `Error` first, that same payload matches `Error` instead, and only a
/// payload with `valid` and no `error` key can ever reach `Result`. See
/// `an_error_and_valid_payload_is_structural_not_a_verdict` below, which
/// pins this ordering behaviourally rather than trusting the doc comment.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum SidecarResponse {
    Error { error: String },
    Result { valid: bool },
}

/// Parses the sidecar's stdout. `Ok(true)`/`Ok(false)` for an actual
/// verdict; `Err(Structural)` for anything else -- empty output, output that
/// isn't JSON, JSON that isn't this shape, or an explicit `{"error":...}`.
/// Note there is deliberately no path here that returns `Failed` other than
/// `Ok(false)` at the call site: this function cannot itself distinguish "the
/// sidecar rejected the signature" from "the sidecar is broken" for anything
/// other than a well-formed `{"valid":false}`.
fn parse_response(raw: &[u8]) -> Result<bool, EcdsaError> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        metrics::record_sidecar_unavailable();
        return Err(EcdsaError::Structural(
            "brainpool sidecar produced no output".to_string(),
        ));
    }
    let parsed: SidecarResponse = serde_json::from_str(trimmed).map_err(|e| {
        metrics::record_sidecar_unavailable();
        EcdsaError::Structural(format!(
            "brainpool sidecar returned unparseable output: {e} (raw: {trimmed:?})"
        ))
    })?;
    match parsed {
        SidecarResponse::Error { error } => {
            metrics::record_sidecar_unavailable();
            Err(EcdsaError::Structural(format!(
                "brainpool sidecar reported: {error}"
            )))
        }
        SidecarResponse::Result { valid } => Ok(valid),
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
/// stdout -- or `Structural` for every way that can fail to produce a clean
/// answer within `sidecar_timeout`: the spawn itself failing (missing
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
) -> Result<Vec<u8>, EcdsaError> {
    let mut child = Command::new("node")
        .arg(script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            metrics::record_sidecar_unavailable();
            EcdsaError::Structural(format!(
                "failed to spawn brainpool sidecar (node {script_path}): {e}"
            ))
        })?;

    match timeout(sidecar_timeout, talk_to_sidecar(&mut child, stdin_bytes)).await {
        Ok(Ok((stdout, status))) => {
            if !status.success() {
                metrics::record_sidecar_unavailable();
                return Err(EcdsaError::Structural(format!(
                    "brainpool sidecar exited with status {status}"
                )));
            }
            Ok(stdout)
        }
        Ok(Err(io_err)) => {
            let _ = child.kill().await;
            metrics::record_sidecar_unavailable();
            Err(EcdsaError::Structural(format!(
                "brainpool sidecar I/O error: {io_err}"
            )))
        }
        Err(_elapsed) => {
            // The `talk_to_sidecar` future (and its borrow of `child`) was
            // just dropped by `timeout`, so `child` is available again here.
            let _ = child.kill().await;
            metrics::record_sidecar_unavailable();
            Err(EcdsaError::Structural(format!(
                "brainpool sidecar timed out after {sidecar_timeout:?}"
            )))
        }
    }
}

/// The fully-parameterised entry point: `verify_brainpool` is this with the
/// production script path and timeout baked in. Tests call this directly to
/// point at stub scripts (and, for the hang case, a much shorter timeout) --
/// see this module's `tests` submodule.
async fn verify_brainpool_with(
    script_path: &str,
    sidecar_timeout: Duration,
    curve: BrainpoolCurve,
    x: &BigUint,
    y: &BigUint,
    r: &BigUint,
    s: &BigUint,
    message: &[u8],
    hash_bits: u32,
) -> Result<(), EcdsaError> {
    let width = curve.field_bytes();
    let hash = hash_name(hash_bits).ok_or_else(|| {
        EcdsaError::Structural(format!(
            "unmappable hash width for brainpool sidecar: {hash_bits} bits"
        ))
    })?;

    let x_hex = hex_field(x, width)?;
    let y_hex = hex_field(y, width)?;
    let r_hex = hex_field(r, width)?;
    let s_hex = hex_field(s, width)?;
    let message_hex = to_hex(message);

    let payload = serde_json::json!({
        "curve": curve.wire_name(),
        "x": x_hex,
        "y": y_hex,
        "r": r_hex,
        "s": s_hex,
        "message": message_hex,
        "hash": hash,
    });
    let stdin_bytes = serde_json::to_vec(&payload).map_err(|e| {
        EcdsaError::Structural(format!("failed to encode brainpool sidecar request: {e}"))
    })?;

    let stdout = run_sidecar(script_path, sidecar_timeout, stdin_bytes).await?;

    if parse_response(&stdout)? {
        Ok(())
    } else {
        Err(EcdsaError::Failed(
            "brainpool sidecar rejected the signature".to_string(),
        ))
    }
}

/// Verifies an ECDSA signature over one of the four brainpool curves via the
/// Node/OpenSSL sidecar at `resolved_sidecar_script()` (`DEFAULT_SIDECAR_
/// SCRIPT` in production; see that function's doc comment for the dev-
/// checkout fallback). `message` is the recovered message *bytes*, not a
/// digest -- the sidecar hashes and truncates it itself, deliberately
/// keeping ECDSA's `bits2int` truncation semantics out of this interface.
/// `hash_bits` is the same `sig_hash` width `params.rs` already carries per
/// circuit (160/224/256/384/512).
///
/// `Ok(())` -- verified. `Err(EcdsaError::Structural(_))` -- the sidecar
/// could not be reached or did not give a clean answer; the caller must map
/// this to `Verdict::Skipped`. `Err(EcdsaError::Failed(_))` -- the sidecar
/// affirmatively rejected the signature; the caller maps this to
/// `Verdict::Invalid`. See this module's doc comment for why that split is
/// the entire point of this client.
pub async fn verify_brainpool(
    curve: BrainpoolCurve,
    x: &BigUint,
    y: &BigUint,
    r: &BigUint,
    s: &BigUint,
    message: &[u8],
    hash_bits: u32,
) -> Result<(), EcdsaError> {
    verify_brainpool_with(
        &resolved_sidecar_script(),
        DEFAULT_SIDECAR_TIMEOUT,
        curve,
        x,
        y,
        r,
        s,
        message,
        hash_bits,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generous enough to absorb `node`'s own cold-start cost under a busy
    // test run (observed ~150ms for a single invocation; several `#[tokio::
    // test]`s spawn `node` concurrently, so this leaves real headroom).
    // Production uses `DEFAULT_SIDECAR_TIMEOUT` via `verify_brainpool`.
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    // Deliberately much shorter than `TEST_TIMEOUT`, used only by the "sidecar
    // hangs" test below -- that stub never exits on its own, so this is the
    // one test that actually waits out its timeout; keeping it short keeps
    // the suite fast without weakening the other tests' headroom.
    const HANG_TEST_TIMEOUT: Duration = Duration::from_millis(300);

    fn stub_path(name: &str) -> String {
        format!(
            "{}/tests/fixtures/brainpool-stubs/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    // The real sidecar script, for the one end-to-end test that exercises it
    // directly rather than through a stub.
    fn real_sidecar_path() -> String {
        format!(
            "{}/brainpool-verifier/verify.mjs",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    // A known-good brainpoolP256r1 / SHA-256 vector, generated with the
    // OpenSSL CLI (`ecparam -genkey`, `dgst -sha256 -sign`) exactly as
    // `brainpool-verifier/verify.test.mjs` generates its own vectors, and
    // independently confirmed against `verify.mjs` itself before being
    // hardcoded here (see task-2-report.md for the generation transcript).
    // Never generated with this crate's own signing logic -- a verifier that
    // only checks signatures it produced itself proves nothing but
    // self-consistency.
    const MESSAGE: &[u8] = b"the quick brown fox jumps over the lazy dog";
    const X_HEX: &str = "789d2f60159c5a0aacba65fa674494b7432027c6f3d440d6333b33a7666c8ab6";
    const Y_HEX: &str = "83866effda416227716d23d6820e9ae57afafac46e39d9b0057a2efaf2a780ec";
    const R_HEX: &str = "7e2ec37fca470b6cdf0cf8f2faf0d9c52b084738359a25c6d33218e1c2704422";
    const S_HEX: &str = "88ef7b45d4d855bad1e7a5ea247a2554e6a21e22f6b43fc4b86bd69d035e8f72";

    fn valid_vector() -> (BigUint, BigUint, BigUint, BigUint) {
        (
            BigUint::parse_bytes(X_HEX.as_bytes(), 16).expect("valid hex"),
            BigUint::parse_bytes(Y_HEX.as_bytes(), 16).expect("valid hex"),
            BigUint::parse_bytes(R_HEX.as_bytes(), 16).expect("valid hex"),
            BigUint::parse_bytes(S_HEX.as_bytes(), 16).expect("valid hex"),
        )
    }

    #[tokio::test]
    async fn a_valid_signature_verifies_against_the_real_sidecar() {
        let (x, y, r, s) = valid_vector();
        let result = verify_brainpool_with(
            &real_sidecar_path(),
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn a_tampered_signature_is_failed_against_the_real_sidecar() {
        let (x, y, r, mut s) = valid_vector();
        s += BigUint::from(1u32); // flip the signature so it no longer verifies
        let err = verify_brainpool_with(
            &real_sidecar_path(),
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("tampered signature must not verify");
        assert!(
            matches!(err, EcdsaError::Failed(_)),
            "expected Failed, got {err:?}"
        );
    }

    /// The 4 remaining (curve, hash) pairings the review flagged as live but
    /// untested end-to-end: algs 30 (brainpoolP224r1/sha224), 36
    /// (brainpoolP256r1/sha1), 37 (brainpoolP384r1/sha256), and 38
    /// (brainpoolP512r1/sha384) -- see
    /// `every_brainpool_row_s_sig_hash_maps_to_the_expected_wire_hash_name`
    /// above for the other 16 rows that reduce to one of these 8 pairings
    /// (or the 4 already covered by `a_valid_signature_verifies_against_the_
    /// real_sidecar` and the real-fixture tests: 21/27/22/29). Each vector
    /// below is generated exactly the same way as `X_HEX`/`Y_HEX`/`R_HEX`/
    /// `S_HEX` above -- OpenSSL CLI (`ecparam -genkey`, `dgst -<hash>
    /// -sign`), reusing the identical `(algorithmId, curve, hash)` pairing
    /// table checked into `brainpool-verifier/verify.test.mjs`'s
    /// `CIRCUIT_CURVE_HASH_PAIRS` (lines 213-220) rather than inventing a
    /// different set of pairings to test -- and independently confirmed
    /// against the real `verify.mjs` (both the vector itself, and that
    /// flipping a nibble of `s` turns the same vector into `{"valid":false}`,
    /// not an error) before being hardcoded here. This calls the real
    /// sidecar, not a stub, so it also proves the composition end to end:
    /// `params.rs`'s `sig_hash` for these rows, through `hash_name`, through
    /// the actual OpenSSL `crypto.verify()` call.
    #[tokio::test]
    async fn each_remaining_curve_hash_pairing_verifies_against_the_real_sidecar() {
        struct Vector {
            algorithm_id: u32,
            curve: BrainpoolCurve,
            hash_bits: u32,
            x: &'static str,
            y: &'static str,
            r: &'static str,
            s: &'static str,
        }
        let vectors = [
            Vector {
                algorithm_id: 30,
                curve: BrainpoolCurve::P224r1,
                hash_bits: 224,
                x: "07ec01ae3598b636f2e00c7cac8e839add6a7b0bb0ebc76a308814217",
                y: "095245315785515b058d9464fe794962bc56573fff465ca01e4814c05",
                r: "07ccbcb5ae965cddfdb555b1f8a35519e9d25016c6bf7b1a817698b96",
                s: "0821ff2c10595c8f66e04684ff55f3ed0bd01c1602ee7f609b7e2bd75",
            },
            Vector {
                algorithm_id: 36,
                curve: BrainpoolCurve::P256r1,
                hash_bits: 160,
                x: "2e2738cf6741d8df025e21d77d822caa31b08ed6dd481a11a83606059c6fe0a3",
                y: "a451bfe6d770fc2d54101050467bcdb8fc5a87175f9f163f56230560df2354c5",
                r: "54efd9537fe1f17345515650a05c7f9d7015d488125761be5c57f24c8acecc0d",
                s: "6f8ba219284058d0ed19aee9aeca86879b4d93fb8ac8cc379dabfec7fc13ac71",
            },
            Vector {
                algorithm_id: 37,
                curve: BrainpoolCurve::P384r1,
                hash_bits: 256,
                x: "361bda69977ff16f7961623a7103a34c785d8ce8046f321f3e62127757840e73cee834a8e1df56e9a2fbcaecd1d3ddd6",
                y: "77ef6d3a86d939a0c99b12aa0b467a4b66775976f2b6489f5adfce629fa6d62257e567bf260a773273cd65064c30da09",
                r: "603b35f024b322d2db4b1f37c88af5a2eb9fc659318056d9c2b97cc2f8cdde7745d63ac16115c25bce3c02d15d7aace5",
                s: "1b153adbd76c8cca3194994b9bb848ca3235492e2ea2c99990a02354d71c0560903f3c210441973f92dbb3f3a7c4be94",
            },
            Vector {
                algorithm_id: 38,
                curve: BrainpoolCurve::P512r1,
                hash_bits: 384,
                x: "141ad2d23d4a367406576e01a3e0952ed6b7ee2741c1659dc1f681383a5f2832f150e884a8b2cff95fa143bb67e9e48852a261b14659441e6a58399f187ebd66",
                y: "9ba608825613a791c86506088998050404286275ae780dcd558c75cedf19eb631af6f1213f4b0daa391617509c715762fe413632bc028bf7cf710b66b21bd7d4",
                r: "45b00db6ceb89474b109937238ef28f00efaa270a0d7384956de3beaf41ac4cfc64ec7b92fd058678bfb4ff9d35db72c85c2feb2875f4a2241bff1e4325ad050",
                s: "943388b92ad3056796471483fe204534c665ac043ed6f3d607fc2d3e1a1d2e94ffd1a68bdf0e7762c6de8bbb33e76aa889724e93b93e05c6c625ca4747ca60d7",
            },
        ];

        for v in vectors {
            let x = BigUint::parse_bytes(v.x.as_bytes(), 16).expect("valid hex");
            let y = BigUint::parse_bytes(v.y.as_bytes(), 16).expect("valid hex");
            let r = BigUint::parse_bytes(v.r.as_bytes(), 16).expect("valid hex");
            let s = BigUint::parse_bytes(v.s.as_bytes(), 16).expect("valid hex");

            let result = verify_brainpool_with(
                &real_sidecar_path(),
                TEST_TIMEOUT,
                v.curve,
                &x,
                &y,
                &r,
                &s,
                MESSAGE,
                v.hash_bits,
            )
            .await;
            assert_eq!(
                result,
                Ok(()),
                "alg {}: expected a valid signature to verify",
                v.algorithm_id
            );

            // Tampering must still turn into Failed (Invalid), never
            // Structural (Skipped) -- same governing-asymmetry check as
            // a_tampered_signature_is_failed_against_the_real_sidecar above,
            // for each of these 4 pairings.
            let mut s_tampered = s.clone();
            s_tampered += BigUint::from(1u32);
            let err = verify_brainpool_with(
                &real_sidecar_path(),
                TEST_TIMEOUT,
                v.curve,
                &x,
                &y,
                &r,
                &s_tampered,
                MESSAGE,
                v.hash_bits,
            )
            .await
            .expect_err("a tampered signature must not verify");
            assert!(
                matches!(err, EcdsaError::Failed(_)),
                "alg {}: expected Failed, got {err:?}",
                v.algorithm_id
            );
        }
    }

    #[tokio::test]
    async fn a_missing_script_is_structural() {
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool_with(
            "/does/not/exist/verify.mjs",
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("missing script must not verify");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_hanging_sidecar_is_structural() {
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool_with(
            &stub_path("hang.mjs"),
            HANG_TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("a hung sidecar must not verify");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }

    #[tokio::test]
    async fn garbage_stdout_is_structural() {
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool_with(
            &stub_path("garbage.mjs"),
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("garbage stdout must not verify");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_structural() {
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool_with(
            &stub_path("nonzero-exit.mjs"),
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("a non-zero exit must not verify");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }

    #[tokio::test]
    async fn an_error_response_is_structural() {
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool_with(
            &stub_path("error-response.mjs"),
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("an {\"error\":...} response must not verify");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }

    #[tokio::test]
    async fn empty_stdout_is_structural() {
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool_with(
            &stub_path("empty.mjs"),
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("empty stdout must not verify");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }

    /// Pins the `SidecarResponse` variant order directly: a payload carrying
    /// both `valid` and `error` -- which the checked-in `verify.mjs` never
    /// emits, but nothing in the type itself ruled out before this reorder
    /// -- must parse as `Error`, not silently match `Result` first and
    /// become an `Ok(false)`/`Invalid` false reject. Exercises
    /// `parse_response` directly rather than through a stub script, since
    /// this is about serde's untagged-enum resolution order, not the
    /// sidecar-unavailable machinery around it.
    #[test]
    fn an_error_and_valid_payload_is_structural_not_a_verdict() {
        let err = parse_response(br#"{"valid":false,"error":"spawn broke"}"#)
            .expect_err("a payload carrying both keys must not be treated as a clean verdict");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural (the Error variant winning), got {err:?}"
        );
    }

    #[test]
    fn from_name_round_trips_all_four_curves() {
        for (name, curve, width) in [
            ("brainpoolP224r1", BrainpoolCurve::P224r1, 28),
            ("brainpoolP256r1", BrainpoolCurve::P256r1, 32),
            ("brainpoolP384r1", BrainpoolCurve::P384r1, 48),
            ("brainpoolP512r1", BrainpoolCurve::P512r1, 64),
        ] {
            assert_eq!(BrainpoolCurve::from_name(name), Some(curve));
            assert_eq!(curve.field_bytes(), width);
            assert_eq!(curve.wire_name(), name);
        }
    }

    #[test]
    fn from_name_rejects_a_nist_curve_name() {
        // The NIST curves' own `Curve::from_name` (`ecdsa.rs`) covers
        // "secp256r1"-style names; this module's `from_name` must not
        // silently accept them (or vice versa) -- the two curve families
        // are handled by entirely different verifiers.
        assert_eq!(BrainpoolCurve::from_name("secp256r1"), None);
        assert_eq!(BrainpoolCurve::from_name("brainpoolP256t1"), None);
        assert_eq!(BrainpoolCurve::from_name(""), None);
    }

    #[test]
    fn an_oversized_coordinate_is_structural_not_truncated() {
        let too_big = BigUint::from(1u32) << 300; // wider than any brainpool field
        let err = hex_field(&too_big, BrainpoolCurve::P256r1.field_bytes())
            .expect_err("an oversized coordinate must not silently truncate");
        assert!(matches!(err, EcdsaError::Structural(_)));
    }

    #[test]
    fn hash_name_covers_all_five_widths_in_use() {
        assert_eq!(hash_name(160), Some("sha1"));
        assert_eq!(hash_name(224), Some("sha224"));
        assert_eq!(hash_name(256), Some("sha256"));
        assert_eq!(hash_name(384), Some("sha384"));
        assert_eq!(hash_name(512), Some("sha512"));
        assert_eq!(hash_name(999), None);
    }

    /// The composition `params::lookup(name).sig_hash -> hash_name -> wire`
    /// for every one of the 20 live brainpool circuits (14 register/
    /// register_id + 6 DSC -- `params.rs`'s `ECDSA_BRAINPOOL_LIMBS` and
    /// `DSC_ECDSA_BRAINPOOL_LIMBS`). Fixture coverage before this only
    /// exercised 4 of the 8 distinct (curve, hash) pairings the table below
    /// spans (algs 21, 22, 27, 29); this test does not need a real sidecar
    /// call to catch a wrong `sig_hash` on a row -- it only needs `params.rs`
    /// and `hash_name` to agree on what wire hash name each row implies -- so
    /// it covers all 20 names, not just the 8 rows the sidecar test below
    /// adds. A mismatch here is exactly the shape of bug described in the
    /// review: a wrong `sig_hash` makes OpenSSL hash with the wrong digest,
    /// which returns a clean `{"valid":false}` and produces `Invalid` for
    /// every document of that circuit -- a false reject.
    #[test]
    fn every_brainpool_row_s_sig_hash_maps_to_the_expected_wire_hash_name() {
        use crate::verifier::params;

        // (circuit name, expected wire hash name) -- expected names taken
        // from `verify.test.mjs`'s CIRCUIT_CURVE_HASH_PAIRS table (the same
        // 8 (curve, hash) pairs), applied to every name that carries each
        // pairing, not just the one row per pairing that table lists.
        let rows: &[(&str, &str)] = &[
            // register / register_id -- alg 27: brainpoolP224r1 / sha1
            ("register_sha1_sha1_sha1_ecdsa_brainpoolP224r1", "sha1"),
            ("register_id_sha1_sha1_sha1_ecdsa_brainpoolP224r1", "sha1"),
            // alg 30: brainpoolP224r1 / sha224
            ("register_sha224_sha224_sha224_ecdsa_brainpoolP224r1", "sha224"),
            ("register_id_sha224_sha224_sha224_ecdsa_brainpoolP224r1", "sha224"),
            // alg 21: brainpoolP256r1 / sha256
            ("register_sha256_sha256_sha256_ecdsa_brainpoolP256r1", "sha256"),
            ("register_id_sha256_sha256_sha256_ecdsa_brainpoolP256r1", "sha256"),
            // alg 37: brainpoolP384r1 / sha256
            ("register_sha256_sha256_sha256_ecdsa_brainpoolP384r1", "sha256"),
            ("register_id_sha256_sha256_sha256_ecdsa_brainpoolP384r1", "sha256"),
            // alg 22: brainpoolP384r1 / sha384
            ("register_sha384_sha384_sha384_ecdsa_brainpoolP384r1", "sha384"),
            ("register_id_sha384_sha384_sha384_ecdsa_brainpoolP384r1", "sha384"),
            // alg 38: brainpoolP512r1 / sha384
            ("register_sha384_sha384_sha384_ecdsa_brainpoolP512r1", "sha384"),
            ("register_id_sha384_sha384_sha384_ecdsa_brainpoolP512r1", "sha384"),
            // alg 29: brainpoolP512r1 / sha512
            ("register_sha512_sha512_sha512_ecdsa_brainpoolP512r1", "sha512"),
            ("register_id_sha512_sha512_sha512_ecdsa_brainpoolP512r1", "sha512"),
            // dsc -- alg 36: brainpoolP256r1 / sha1
            ("dsc_sha1_ecdsa_brainpoolP256r1", "sha1"),
            // alg 21: brainpoolP256r1 / sha256
            ("dsc_sha256_ecdsa_brainpoolP256r1", "sha256"),
            // alg 37: brainpoolP384r1 / sha256
            ("dsc_sha256_ecdsa_brainpoolP384r1", "sha256"),
            // alg 22: brainpoolP384r1 / sha384
            ("dsc_sha384_ecdsa_brainpoolP384r1", "sha384"),
            // alg 38: brainpoolP512r1 / sha384
            ("dsc_sha384_ecdsa_brainpoolP512r1", "sha384"),
            // alg 29: brainpoolP512r1 / sha512
            ("dsc_sha512_ecdsa_brainpoolP512r1", "sha512"),
        ];
        assert_eq!(rows.len(), 20, "must cover all 20 live brainpool circuits, not a subset");

        for (name, expected_wire_hash) in rows {
            let p = params::lookup(name).unwrap_or_else(|| panic!("no CircuitParams for {name}"));
            assert!(
                matches!(p.scheme, params::Scheme::EcdsaBrainpool { .. }),
                "{name}: expected Scheme::EcdsaBrainpool, got {:?}",
                p.scheme
            );
            let got = hash_name(p.sig_hash)
                .unwrap_or_else(|| panic!("{name}: sig_hash {} has no wire hash name", p.sig_hash));
            assert_eq!(got, *expected_wire_hash, "{name}: wire hash name for sig_hash {}", p.sig_hash);
        }
    }

    #[tokio::test]
    async fn an_unmappable_hash_width_is_structural() {
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool_with(
            &real_sidecar_path(),
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            999,
        )
        .await
        .expect_err("an unmappable hash width must not verify");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }

    /// `DEFAULT_SIDECAR_SCRIPT` (the in-image path baked into `verify_
    /// brainpool`, the public entry point `passport.rs`/`dsc.rs`'s dispatch
    /// actually calls) does not exist on the machine running this test --
    /// see `resolved_sidecar_script`'s doc comment for exactly why
    /// (Dockerfile.tee's final stage never copies `/src` into the image, so
    /// this path is reachable only inside the real container). Before Task 4
    /// (Plan 4), that meant this test's only option was to pin the
    /// "in-image path is missing" failure itself, which left `verify_
    /// brainpool` -- as opposed to this module's own `verify_brainpool_with`
    /// -parameterised tests above -- with no coverage that it can ever
    /// reach a *working* sidecar at all. Task 4 needed exactly that
    /// end-to-end path (its real-fixture brainpool tests in
    /// `real_fixtures.rs` go through the full `passport::verify`/
    /// `dsc::verify` dispatch, which calls `verify_brainpool`, not `verify_
    /// brainpool_with`), so `resolved_sidecar_script` now falls back to this
    /// crate's own checked-in `brainpool-verifier/verify.mjs` whenever the
    /// in-image path is absent. This test now pins that fallback directly: a
    /// known-good vector must genuinely verify through the public entry
    /// point on a plain dev checkout, not merely fail predictably.
    #[tokio::test]
    async fn verify_brainpool_falls_back_to_the_checked_in_sidecar_when_the_image_path_is_absent() {
        assert!(
            !std::path::Path::new(DEFAULT_SIDECAR_SCRIPT).exists(),
            "this test's premise is that the in-image path is absent on a dev checkout; if \
             that ever changes, the fallback branch this test exercises would go untested \
             instead of failing loudly"
        );
        let (x, y, r, s) = valid_vector();
        let result = verify_brainpool(BrainpoolCurve::P256r1, &x, &y, &r, &s, MESSAGE, 256).await;
        assert_eq!(result, Ok(()), "expected the fallback path to genuinely verify a valid vector");
    }

    /// Pins `resolved_sidecar_script` directly: on this machine (no
    /// `/brainpool-verifier`), it must return the checked-in path under
    /// `CARGO_MANIFEST_DIR`, not silently fall through to something else.
    #[test]
    fn resolved_sidecar_script_falls_back_to_the_checked_in_copy() {
        assert!(!std::path::Path::new(DEFAULT_SIDECAR_SCRIPT).exists());
        assert_eq!(resolved_sidecar_script(), real_sidecar_path());
    }

    /// Task 4 (Plan 4)'s skip-reason counter: every way this module can fail
    /// to get a clean answer out of the sidecar process (as opposed to the
    /// sidecar cleanly rejecting a signature, or a request-shape problem
    /// caught before the process is ever spawned) must call `metrics::
    /// record_sidecar_unavailable` in addition to returning `Structural`.
    /// Uses `>=`, same convention as `metrics`'s own tests: this is a
    /// process-global counter, so other tests in this same binary may also
    /// be incrementing it concurrently.
    #[tokio::test]
    async fn every_sidecar_unavailable_failure_mode_increments_the_counter() {
        let (x, y, r, s) = valid_vector();
        let cases: &[&str] = &["hang.mjs", "garbage.mjs", "nonzero-exit.mjs", "error-response.mjs", "empty.mjs"];
        for name in cases {
            let before = metrics::sidecar_unavailable_count();
            let sidecar_timeout = if *name == "hang.mjs" { HANG_TEST_TIMEOUT } else { TEST_TIMEOUT };
            let err = verify_brainpool_with(
                &stub_path(name),
                sidecar_timeout,
                BrainpoolCurve::P256r1,
                &x,
                &y,
                &r,
                &s,
                MESSAGE,
                256,
            )
            .await
            .expect_err("every one of these stubs must fail to verify");
            assert!(matches!(err, EcdsaError::Structural(_)), "{name}: expected Structural, got {err:?}");
            assert!(
                metrics::sidecar_unavailable_count() >= before + 1,
                "{name}: must increment the sidecar-unavailable counter"
            );
        }

        // A missing script (Command spawns `node` fine, but node itself
        // exits 1 on MODULE_NOT_FOUND) also counts -- covered by the
        // non-zero-exit path in run_sidecar, not a spawn failure, since
        // `node` itself is present on this machine.
        let before = metrics::sidecar_unavailable_count();
        let err = verify_brainpool_with(
            "/does/not/exist/verify.mjs",
            TEST_TIMEOUT,
            BrainpoolCurve::P256r1,
            &x,
            &y,
            &r,
            &s,
            MESSAGE,
            256,
        )
        .await
        .expect_err("a missing script must not verify");
        assert!(matches!(err, EcdsaError::Structural(_)));
        assert!(metrics::sidecar_unavailable_count() >= before + 1);
    }

    // Deliberately no test asserting that an affirmative {"valid":false}
    // rejection leaves SIDECAR_UNAVAILABLE unchanged: that would need an
    // exact-equality read of a process-global atomic, which -- under cargo
    // test's default parallel execution, with other tests in this same
    // module concurrently incrementing the identical counter -- is exactly
    // the kind of assertion this file's own tests, and metrics.rs's, already
    // avoid (both use ">=", never "==", for this reason). The guarantee
    // itself still holds and is checked by inspection, not a flaky runtime
    // assertion: parse_response's only branch that can produce Ok(false)
    // (which becomes EcdsaError::Failed at the call site in
    // verify_brainpool_with) has no metrics call anywhere near it -- every
    // metrics::record_sidecar_unavailable() call in this file sits inside a
    // Structural-producing branch, enumerated exhaustively by
    // every_sidecar_unavailable_failure_mode_increments_the_counter above.
}
