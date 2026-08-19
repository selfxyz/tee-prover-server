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
//! Not yet wired into `passport.rs`/`dsc.rs`'s dispatch -- that is Task 3.
//! Until then several items here are unused outside this module's own tests,
//! hence the scattered `#[cfg_attr(not(test), allow(dead_code))]`.

use std::process::Stdio;
use std::time::Duration;

use num_bigint::BigUint;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::ecdsa::EcdsaError;

/// The four brainpool curves used by the 20 circuits no Rust crate covers.
/// Not yet constructed outside this module's own tests -- Task 3 wires
/// `from_name`'s output into dispatch.
#[cfg_attr(not(test), allow(dead_code))]
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
    #[cfg_attr(not(test), allow(dead_code))]
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

/// The in-image sidecar path, matching Task 1's `Dockerfile.tee` placement.
/// `verify_brainpool` uses this; tests point `verify_brainpool_with` at stub
/// scripts instead.
#[cfg_attr(not(test), allow(dead_code))]
pub const DEFAULT_SIDECAR_SCRIPT: &str = "/brainpool-verifier/verify.mjs";

/// Generous relative to a Groth16 proving step measured in minutes -- this
/// only needs to bound a `node` process doing one OpenSSL call, not compete
/// with it on latency.
const DEFAULT_SIDECAR_TIMEOUT: Duration = Duration::from_secs(10);

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
#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum SidecarResponse {
    Result { valid: bool },
    Error { error: String },
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
        return Err(EcdsaError::Structural(
            "brainpool sidecar produced no output".to_string(),
        ));
    }
    let parsed: SidecarResponse = serde_json::from_str(trimmed).map_err(|e| {
        EcdsaError::Structural(format!(
            "brainpool sidecar returned unparseable output: {e} (raw: {trimmed:?})"
        ))
    })?;
    match parsed {
        SidecarResponse::Error { error } => Err(EcdsaError::Structural(format!(
            "brainpool sidecar reported: {error}"
        ))),
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
            EcdsaError::Structural(format!(
                "failed to spawn brainpool sidecar (node {script_path}): {e}"
            ))
        })?;

    match timeout(sidecar_timeout, talk_to_sidecar(&mut child, stdin_bytes)).await {
        Ok(Ok((stdout, status))) => {
            if !status.success() {
                return Err(EcdsaError::Structural(format!(
                    "brainpool sidecar exited with status {status}"
                )));
            }
            Ok(stdout)
        }
        Ok(Err(io_err)) => {
            let _ = child.kill().await;
            Err(EcdsaError::Structural(format!(
                "brainpool sidecar I/O error: {io_err}"
            )))
        }
        Err(_elapsed) => {
            // The `talk_to_sidecar` future (and its borrow of `child`) was
            // just dropped by `timeout`, so `child` is available again here.
            let _ = child.kill().await;
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
/// Node/OpenSSL sidecar at `DEFAULT_SIDECAR_SCRIPT`. `message` is the
/// recovered message *bytes*, not a digest -- the sidecar hashes and
/// truncates it itself, deliberately keeping ECDSA's `bits2int` truncation
/// semantics out of this interface. `hash_bits` is the same `sig_hash` width
/// `params.rs` already carries per circuit (160/224/256/384/512).
///
/// `Ok(())` -- verified. `Err(EcdsaError::Structural(_))` -- the sidecar
/// could not be reached or did not give a clean answer; the caller must map
/// this to `Verdict::Skipped`. `Err(EcdsaError::Failed(_))` -- the sidecar
/// affirmatively rejected the signature; the caller maps this to
/// `Verdict::Invalid`. See this module's doc comment for why that split is
/// the entire point of this client.
#[cfg_attr(not(test), allow(dead_code))]
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
        DEFAULT_SIDECAR_SCRIPT,
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

    #[tokio::test]
    async fn verify_brainpool_routes_through_the_documented_default_path() {
        // `DEFAULT_SIDECAR_SCRIPT` is the in-image path baked into the public
        // entry point; it does not exist on the machine running this test,
        // so this both exercises `verify_brainpool` itself (otherwise unused
        // outside production dispatch, which is Task 3) and doubles as a
        // "script missing" case through the real public API.
        let (x, y, r, s) = valid_vector();
        let err = verify_brainpool(BrainpoolCurve::P256r1, &x, &y, &r, &s, MESSAGE, 256)
            .await
            .expect_err("the default path does not exist on this machine");
        assert!(
            matches!(err, EcdsaError::Structural(_)),
            "expected Structural, got {err:?}"
        );
    }
}
