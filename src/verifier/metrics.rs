//! Global counters for the pre-check's three-valued outcome, and a periodic
//! summary line.
//!
//! Before this, `main.rs`'s `Verdict::Valid => {}` logged nothing and there
//! were no counters at all, so "the pre-check verifies 97% of traffic" and
//! "the pre-check skips everything" were indistinguishable from outside --
//! which is exactly the state that let Aadhaar and KYC ship skipping 100% of
//! real traffic (see `chunks::field_as_strings`) without anyone noticing.
//!
//! This same binary also runs on disclose-only images. Those circuits prove
//! identity-tree membership and selective disclosure and carry no document
//! signature, so `verify.mjs` recognises the four `vc_and_disclose*` names
//! and reports `Valid` for them: a disclose image's expected steady state is
//! a 100% *valid* rate, and a skip there is a red flag exactly as it is on a
//! register image.
//!
//! **This was not always so.** Until the disclose names were recognised,
//! every disclose request skipped, and this doc said a 100% skip rate was
//! expected on such an image. That was accurate while `Skipped` was
//! documented as "never a rejection" -- but once `Skipped` began rejecting
//! under `enforce`, the same 100% rate meant a disclose image rejecting
//! every request, and this paragraph still read as if it were fine. Kept
//! visible rather than quietly rewritten, because the stale invariant is
//! what made the behaviour hard to see.
//!
//! Deliberately three flat `AtomicU64` counters plus a `println!` summary,
//! not the current spec's fuller `(circuit_name, verdict)` breakdown.
//!
//! **Updated 2026-08-19.** An earlier draft of this module doc justified
//! that gap by citing an out-of-scope ruling from the *old* spec
//! (`docs/superpowers/specs/2026-08-18-native-signature-precheck-design.md`).
//! The current spec (`docs/superpowers/specs/2026-08-19-tee-signature-
//! authority-design.md`, "Fail-closed, and how it ships") reverses that
//! ruling: per-circuit metrics are not out of scope, they are a named
//! prerequisite for the enforce-on-known -> enforce transition ("this is
//! what the `(circuit_name, verdict)` metrics debt -- outstanding across all
//! five previous plans -- is finally needed for. **It must be paid here**").
//! It is scheduled, not declined: it is being sequenced deliberately as the
//! next plan's first task, after this fix wave, rather than added here as
//! scope creep on a bug-fix pass. These three flat counters remain the
//! coarse, this-process-lifetime signal until that plan lands.

use std::sync::atomic::{AtomicU64, Ordering};

use super::Verdict;

static VALID: AtomicU64 = AtomicU64::new(0);
static SKIPPED: AtomicU64 = AtomicU64::new(0);
static INVALID: AtomicU64 = AtomicU64::new(0);

/// A subset of `SKIPPED`: counts skips specifically attributable to the
/// `signature-verifier` Node sidecar not producing a clean answer -- a spawn
/// failure, a timeout, a non-zero exit, or output that wasn't one of the
/// three well-formed verdict shapes (see `sidecar::run_sidecar`/
/// `parse_response`, the only call sites of `record_sidecar_unavailable`).
/// NOT incremented for an ordinary skip that has nothing to do with the
/// sidecar being reachable -- an unknown circuit, a missing/malformed field,
/// or `verify.mjs` itself choosing to skip (e.g. `register_kyc`, which never
/// reaches the sidecar at all -- see `mod.rs`'s `dispatch`). Those stay
/// counted only in `SKIPPED`.
///
/// Plan A, Task 4: since the sidecar now serves every non-KYC circuit
/// (previously just brainpool), a widening gap between `skipped` and
/// `sidecar_unavailable` in the summary line below is still the signal that
/// distinguishes "the sidecar has been dead for a day" from "no traffic
/// arrived today" -- two situations that would otherwise print an identical
/// `skipped=N` line and be impossible to tell apart from the log stream
/// alone.
static SIDECAR_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);

/// Print a summary line every this many processed requests (valid + skipped
/// + invalid, combined).
const REPORT_EVERY: u64 = 100;

/// Records one verdict's outcome in the running totals and, every
/// `REPORT_EVERY` requests, prints a summary line. Call this exactly once per
/// `verify_inputs` result, in addition to (not instead of) the per-request
/// log line `main.rs` already prints for each arm.
pub fn record(v: &Verdict) {
    match v {
        Verdict::Valid => {
            VALID.fetch_add(1, Ordering::Relaxed);
        }
        Verdict::Skipped(_) => {
            SKIPPED.fetch_add(1, Ordering::Relaxed);
        }
        Verdict::Invalid(_) => {
            INVALID.fetch_add(1, Ordering::Relaxed);
        }
    }

    let valid = VALID.load(Ordering::Relaxed);
    let skipped = SKIPPED.load(Ordering::Relaxed);
    let invalid = INVALID.load(Ordering::Relaxed);
    let sidecar_unavailable = SIDECAR_UNAVAILABLE.load(Ordering::Relaxed);
    let total = valid + skipped + invalid;
    if total % REPORT_EVERY == 0 {
        println!(
            "precheck summary: valid={valid} skipped={skipped} invalid={invalid} \
             sidecar_unavailable={sidecar_unavailable} total={total}"
        );
    }
}

/// Records one sidecar-unavailable event. Call this from `sidecar.rs`
/// (`run_sidecar`/`parse_response`, its only current call sites -- see
/// their own module doc) at each point it cannot get a clean answer out of
/// the JS `signature-verifier` sidecar process itself (spawn failure,
/// timeout, non-zero exit, unparseable/empty output, or an explicit
/// `{"error":...}` response) -- i.e. every case those functions produce a
/// `Skipped` for reasons attributable to the sidecar rather than the input.
/// `primitives::brainpool` was the caller before Plan A, Task 4 deleted it
/// along with every other Rust family verifier; the sidecar now serves that
/// role for every non-KYC circuit. Deliberately separate from `record`: the
/// caller still calls `record(&Verdict::Skipped(reason))` exactly as before
/// (so `SKIPPED` counts every skip, sidecar-caused or not); this adds the
/// narrower, overlapping count on top, in addition to (not instead of) that
/// call.
pub fn record_sidecar_unavailable() {
    SIDECAR_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
}

/// Test-only read of the running total, for `sidecar.rs`'s own tests to
/// confirm each of its sidecar-unavailable failure modes actually calls
/// `record_sidecar_unavailable` -- without making the counter itself `pub`,
/// which would let production code outside this module increment or read it
/// directly, bypassing the one intended call path. (`primitives::brainpool`
/// held this role before Plan A, Task 4 deleted it; see
/// `record_sidecar_unavailable`'s own doc comment.)
#[cfg(test)]
pub(crate) fn sidecar_unavailable_count() -> u64 {
    SIDECAR_UNAVAILABLE.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These counters are process-global statics, so under cargo test's
    // default parallel execution other tests in this file (and this test
    // itself, for the loop below) may be incrementing the same counter
    // concurrently between this test's own before/after reads. Assert
    // ">= before + 1", never "== before + 1": these counters only ever go
    // up, so ">=" still proves this call's increment landed, without being
    // flaky about how many OTHER increments landed in the same window.
    //
    // `recording_sidecar_unavailable_increments_its_own_counter_not_skipped`
    // is the one exception: its whole point is an exact-equality read of
    // SKIPPED (proving record_sidecar_unavailable does NOT touch it), which
    // an unsynchronised concurrent incrementer -- namely
    // `recording_never_panics_regardless_of_running_total` below, which
    // calls `record(&Verdict::Skipped(..))` REPORT_EVERY+1 times in this
    // same module -- can and does race (observed ~8 failures in 30 runs of
    // `cargo test --bin tee-server -- metrics::tests`). `record` has exactly
    // one non-test caller (`main.rs`), so serialising just these four tests
    // behind a lock costs nothing in production and turns the race into a
    // deterministic pass. A module-local lock, not a crate-wide one: it only
    // needs to order this file's own tests against each other.
    static LOCK: Mutex<()> = Mutex::new(());

    fn locked() -> std::sync::MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn recording_a_valid_verdict_increments_the_valid_counter() {
        let _guard = locked();
        let before = VALID.load(Ordering::Relaxed);
        record(&Verdict::Valid);
        assert!(VALID.load(Ordering::Relaxed) >= before + 1);
    }

    #[test]
    fn recording_a_skipped_verdict_increments_the_skipped_counter() {
        let _guard = locked();
        let before = SKIPPED.load(Ordering::Relaxed);
        record(&Verdict::Skipped("reason".to_string()));
        assert!(SKIPPED.load(Ordering::Relaxed) >= before + 1);
    }

    #[test]
    fn recording_an_invalid_verdict_increments_the_invalid_counter() {
        let _guard = locked();
        let before = INVALID.load(Ordering::Relaxed);
        record(&Verdict::Invalid("reason".to_string()));
        assert!(INVALID.load(Ordering::Relaxed) >= before + 1);
    }

    #[test]
    fn recording_sidecar_unavailable_increments_its_own_counter_not_skipped() {
        // Deliberately does NOT also call record(&Verdict::Skipped(..)) here
        // -- that is the caller's job at the call site in primitives::
        // brainpool (in addition to this, not instead of it). This test
        // pins that record_sidecar_unavailable is its own counter, distinct
        // from SKIPPED, not a side door into it.
        //
        // This is an exact-equality read of a process-global atomic, so it
        // needs `locked()` (see the module doc above): without it, this can
        // race against `recording_never_panics_regardless_of_running_total`
        // incrementing SKIPPED concurrently in the same binary.
        let _guard = locked();
        let before_unavailable = SIDECAR_UNAVAILABLE.load(Ordering::Relaxed);
        let before_skipped = SKIPPED.load(Ordering::Relaxed);
        record_sidecar_unavailable();
        assert!(SIDECAR_UNAVAILABLE.load(Ordering::Relaxed) >= before_unavailable + 1);
        assert_eq!(
            SKIPPED.load(Ordering::Relaxed),
            before_skipped,
            "record_sidecar_unavailable must not itself touch SKIPPED"
        );
    }

    #[test]
    fn recording_never_panics_regardless_of_running_total() {
        // Exercises the REPORT_EVERY modulo/print path itself, whatever the
        // current running total happens to be from other tests. Takes the
        // same lock as the other tests here: it increments SKIPPED
        // REPORT_EVERY+1 times, which is exactly the traffic
        // `recording_sidecar_unavailable_increments_its_own_counter_not_skipped`
        // needs to not be racing against when it reads SKIPPED for equality.
        let _guard = locked();
        for _ in 0..(REPORT_EVERY + 1) {
            record(&Verdict::Skipped("x".to_string()));
        }
    }
}
