//! Global counters for the pre-check's three-valued outcome, and a periodic
//! summary line.
//!
//! Before this, `main.rs`'s `Verdict::Valid => {}` logged nothing and there
//! were no counters at all, so "the pre-check verifies 97% of traffic" and
//! "the pre-check skips everything" were indistinguishable from outside --
//! which is exactly the state that let Aadhaar and KYC ship skipping 100% of
//! real traffic (see `chunks::field_as_strings`) without anyone noticing.
//!
//! This same binary also runs on disclose-only images where every request
//! skips by construction (the disclose circuits prove membership/selective
//! disclosure, not a document signature -- see the design's Non-goals), so a
//! raw skip count is not even comparable across images: a 100% skip rate is
//! expected there and a red flag on a register image. These counters are a
//! coarse, this-process-lifetime signal for the latter case, not a
//! cross-image metric.
//!
//! Deliberately three flat `AtomicU64` counters plus a `println!` summary,
//! not the spec's fuller `(circuit_name, verdict)` breakdown: this repo has
//! no metrics framework and adding one is explicitly out of scope (the
//! spec's Metrics section), so this answers the one question that matters
//! most cheaply -- "is the skip rate near 100%?" -- using the existing log
//! stream.

use std::sync::atomic::{AtomicU64, Ordering};

use super::Verdict;

static VALID: AtomicU64 = AtomicU64::new(0);
static SKIPPED: AtomicU64 = AtomicU64::new(0);
static INVALID: AtomicU64 = AtomicU64::new(0);

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
    let total = valid + skipped + invalid;
    if total % REPORT_EVERY == 0 {
        println!(
            "precheck summary: valid={valid} skipped={skipped} invalid={invalid} total={total}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These counters are process-global statics, so under cargo test's
    // default parallel execution other tests in this file (and this test
    // itself, for the loop below) may be incrementing the same counter
    // concurrently between this test's own before/after reads. Assert
    // ">= before + 1", never "== before + 1": these counters only ever go
    // up, so ">=" still proves this call's increment landed, without being
    // flaky about how many OTHER increments landed in the same window.

    #[test]
    fn recording_a_valid_verdict_increments_the_valid_counter() {
        let before = VALID.load(Ordering::Relaxed);
        record(&Verdict::Valid);
        assert!(VALID.load(Ordering::Relaxed) >= before + 1);
    }

    #[test]
    fn recording_a_skipped_verdict_increments_the_skipped_counter() {
        let before = SKIPPED.load(Ordering::Relaxed);
        record(&Verdict::Skipped("reason".to_string()));
        assert!(SKIPPED.load(Ordering::Relaxed) >= before + 1);
    }

    #[test]
    fn recording_an_invalid_verdict_increments_the_invalid_counter() {
        let before = INVALID.load(Ordering::Relaxed);
        record(&Verdict::Invalid("reason".to_string()));
        assert!(INVALID.load(Ordering::Relaxed) >= before + 1);
    }

    #[test]
    fn recording_never_panics_regardless_of_running_total() {
        // Exercises the REPORT_EVERY modulo/print path itself, whatever the
        // current running total happens to be from other tests.
        for _ in 0..(REPORT_EVERY + 1) {
            record(&Verdict::Skipped("x".to_string()));
        }
    }
}
