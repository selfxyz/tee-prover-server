// Task 3 (Plan A): the equivalence gate.
//
// Before Task 4 deletes any Rust signature-verification code, this file
// establishes -- and keeps re-checking, for as long as both implementations
// exist -- that verify.mjs (signature-verifier/verify.mjs) agrees with the
// Rust reference (src/verifier/{passport,dsc,aadhaar,kyc}.rs, dispatched via
// src/verifier/mod.rs's `dispatch`) over the 23 real fixtures checked in
// under tests/fixtures/, and over deliberately tampered variants of them.
//
// This file does NOT shell out to `cargo`/`rustc`. The Rust side is a
// RECORDED baseline -- see "HOW THE RUST BASELINE WAS CAPTURED" below for
// exactly which command produced each recorded verdict, so a reader can tell
// what was observed from what was inferred. This file replays that recorded
// baseline against a live, current run of verify.mjs's `verify()`. If
// verify.mjs's behaviour on any fixture (or the tampered variants below) ever
// drifts from the recorded Rust baseline, this test fails -- that is the
// entire point of the gate. (A drift on the RUST side, after this task, would
// need a fresh capture and an update to this file's recorded baseline --
// see the module doc of src/verifier/real_fixtures.rs for the analogous
// "capture, don't hand-edit" discipline this file follows.)
//
// Run with: node --test signature-verifier/differential.test.mjs
//
// =======================================================================
// HOW THE RUST BASELINE WAS CAPTURED
// =======================================================================
//
// 1. VALID baseline (all 23 fixtures): `cargo test --bin tee-server -- \
//    real_fixtures` -- this is the existing, permanent, committed Rust test
//    suite (src/verifier/real_fixtures.rs). Run on 2026-08-19 against this
//    branch's HEAD (a7b91a0), output "test result: ok. 158 passed; 0 failed".
//    That includes one dedicated `real_*_fixture_is_valid`-style test per
//    fixture file (all 23, including `real_kyc_fixture_is_valid`, which
//    calls `kyc::verify` directly and asserts `Valid`) plus
//    `all_real_fixtures_are_present`, which asserts the FIXTURES table has
//    exactly 23 rows, one per checked-in fixture. OBSERVED, not inferred:
//    this command was actually run and its "158 passed; 0 failed" output
//    inspected before writing this file.
//
// 2. SIGNATURE-TAMPER baseline (all 23 fixtures): the same cargo run above
//    also runs `every_fixture_stops_verifying_when_its_signature_is_tampered`
//    (part of the same 158), which flips one limb of each fixture's own
//    signature field (per real_fixtures.rs's FIXTURES table: `signature`,
//    `signature_passport`, or `s`) and asserts `Invalid` via `dispatch` for
//    all 23 rows, register_kyc included (its kyc::verify path really does
//    reject a tampered `s`). OBSERVED via the same passing run as (1).
//
// 3. DG1 / ECONTENT / KEY-LIMB baselines (register + DSC families only --
//    Aadhaar and KYC have no dg1/eContent/cert-key-window concept): NOT
//    covered by any existing, permanent Rust test across all fixtures.
//    Captured by TEMPORARILY appending one throwaway #[tokio::test] to
//    src/verifier/real_fixtures.rs (looping FIXTURES, tampering dg1/
//    eContent/pubKey_dsc/csca_pubKey exactly as the generic signature-tamper
//    test above tampers the signature field, printing each resulting
//    Verdict via `println!`), running it with:
//      cargo test --bin tee-server -- \
//        scratch_dump_dg1_econtent_keylimb_verdicts --nocapture \
//        --test-threads=1
//    ...reading the printed `Verdict::Invalid(...)`/`Verdict::Skipped(...)`
//    lines directly off stdout, and then reverting the scratch addition with
//    `git checkout -- src/verifier/real_fixtures.rs` before anything was
//    committed. Task 3's brief adds exactly one file
//    (this one) and forbids modifying any Rust file; the working tree was
//    confirmed clean (`git diff --stat` empty, `git status --short` showing
//    only a pre-existing unrelated untracked directory) both before this
//    capture and after reverting it. The recorded strings below (see
//    RUST_DG1_ECONTENT_BASELINE and RUST_KEYLIMB_BASELINE) are copied
//    verbatim from that OBSERVED stdout, not derived by reading the Rust
//    source and guessing.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verify, parseCircuitName } from './verify.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, '..', 'tests', 'fixtures');
const REAL_FIXTURES_RS = path.join(__dirname, '..', 'src', 'verifier', 'real_fixtures.rs');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf8'));
}

// -----------------------------------------------------------------------
// Parse src/verifier/real_fixtures.rs's own FIXTURES table, rather than
// hand-copying it -- so a fixture renamed or reassigned to a different
// circuit on the Rust side is caught here as a drift, not silently
// duplicated into a second, independently-maintained table that could go
// stale. This is also the "check the two mappings agree" step Task 3's
// brief calls for: parsing Rust's own source is the only way to compare
// against it without re-deriving Rust's table by hand.
// -----------------------------------------------------------------------

function parseRustFixturesTable() {
  const src = fs.readFileSync(REAL_FIXTURES_RS, 'utf8');
  const startMarker = 'const FIXTURES: &[(&str, &str, &str)] = &[';
  const start = src.indexOf(startMarker);
  assert.notEqual(start, -1, 'could not find the FIXTURES table in real_fixtures.rs -- has it been renamed?');
  const end = src.indexOf('\n];', start);
  assert.notEqual(end, -1, 'could not find the end of the FIXTURES table in real_fixtures.rs');
  const block = src.slice(start + startMarker.length, end);
  const rowRe = /\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)/g;
  const rows = [];
  let m;
  while ((m = rowRe.exec(block)) !== null) {
    rows.push({ file: m[1], circuit: m[2], sigField: m[3] });
  }
  return rows;
}

const RUST_FIXTURES = parseRustFixturesTable();

function familyOf(circuit) {
  if (circuit === 'register_kyc') return 'kyc';
  if (circuit === 'register_aadhaar') return 'aadhaar';
  if (circuit.startsWith('dsc_')) return 'dsc';
  return 'register';
}

describe('mapping agreement: the Rust FIXTURES table and this repo\'s fixture directory line up', () => {
  test('real_fixtures.rs\'s FIXTURES table has exactly 23 rows, one per checked-in fixture', () => {
    assert.equal(RUST_FIXTURES.length, 23, `parsed ${RUST_FIXTURES.length} rows from real_fixtures.rs -- expected 23`);
    const onDisk = fs.readdirSync(FIXTURES_DIR).filter((f) => f.endsWith('.json'));
    assert.equal(onDisk.length, 23, `tests/fixtures/ holds ${onDisk.length} .json files, expected 23`);
    const rustFiles = new Set(RUST_FIXTURES.map((r) => r.file));
    for (const f of onDisk) {
      assert.ok(rustFiles.has(f), `${f} is on disk but not in real_fixtures.rs's FIXTURES table`);
    }
  });

  // The comparison in every describe block below is meaningless if the two
  // sides verify the SAME FILE under DIFFERENT circuit names -- this is what
  // would make that failure mode loud instead of silent.
  for (const row of RUST_FIXTURES) {
    test(`${row.file}: verify.mjs's parseCircuitName recognizes "${row.circuit}" (the exact name real_fixtures.rs verifies it under)`, () => {
      const parsed = parseCircuitName(row.circuit);
      assert.notEqual(parsed, null, `verify.mjs does not recognize circuit name "${row.circuit}" at all`);
      assert.equal(parsed.family, familyOf(row.circuit));
    });
  }
});

// =======================================================================
// 1. VALID baseline -- see capture note (1) above.
// =======================================================================

describe('Rust <-> JS: every real fixture verifies the same way (register_kyc is the one documented exception)', () => {
  for (const row of RUST_FIXTURES) {
    test(`${row.file} (${row.circuit})`, () => {
      const fixture = loadFixture(row.file);
      const result = verify(row.circuit, fixture);
      if (row.circuit === 'register_kyc') {
        // THE documented divergence this task's brief predicts: Rust's
        // kyc::verify (EdDSA-BabyJubJub + Poseidon2) has no node:crypto
        // primitive, so verify.mjs always skips it -- by design, and with no
        // production effect, since mod.rs's dispatch routes register_kyc to
        // Rust's native kyc::verify both before and after Task 4 (verify.mjs
        // is simply never asked about this circuit in production).
        assert.equal(result.verdict, 'skipped', `expected the documented register_kyc skip, got ${JSON.stringify(result)}`);
        assert.match(result.reason, /BabyJubJub/);
      } else {
        // Rust: Valid (real_fixtures.rs's real_*_fixture_is_valid tests, all
        // 22 of the non-kyc rows, captured passing -- see note (1)).
        assert.deepEqual(result, { verdict: 'valid' }, `${row.file}: Rust says Valid, JS said ${JSON.stringify(result)}`);
      }
    });
  }
});

// =======================================================================
// 2. SIGNATURE-TAMPER baseline -- see capture note (2) above. Both sides
// reject for every fixture except register_kyc, where JS's unconditional
// skip (the same documented exception as above) means it never even looks
// at the tampered `s` field.
// =======================================================================

function tamperedValue(v) {
  return String(v) === '1' ? '2' : '1';
}

function tamperField(fixture, fieldName) {
  const tampered = structuredClone(fixture);
  const value = tampered[fieldName];
  if (Array.isArray(value)) {
    const limbs = [...value];
    limbs[0] = tamperedValue(limbs[0]);
    tampered[fieldName] = limbs;
  } else {
    tampered[fieldName] = tamperedValue(value);
  }
  return tampered;
}

// Phrases that identify which link rejected, shared with verify.test.mjs's
// own reason-content assertions -- these are what "the link identified"
// means operationally: not exact wording, but which of these buckets a
// reason falls into.
const SIGNATURE_LINK_PHRASES = ['signature does not verify', 'PSS signature does not verify', 'ECDSA signature does not verify', 'Aadhaar signature does not verify', 'KYC EdDSA signature does not verify'];

describe('Rust <-> JS: tampering the signature -- both reject, naming the signature link (register_kyc excepted)', () => {
  for (const row of RUST_FIXTURES) {
    test(`${row.file}: flipping one limb/value of "${row.sigField}"`, () => {
      const fixture = loadFixture(row.file);
      const tampered = tamperField(fixture, row.sigField);
      const result = verify(row.circuit, tampered);

      if (row.circuit === 'register_kyc') {
        // Rust: Invalid (the tampered-signature generic test covers this
        // row too -- see capture note (2)). JS: still 'skipped',
        // unconditionally -- the same documented exception, not a new one:
        // verify.mjs never evaluates register_kyc's fields at all, tampered
        // or not.
        assert.equal(result.verdict, 'skipped');
        return;
      }
      // Rust: Invalid for all 22 remaining rows (capture note (2)), naming
      // the signature check specifically -- confirmed against the Rust
      // source directly for every scheme this repo has (RSA:
      // "signature does not verify under pubKey_dsc"/"under csca_pubKey";
      // PSS: "PSS signature does not verify: ..."; ECDSA (NIST and
      // brainpool alike): "ECDSA signature does not verify: ..."; Aadhaar:
      // "Aadhaar signature does not verify" -- see passport.rs:201,219,
      // dsc.rs:292,310, primitives/ecdsa.rs:256-280, aadhaar.rs:81).
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assert.ok(
        SIGNATURE_LINK_PHRASES.some((p) => result.reason.includes(p)),
        `${row.file}: reason does not name the signature link: ${result.reason}`,
      );
    });
  }
});

// =======================================================================
// 3. DG1 baseline (register family only -- 16 rows). Full agreement: both
// sides reject with the SAME wording, because verify.mjs's dg1 link (see
// its own doc comment) copies passport.rs's reason string verbatim.
// =======================================================================

const REGISTER_ROWS = RUST_FIXTURES.filter((r) => familyOf(r.circuit) === 'register');
const DSC_ROWS = RUST_FIXTURES.filter((r) => familyOf(r.circuit) === 'dsc');
assert.equal(REGISTER_ROWS.length, 16, `expected 16 register-family rows, got ${REGISTER_ROWS.length}`);
assert.equal(DSC_ROWS.length, 5, `expected 5 DSC-family rows, got ${DSC_ROWS.length}`);

const DG1_LINK_PHRASE = 'dg1 hash does not match';
const ECONTENT_LINK_PHRASE = 'eContent hash does not match';

describe('Rust <-> JS: tampering dg1 -- both reject, naming the dg1 link (register family)', () => {
  // RUST BASELINE (capture note (3)): every one of the 16 register-family
  // rows printed `Invalid("dg1 hash does not match eContent at
  // dg1_hash_offset")` -- observed for all 16, no exceptions.
  for (const row of REGISTER_ROWS) {
    test(`${row.file}: flipping one byte of dg1`, () => {
      const fixture = loadFixture(row.file);
      const tampered = structuredClone(fixture);
      const dg1 = [...tampered.dg1];
      dg1[0] = String((Number(dg1[0]) ^ 1) & 0xff);
      tampered.dg1 = dg1;

      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assert.ok(result.reason.includes(DG1_LINK_PHRASE), `${row.file}: got ${result.reason}`);
    });
  }
});

describe('Rust <-> JS: tampering eContent -- both reject, naming the eContent link (register family)', () => {
  // RUST BASELINE (capture note (3)): every one of the 16 register-family
  // rows printed `Invalid("eContent hash does not match signed_attr at
  // signed_attr_econtent_hash_offset")` -- observed for all 16.
  for (const row of REGISTER_ROWS) {
    test(`${row.file}: flipping eContent[0]`, () => {
      const fixture = loadFixture(row.file);
      // dg1_hash_offset is 70 for every register-family fixture (verified
      // against every checked-in fixture -- also asserted by
      // verify.test.mjs), so index 0 lies outside the dg1-hash window and
      // link 1 stays intact; only link 2 breaks.
      assert.equal(Number([].concat(fixture.dg1_hash_offset)[0]), 70, `${row.file}: dg1_hash_offset assumption changed`);
      const tampered = structuredClone(fixture);
      const econtent = [...tampered.eContent];
      econtent[0] = String((Number(econtent[0]) ^ 1) & 0xff);
      tampered.eContent = econtent;

      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assert.ok(result.reason.includes(ECONTENT_LINK_PHRASE), `${row.file}: got ${result.reason}`);
    });
  }
});

// =======================================================================
// 4. KEY-LIMB baseline, DSC family (5 rows) -- full agreement. dsc.rs
// already implements the raw_csca byte-window comparison (dsc.rs:198-262),
// which is exactly what verify.mjs's keyMatchesWindow was written to mirror
// -- so both sides reject with IDENTICAL wording here (confirmed against
// dsc.rs's own source: "csca_pubKey does not match the bytes in raw_csca at
// csca_pubKey_offset", byte-for-byte the same string verify.mjs produces).
// =======================================================================

const KEYLIMB_PHRASE = 'does not match the bytes in raw_';

describe('Rust <-> JS: tampering csca_pubKey -- both reject, naming the same key-window link (DSC family)', () => {
  // RUST BASELINE (capture note (3)): all 5 DSC-family rows printed
  // `Invalid("csca_pubKey does not match the bytes in raw_csca at
  // csca_pubKey_offset")` -- observed for all 5, wording included.
  for (const row of DSC_ROWS) {
    test(`${row.file}: flipping one limb of csca_pubKey`, () => {
      const fixture = loadFixture(row.file);
      const tampered = tamperField(fixture, 'csca_pubKey');
      const result = verify(row.circuit, tampered);
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assert.ok(result.reason.includes(KEYLIMB_PHRASE), `${row.file}: got ${result.reason}`);
      assert.equal(result.reason, 'csca_pubKey does not match the bytes in raw_csca at csca_pubKey_offset');
    });
  }
});

// =======================================================================
// 5. DIVERGENCE #2 -- register family, pubKey_dsc-limb tamper.
//
// *** NOT the divergence Task 3's brief predicted ("exactly one divergence:
// register_kyc"). This is a SECOND, additional divergence, found while
// building this gate, that the brief's four pre-approved "intentional
// differences" do not cover. It is flagged here, not silently treated as
// equivalent to the register_kyc exception, and is called out prominently
// in this task's report as requiring explicit sign-off before Task 4
// proceeds -- per this task's own instructions: "Any other divergence is a
// stop-and-report... Report the fixture, both verdicts, and your analysis
// of which side is correct." ***
//
// What's happening: passport.rs (register family) has NO check at all that
// tie `pubKey_dsc` to the certificate embedded in `raw_dsc` -- unlike
// dsc.rs's csca_pubKey check (section 4 above), passport.rs never reads
// raw_dsc/dsc_pubKey_offset/dsc_pubKey_actual_size (confirmed directly
// against passport.rs's source: its own module doc comment lists only 3
// links, and grep confirms no such field is ever read). verify.mjs's
// verifyRegisterFamily deliberately ADDS this link anyway (see its own doc
// comment, which explicitly anticipates exactly this differential-gate
// finding: "Task 3's differential gate may see this module return Invalid
// on a pubKey_dsc-tampered input where the Rust reference returns something
// else... that is this decision working as intended, not a disagreement to
// resolve by removing the link").
//
// So when pubKey_dsc is tampered on a register-family fixture:
//   - RSA/PSS rows (6): Rust still rejects (Invalid), but blames the FINAL
//     SIGNATURE CHECK ("signature does not verify under pubKey_dsc" / "PSS
//     signature does not verify: EM does not end in 0xbc") -- the tampered
//     key is used directly, with no independent key-identity check. JS
//     blames the KEY-WINDOW LINK instead ("pubKey_dsc does not match the
//     bytes in raw_dsc..."). Both verdicts are Invalid, but the LINK
//     IDENTIFIED differs -- which Task 3's brief explicitly says must not
//     happen ("the link identified must not differ").
//   - ECDSA/brainpool rows (10): Rust's pre-check does not reject at all --
//     it SKIPS ("public key is not on the curve" / "brainpool sidecar
//     reported: invalid public key"), because it reconstructs an EC point
//     from the tampered limbs directly and that point is (usually) not on
//     the curve, which this codebase's own stated design classifies as
//     "cannot be certain" rather than an affirmative failure. JS rejects
//     (Invalid) via the key-window link before ever attempting to
//     reconstruct a point. This is a stronger divergence than a wording
//     difference: one side's PRE-CHECK layer defers (Skipped, forwarded to
//     the slow circuit-proving path, which does still reject there), the
//     other's rejects immediately.
//
// ANALYSIS (mine, for the human sign-off this needs): no false ACCEPT is
// possible on either side here -- a genuinely tampered pubKey_dsc is
// rejected somewhere in the pipeline regardless (immediately in JS; at
// proving time, via register.circom's own CheckPubkeyPosition/
// CheckPubkeysEqual, in Rust's case for the 10 Skipped rows). This link
// never fires on any of the 23 real (non-tampered) fixtures either -- the
// "every real fixture verifies the same way" describe block above already
// proves that. So this divergence is adversarial-input-only, and JS is
// arguably the MORE correct side (it closes a real gap passport.rs leaves
// open, mirroring dsc.rs's own precedent for the DSC family) -- but it is
// still a real functional divergence from the Rust reference this task was
// asked to gate on, was not in the brief's approved list, and should not be
// waved through by this file alone.
// =======================================================================

const RUST_KEYLIMB_BASELINE_REGISTER = {
  // Brainpool ECDSA: the sidecar rejects the tampered point as unreadable.
  'register_ecdsa_brainpoolP224r1.json': { verdict: 'skipped', reasonIncludes: 'brainpool sidecar reported: invalid public key' },
  'register_ecdsa_brainpoolP256r1.json': { verdict: 'skipped', reasonIncludes: 'brainpool sidecar reported: invalid public key' },
  'register_ecdsa_brainpoolP384r1.json': { verdict: 'skipped', reasonIncludes: 'brainpool sidecar reported: invalid public key' },
  'register_ecdsa_brainpoolP512r1.json': { verdict: 'skipped', reasonIncludes: 'brainpool sidecar reported: invalid public key' },
  // NIST ECDSA: the off-curve point reconstructed from the tampered limb.
  'register_ecdsa_secp224r1.json': { verdict: 'skipped', reasonIncludes: 'public key is not on the curve' },
  'register_ecdsa_secp256r1.json': { verdict: 'skipped', reasonIncludes: 'public key is not on the curve' },
  'register_ecdsa_secp256r1_sha1.json': { verdict: 'skipped', reasonIncludes: 'public key is not on the curve' },
  'register_ecdsa_secp384r1.json': { verdict: 'skipped', reasonIncludes: 'public key is not on the curve' },
  'register_ecdsa_secp384r1_sha256.json': { verdict: 'skipped', reasonIncludes: 'public key is not on the curve' },
  'register_ecdsa_secp521r1.json': { verdict: 'skipped', reasonIncludes: 'public key is not on the curve' },
  // RSA / RSA-PSS: the tampered key is used directly; only the final
  // signature check catches it, not a key-identity check.
  'register_id.json': { verdict: 'invalid', reasonIncludes: 'signature does not verify under pubKey_dsc' },
  'register_passport.json': { verdict: 'invalid', reasonIncludes: 'signature does not verify under pubKey_dsc' },
  'register_pss.json': { verdict: 'invalid', reasonIncludes: 'PSS signature does not verify' },
  'register_pss_sha256_salt64.json': { verdict: 'invalid', reasonIncludes: 'PSS signature does not verify' },
  'register_pss_sha384.json': { verdict: 'invalid', reasonIncludes: 'PSS signature does not verify' },
  'register_pss_sha512.json': { verdict: 'invalid', reasonIncludes: 'PSS signature does not verify' },
};

describe('DIVERGENCE #2 (flagged, not silently accepted): tampering pubKey_dsc (register family) -- Rust and JS disagree', () => {
  assert.equal(
    Object.keys(RUST_KEYLIMB_BASELINE_REGISTER).length,
    16,
    'expected a recorded Rust baseline row for all 16 register-family fixtures',
  );

  for (const row of REGISTER_ROWS) {
    test(`${row.file}: pubKey_dsc-limb tamper -- JS rejects at the key-window link, Rust's recorded baseline does not`, () => {
      const fixture = loadFixture(row.file);
      const tampered = tamperField(fixture, 'pubKey_dsc');
      const result = verify(row.circuit, tampered);

      // JS's actual, current behaviour: always Invalid, always the
      // key-window link (verifyRegisterFamily's link 3, deliberately added
      // beyond passport.rs's own scope).
      assert.equal(result.verdict, 'invalid', `${row.file}: got ${JSON.stringify(result)}`);
      assert.ok(result.reason.includes(KEYLIMB_PHRASE), `${row.file}: got ${result.reason}`);

      // Rust's recorded baseline (capture note (3)) for the SAME mutation:
      // never the key-window link, because passport.rs has no such link to
      // fire.
      const rustBaseline = RUST_KEYLIMB_BASELINE_REGISTER[row.file];
      assert.ok(rustBaseline, `${row.file}: no recorded Rust baseline for this row`);
      assert.ok(
        !rustBaseline.reasonIncludes.includes('raw_dsc'),
        `${row.file}: recorded Rust baseline unexpectedly mentions raw_dsc -- if Rust has grown this check, ` +
          'this divergence may have closed; re-examine before treating it as still open',
      );
      if (rustBaseline.verdict === 'invalid') {
        // The 6 RSA/PSS rows: same final verdict, different link identified.
        assert.ok(
          rustBaseline.reasonIncludes.includes('signature does not verify') || rustBaseline.reasonIncludes.includes('PSS signature does not verify'),
          `${row.file}: expected Rust's recorded reason to blame the signature check, got ${rustBaseline.reasonIncludes}`,
        );
      } else {
        // The 10 ECDSA/brainpool rows: Rust's pre-check does not reject at
        // all here (Skipped, deferred to the slow path) where JS does.
        assert.equal(rustBaseline.verdict, 'skipped');
      }
    });
  }
});
