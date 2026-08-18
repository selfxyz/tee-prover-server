//! Circuit parameter lookup: given a circuit name, the hash algorithms, signature
//! scheme, and limb layout (`n`, `k`) it uses to encode big-integer values (RSA
//! moduli/signatures) as base-`2^n` limbs.
//!
//! `n` and `k` never appear in the circuit name — only in the sibling monorepo's
//! instance files, e.g. `../self/circuits/circuits/register/instances/
//! register_sha256_sha256_sha256_rsa_65537_4096.circom`:
//!
//! ```text
//! component main { public [ merkle_root ] } = REGISTER(256, 256, 1, 120, 35, 512, 256);
//! ```
//!
//! whose arguments are `(DG_HASH_ALGO, ECONTENT_HASH_ALGO, signatureAlgorithm, n, k,
//! MAX_ECONTENT_PADDED_LEN, MAX_SIGNED_ATTR_PADDED_LEN)`. The `(n, k)` table below was
//! populated by reading every such file once and transcribing verbatim — see the task
//! report for the full file-by-file list. Do not hand-edit an entry without re-reading
//! its source instance file: a wrong `(n, k)` makes a verifier reassemble the wrong
//! integer and reject a valid document, which is exactly the false-reject outcome this
//! whole design exists to avoid. `table_matches_the_monorepo_instance_files` below
//! guards against drift when the sibling monorepo is checked out.
//!
//! Scope for this table is deliberately narrow: RSA PKCS#1 v1.5 passport
//! (`register_*`) and EU-ID (`register_id_*`) circuits, plus the fixed
//! `register_aadhaar` and `register_kyc` instances. RSAPSS and ECDSA are left out
//! entirely on purpose — `lookup` returns `None` for them and callers skip. A later
//! plan adds them.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    Rsa { e: u64, bits: u32 },
    // RsaPss and Ecdsa are not constructed yet: `lookup` never returns them
    // because Plan 1 (this plan) only populates the table for RSA PKCS#1
    // v1.5 circuits, by design (see this file's module doc). They exist now
    // so Plan 2 (RSAPSS) and Plan 3/4 (ECDSA NIST/brainpool) — both already
    // scoped in the design's coverage ramp — add a verifier without first
    // reshaping this enum. Remove this attribute once either plan lands and
    // starts constructing its variant.
    #[allow(dead_code)]
    RsaPss { e: u64, salt_len: usize, bits: u32 },
    #[allow(dead_code)]
    Ecdsa { curve: String },
    EdDsaBabyJubJub,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitParams {
    pub dg_hash: u32,
    pub econtent_hash: u32,
    pub sig_hash: u32,
    pub scheme: Scheme,
    pub n: u32,
    pub k: u32,
}

fn sha_bits(tag: &str) -> Option<u32> {
    match tag {
        "sha1" => Some(160),
        "sha224" => Some(224),
        "sha256" => Some(256),
        "sha384" => Some(384),
        "sha512" => Some(512),
        _ => None,
    }
}

/// `(n, k)` transcribed verbatim from the sibling monorepo's instance files at
/// `../self/circuits/circuits/{register,register_id}/instances/<name>.circom` (the
/// 4th and 5th arguments to `REGISTER(...)` / `REGISTER_ID(...)`). Every RSA
/// PKCS#1 v1.5 passport and EU-ID circuit currently uses `(120, 35)` — see the task
/// report for the file read backing each row.
const RSA_LIMBS: &[(&str, u32, u32)] = &[
    // register/instances/*.circom
    ("register_sha1_sha1_sha1_rsa_64321_4096", 120, 35),
    ("register_sha1_sha1_sha1_rsa_65537_4096", 120, 35),
    ("register_sha1_sha256_sha256_rsa_65537_4096", 120, 35),
    ("register_sha256_sha1_sha1_rsa_65537_4096", 120, 35),
    ("register_sha256_sha256_sha256_rsa_3_4096", 120, 35),
    ("register_sha256_sha256_sha256_rsa_65537_4096", 120, 35),
    ("register_sha512_sha512_sha256_rsa_65537_4096", 120, 35),
    ("register_sha512_sha512_sha512_rsa_65537_4096", 120, 35),
    // register_id/instances/*.circom
    ("register_id_sha1_sha1_sha1_rsa_65537_4096", 120, 35),
    ("register_id_sha1_sha256_sha256_rsa_65537_4096", 120, 35),
    ("register_id_sha256_sha256_sha256_rsa_3_4096", 120, 35),
    ("register_id_sha256_sha256_sha256_rsa_65537_4096", 120, 35),
    ("register_id_sha512_sha512_sha256_rsa_65537_4096", 120, 35),
    ("register_id_sha512_sha512_sha512_rsa_65537_4096", 120, 35),
];

/// `(signatureAlgorithm ID, hash_bits, exponent)`, transcribed from
/// `../self/circuits/circuits/utils/passport/signatureAlgorithm.circom`: its
/// top-of-file "ID to Signature Algorithm" comment table (which names the
/// hash and exponent directly, e.g. `1: rsa_sha256_65537_2048`) and its
/// `getHashLength(signatureAlgorithm)` function agree on every entry below —
/// both were read and cross-checked before transcribing, not guessed from
/// one source alone. Limited to the RSA PKCS#1 v1.5 IDs that actually appear
/// as the `signatureAlgorithm` (3rd) argument across the 14 `REGISTER`/
/// `REGISTER_ID` instance files this crate's `RSA_LIMBS` table covers, plus
/// the handful of neighbouring RSA IDs from the same table that read
/// cleanly. RSAPSS and ECDSA IDs are omitted entirely — out of scope for
/// this plan, and `lookup` already returns `None` for those circuit names,
/// so the drift test below never needs an entry for them.
///
/// Used only by the `#[cfg(test)]` drift guard below, hence `cfg_attr`
/// rather than a bare `#[allow(dead_code)]`: a non-test build genuinely has
/// no caller for this, and the warning should come back the moment that
/// stops being true.
#[cfg_attr(not(test), allow(dead_code))]
const SIGNATURE_ALGORITHM_TABLE: &[(u32, u32, u64)] = &[
    // (id, hash_bits, exponent)
    (1, 256, 65537),   // rsa_sha256_65537_2048
    (3, 160, 65537),   // rsa_sha1_65537_2048
    (10, 256, 65537),  // rsa_sha256_65537_4096
    (11, 160, 65537),  // rsa_sha1_65537_4096
    (13, 256, 3),      // rsa_sha256_3_2048
    (14, 256, 65537),  // rsa_sha256_65537_3072
    (15, 512, 65537),  // rsa_sha512_65537_4096
    (31, 512, 65537),  // rsa_sha512_65537_2048
    (32, 256, 3),      // rsa_sha256_3_4096
    (33, 160, 3),      // rsa_sha1_3_4096
    (34, 384, 65537),  // rsa_sha384_65537_4096
    (47, 160, 64321),  // rsa_sha1_64321_4096
    (48, 256, 130689), // rsa_sha256_130689_4096
    (49, 256, 122125), // rsa_sha256_122125_4096
    (50, 256, 107903), // rsa_sha256_107903_4096
    (51, 256, 56611),  // rsa_sha256_56611_4096
];

/// Looks up `(hash_bits, exponent)` for a `signatureAlgorithm` ID from the
/// table above. Used only by the `#[cfg(test)]` drift guard below.
#[cfg_attr(not(test), allow(dead_code))]
fn signature_algorithm_hash_and_exponent(id: u32) -> Option<(u32, u64)> {
    SIGNATURE_ALGORITHM_TABLE
        .iter()
        .find(|(entry_id, _, _)| *entry_id == id)
        .map(|(_, hash_bits, exponent)| (*hash_bits, *exponent))
}

pub fn lookup(name: &str) -> Option<CircuitParams> {
    // register_aadhaar.circom instantiates REGISTER_AADHAAR(121, 17, 512 * 3) — a
    // different template with a different argument order (n, k, maxDataLength).
    // (n, k) = (121, 17) is transcribed directly from that file's first two args.
    if name == "register_aadhaar" {
        return Some(CircuitParams {
            // N/A: Aadhaar (register_aadhaar.circom:29-33) is one hash, one
            // RSA verify, with no dg1<->eContent<->signed_attr chain at all
            // (see verifier::aadhaar's module doc) -- it has no dg1 link and
            // no eContent link for these to describe. 256 is `sig_hash`'s
            // real value (the width the RSA signature is actually taken
            // over); these two are unused placeholders that happen to share
            // that same number, which makes them look load-bearing when
            // they are not. aadhaar::verify never reads dg_hash or
            // econtent_hash.
            dg_hash: 256,
            econtent_hash: 256,
            sig_hash: 256,
            scheme: Scheme::Rsa {
                e: 65537,
                bits: 2048,
            },
            n: 121,
            k: 17,
        });
    }
    // register_kyc.circom instantiates REGISTER_KYC() — no template arguments at
    // all, so there is no (n, k) to transcribe. This is a category difference, not
    // an unhandled case: KYC signs with EdDSA over BabyJubJub field elements, which
    // has no RSA-style big-integer limb decomposition to describe. 0/0 is an
    // explicit "not applicable" placeholder rather than an invented value.
    if name == "register_kyc" {
        return Some(CircuitParams {
            // N/A, all three: KYC's message hash is PackBytesAndPoseidon
            // over data_padded (see verifier::kyc's module doc), not a SHA
            // variant selected by a bit width at all, so none of dg_hash/
            // econtent_hash/sig_hash describes anything real here. 0 reads
            // less plausibly than Aadhaar's copied-256s above, but is
            // exactly as unused: kyc::verify never reads any of the three.
            dg_hash: 0,
            econtent_hash: 0,
            sig_hash: 0,
            scheme: Scheme::EdDsaBabyJubJub,
            n: 0,
            k: 0,
        });
    }

    let rest = if let Some(rest) = name.strip_prefix("register_id_") {
        rest
    } else if let Some(rest) = name.strip_prefix("register_") {
        rest
    } else {
        return None;
    };

    let parts: Vec<&str> = rest.split('_').collect();
    if parts.len() < 4 {
        return None;
    }
    let dg_hash = sha_bits(parts[0])?;
    let econtent_hash = sha_bits(parts[1])?;
    let sig_hash = sha_bits(parts[2])?;

    // Only RSA PKCS#1 v1.5 is in scope for this table. RSAPSS and ECDSA circuits
    // return None here and skip — a later plan adds them.
    if parts[3] != "rsa" {
        return None;
    }
    if parts.len() != 6 {
        return None;
    }
    let e: u64 = parts[4].parse().ok()?;
    let bits: u32 = parts[5].parse().ok()?;

    let (n, k) = RSA_LIMBS
        .iter()
        .find(|(entry_name, _, _)| *entry_name == name)
        .map(|(_, n, k)| (*n, *k))?;

    Some(CircuitParams {
        dg_hash,
        econtent_hash,
        sig_hash,
        scheme: Scheme::Rsa { e, bits },
        n,
        k,
    })
}

/// Extracts the comma-separated argument list following `marker` in `src`, up to
/// the matching close-paren. Tolerant of whitespace and newlines between args.
/// Used only by the `#[cfg(test)]` drift guard below (via the two `parse_*`
/// functions that follow), so it has no caller in a non-test build.
#[cfg_attr(not(test), allow(dead_code))]
fn extract_args<'a>(src: &'a str, marker: &str) -> Option<Vec<&'a str>> {
    let idx = src.find(marker)?;
    let start = idx + marker.len();
    let end = start + src[start..].find(')')?;
    Some(src[start..end].split(',').map(|s| s.trim()).collect())
}

/// Finds a `REGISTER(...)`, `REGISTER_ID(...)`, or `REGISTER_AADHAAR(...)` call and
/// returns its `(n, k)` arguments. `REGISTER`/`REGISTER_ID` carry `n, k` as their
/// 4th and 5th arguments; `REGISTER_AADHAAR(n, k, maxDataLength)` carries them as
/// its 1st and 2nd. Returns `None` for anything else (including `REGISTER_KYC()`,
/// which takes no template arguments at all).
///
/// Used only by the `#[cfg(test)]` drift guard below: production dispatch
/// never re-derives `(n, k)` from an instance file, it reads the checked-in
/// `RSA_LIMBS`/`lookup` table.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_instance_n_k(src: &str) -> Option<(u32, u32)> {
    if let Some(args) = extract_args(src, "REGISTER_AADHAAR(") {
        if args.len() < 2 {
            return None;
        }
        let n: u32 = args[0].parse().ok()?;
        let k: u32 = args[1].parse().ok()?;
        return Some((n, k));
    }
    let args = if let Some(args) = extract_args(src, "REGISTER_ID(") {
        args
    } else {
        extract_args(src, "REGISTER(")?
    };
    if args.len() < 5 {
        return None;
    }
    let n: u32 = args[3].parse().ok()?;
    let k: u32 = args[4].parse().ok()?;
    Some((n, k))
}

/// Finds a `REGISTER(...)` or `REGISTER_ID(...)` call and returns its first
/// three arguments — `(DG_HASH_ALGO, ECONTENT_HASH_ALGO, signatureAlgorithm)`
/// — as `(u32, u32, u32)`. Deliberately does *not* handle
/// `REGISTER_AADHAAR(...)`: that template's argument list is `(n, k,
/// maxDataLength)` and carries none of these three, since Aadhaar's hash
/// widths and signature scheme are fixed by the circuit body rather than
/// passed in as template parameters (see `lookup`'s `register_aadhaar` arm).
/// Returns `None` for anything else, including `REGISTER_AADHAAR(...)` and
/// `REGISTER_KYC()`.
///
/// Used only by the `#[cfg(test)]` drift guard below.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_instance_hash_and_sig_algo(src: &str) -> Option<(u32, u32, u32)> {
    if extract_args(src, "REGISTER_AADHAAR(").is_some() {
        return None;
    }
    let args = if let Some(args) = extract_args(src, "REGISTER_ID(") {
        args
    } else {
        extract_args(src, "REGISTER(")?
    };
    if args.len() < 3 {
        return None;
    }
    let dg_hash: u32 = args[0].parse().ok()?;
    let econtent_hash: u32 = args[1].parse().ok()?;
    let sig_algo: u32 = args[2].parse().ok()?;
    Some((dg_hash, econtent_hash, sig_algo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_representative_rsa_circuit() {
        let p = lookup("register_sha256_sha256_sha256_rsa_65537_4096").expect("should be known");
        assert_eq!((p.dg_hash, p.econtent_hash, p.sig_hash), (256, 256, 256));
        assert_eq!((p.n, p.k), (120, 35));
        assert!(matches!(
            p.scheme,
            Scheme::Rsa {
                e: 65537,
                bits: 4096
            }
        ));
    }

    #[test]
    fn parses_mixed_hash_algorithms() {
        // Real deployed circuit: dg1 hashed with sha1, the rest with sha256.
        let p = lookup("register_sha1_sha256_sha256_rsa_65537_4096").expect("should be known");
        assert_eq!((p.dg_hash, p.econtent_hash, p.sig_hash), (160, 256, 256));
    }

    #[test]
    fn unknown_circuit_returns_none() {
        assert!(lookup("register_sha256_sha256_sha256_rsa_99991_4096").is_none());
        assert!(lookup("definitely_not_a_circuit").is_none());
    }

    /// The drift guard. Parses the sibling monorepo's instance files and asserts our
    /// table agrees on (n, k) for every circuit we claim to support. Skips with a
    /// message when the monorepo is not checked out, so CI here never requires it.
    #[test]
    fn table_matches_the_monorepo_instance_files() {
        let root = std::path::Path::new("../self/circuits/circuits");
        if !root.exists() {
            eprintln!("SKIP: sibling monorepo not present at {}", root.display());
            return;
        }
        let mut checked = 0usize;
        for family in ["register", "register_id"] {
            let dir = root.join(family).join("instances");
            if !dir.exists() {
                continue;
            }
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                // register_kyc.circom lives alongside the REGISTER(...)/REGISTER_ID(...)
                // instances in register/instances/ but instantiates REGISTER_KYC(),
                // which takes no template arguments at all. That's a category
                // difference, not an unhandled case: KYC signs with EdDSA over
                // BabyJubJub field elements, which has no limb layout to drift-check
                // in the first place. register_aadhaar, by contrast, DOES have a real
                // (n, k) = (121, 17) used for actual big-integer reassembly (Task 5),
                // so it stays in this loop — parse_instance_n_k handles its
                // REGISTER_AADHAAR(n, k, maxDataLength) layout above.
                if stem == "register_kyc" {
                    continue;
                }
                let Some(ours) = lookup(stem) else { continue }; // unsupported: fine
                let src = std::fs::read_to_string(&path).unwrap();
                let (n, k) = parse_instance_n_k(&src).unwrap_or_else(|| {
                    panic!("could not parse REGISTER args from {}", path.display())
                });
                assert_eq!(
                    (ours.n, ours.k),
                    (n, k),
                    "table drift for {stem}: table says {:?}, instance file says {:?}",
                    (ours.n, ours.k),
                    (n, k)
                );

                // Beyond (n, k): dg_hash, econtent_hash, and sig_hash are
                // derived from the circuit NAME by convention, and they
                // select every digest and both offset bounds
                // (passportVerifier.circom). A name<->instance divergence
                // there is a false-reject generator of exactly the class the
                // (n, k) guard above exists to prevent, so it gets the same
                // drift protection. register_aadhaar's REGISTER_AADHAAR(n, k,
                // maxDataLength) carries none of these three template
                // arguments (its hash widths and RSA-65537 scheme are fixed
                // in the circuit body, not passed in) — parse_instance_
                // hash_and_sig_algo returns None for it by design, so it is
                // excluded from this half of the check while staying in the
                // (n, k) check above.
                if let Some((dg_hash_arg, econtent_hash_arg, sig_algo_id)) =
                    parse_instance_hash_and_sig_algo(&src)
                {
                    assert_eq!(
                        ours.dg_hash, dg_hash_arg,
                        "dg_hash drift for {stem}: table says {}, instance file's 1st REGISTER \
                         arg says {}",
                        ours.dg_hash, dg_hash_arg
                    );
                    assert_eq!(
                        ours.econtent_hash, econtent_hash_arg,
                        "econtent_hash drift for {stem}: table says {}, instance file's 2nd \
                         REGISTER arg says {}",
                        ours.econtent_hash, econtent_hash_arg
                    );

                    let (expected_sig_hash, expected_exponent) =
                        signature_algorithm_hash_and_exponent(sig_algo_id).unwrap_or_else(|| {
                            panic!(
                                "{stem}: no entry in SIGNATURE_ALGORITHM_TABLE for \
                                 signatureAlgorithm id {sig_algo_id} (instance file's 3rd \
                                 REGISTER arg) — add it by reading signatureAlgorithm.circom, \
                                 do not guess"
                            )
                        });
                    assert_eq!(
                        ours.sig_hash, expected_sig_hash,
                        "sig_hash drift for {stem}: table says {}, but signatureAlgorithm id \
                         {sig_algo_id} (from the instance file) implies {}",
                        ours.sig_hash, expected_sig_hash
                    );
                    let Scheme::Rsa { e: ours_e, .. } = ours.scheme else {
                        panic!(
                            "{stem}: table's scheme is not Rsa, but the instance file's \
                             signatureAlgorithm id {sig_algo_id} is an RSA PKCS#1v15 id"
                        );
                    };
                    assert_eq!(
                        ours_e, expected_exponent,
                        "RSA exponent drift for {stem}: table says e={ours_e}, but \
                         signatureAlgorithm id {sig_algo_id} (from the instance file) implies \
                         e={expected_exponent}"
                    );
                }

                checked += 1;
            }
        }
        // Exact count, not just > 0: a future parser change that silently matched
        // only one file should fail loudly here, not slip through a bare non-zero check.
        assert_eq!(
            checked, 15,
            "expected to check 15 circuits (14 REGISTER/REGISTER_ID RSA instances + \
             register_aadhaar) but checked {checked} — table or instance coverage drifted"
        );
    }
}
