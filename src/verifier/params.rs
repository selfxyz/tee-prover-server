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
//! Scope for this table is deliberately narrow: RSA PKCS#1 v1.5, RSASSA-PSS, and
//! ECDSA (NIST curves only) passport (`register_*`) and EU-ID (`register_id_*`)
//! circuits, plus the fixed `register_aadhaar` and `register_kyc` instances.
//! Brainpool-curve ECDSA circuits are left out entirely on purpose — `lookup`
//! returns `None` for them and callers skip. A later plan may add them.
//!
//! For RSASSA-PSS rows, `salt_len` and `bits` (the minimum RSA key length) are
//! properties of the circuit's `signatureAlgorithm` ID, not of the circuit
//! name, per `signatureVerifier.circom`'s
//! `SALT_LEN = 64 if alg == 46 else getHashLength(alg) / 8` and
//! `KEY_LENGTH = getMinKeyLength(alg)`. Algorithm 46 (Denmark) is SHA-256 with
//! a 64-byte salt — the exception that proves the `hash/8` rule is not the
//! whole story. The circuit name happens to also embed matching numbers for
//! all 15 PSS rows today (see `PSS_SALT_AND_KEY_LENGTH` below); that is a
//! property of today's data, not something this code derives from.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    Rsa { e: u64, bits: u32 },
    // Constructed by `lookup` for the 15 RSASSA-PSS circuits (Plan 2). `bits`
    // is the minimum RSA key length (`getMinKeyLength`), not necessarily the
    // circuit's own name suffix — see this file's module doc.
    RsaPss { e: u64, salt_len: usize, bits: u32 },
    // Constructed by `lookup` for the 14 ECDSA NIST-curve circuits (Plan 3).
    // Unlike RSA/PSS there is no exponent to carry — ECDSA's public key is a
    // curve point, not a modulus/exponent pair — so this variant holds only
    // the curve name, taken verbatim from the circuit name's own trailing
    // component. Brainpool-curve circuits (also present in the same instance
    // directories) are out of scope for this plan and still return `None`
    // from `lookup`; a later plan may extend this table to cover them.
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

/// `(name, curve, n, k)` for the 14 ECDSA NIST-curve passport and EU-ID circuits,
/// transcribed verbatim from `../self/circuits/circuits/{register,register_id}/
/// instances/*_ecdsa_secp*.circom`'s `REGISTER`/`REGISTER_ID(DG_HASH, ECONTENT_HASH,
/// signatureAlgorithm, n, k, ...)` 4th/5th arguments, cross-checked against
/// `getHashLength`/`getKLengthFactor` in
/// `../self/circuits/circuits/utils/passport/signatureAlgorithm.circom`. `sig_hash`
/// is not stored here — same convention as `RSA_LIMBS` above, it comes from the
/// circuit name's own 3rd component via `sha_bits`. `n = 66` for secp521r1 is not a
/// typo: those limbs are not byte-aligned, and `chunks::bigint_from_limbs` (base-
/// `2^n`) handles it correctly; a byte-slicing shortcut would silently corrupt
/// secp521r1 keys. Algorithm 44 (secp224r1) has four live circuits, not two:
/// `sha256_sha224_sha224` and `sha256_sha256_sha224` differ in their eContent hash,
/// and both exist for `register` and `register_id` — deduplicating by curve or
/// algorithm id would drop two of them. Brainpool-curve instances live alongside
/// these in the same directories but are deliberately absent: out of scope for this
/// plan, so `lookup` returns `None` for them (the safe default — see this file's
/// module doc on the false-reject/false-accept asymmetry).
const ECDSA_LIMBS: &[(&str, &str, u32, u32)] = &[
    // register/instances/*.circom
    ("register_sha1_sha1_sha1_ecdsa_secp256r1", "secp256r1", 64, 4), // alg 7: ecdsa_sha1_secp256r1_256
    ("register_sha256_sha256_sha256_ecdsa_secp256r1", "secp256r1", 64, 4), // alg 8: ecdsa_sha256_secp256r1_256
    ("register_sha384_sha384_sha384_ecdsa_secp384r1", "secp384r1", 64, 6), // alg 9: ecdsa_sha384_secp384r1_384
    ("register_sha256_sha256_sha256_ecdsa_secp384r1", "secp384r1", 64, 6), // alg 23: ecdsa_sha256_secp384r1_384
    ("register_sha512_sha512_sha512_ecdsa_secp521r1", "secp521r1", 66, 8), // alg 41: ecdsa_sha512_secp521r1_521
    ("register_sha256_sha224_sha224_ecdsa_secp224r1", "secp224r1", 32, 7), // alg 44: ecdsa_sha224_secp224r1_224 (dg sha256/econtent sha224)
    ("register_sha256_sha256_sha224_ecdsa_secp224r1", "secp224r1", 32, 7), // alg 44: ecdsa_sha224_secp224r1_224 (dg sha256/econtent sha256)
    // register_id/instances/*.circom
    ("register_id_sha1_sha1_sha1_ecdsa_secp256r1", "secp256r1", 64, 4), // alg 7
    ("register_id_sha256_sha256_sha256_ecdsa_secp256r1", "secp256r1", 64, 4), // alg 8
    ("register_id_sha384_sha384_sha384_ecdsa_secp384r1", "secp384r1", 64, 6), // alg 9
    ("register_id_sha256_sha256_sha256_ecdsa_secp384r1", "secp384r1", 64, 6), // alg 23
    ("register_id_sha512_sha512_sha512_ecdsa_secp521r1", "secp521r1", 66, 8), // alg 41
    ("register_id_sha256_sha224_sha224_ecdsa_secp224r1", "secp224r1", 32, 7), // alg 44 (dg sha256/econtent sha224)
    ("register_id_sha256_sha256_sha224_ecdsa_secp224r1", "secp224r1", 32, 7), // alg 44 (dg sha256/econtent sha256)
];

/// `(name, salt_len bytes, key_bits)` for the 15 RSASSA-PSS passport and EU-ID
/// circuits. `salt_len` and `key_bits` are transcribed by applying
/// `signatureVerifier.circom`'s two rules —
/// `SALT_LEN = 64 if id == 46 else getHashLength(id) / 8` and
/// `KEY_LENGTH = getMinKeyLength(id)` — to each circuit's `signatureAlgorithm`
/// ID (the 3rd `REGISTER`/`REGISTER_ID` argument in its instance file), reading
/// `getHashLength` and `getMinKeyLength` from
/// `../self/circuits/circuits/utils/passport/signatureAlgorithm.circom`. They
/// are NOT read from the numbers embedded in the circuit name itself (the
/// `_32_`/`_64_`/`_48_` salt-length component and the trailing `_2048`/
/// `_3072`/`_4096` key-length component) — even though, for all 15 rows below,
/// the name's numbers happen to agree with these. That agreement is a
/// property of today's data, not a rule this table relies on: algorithm 46
/// (Denmark) is SHA-256 with a 64-byte salt, breaking the otherwise-universal
/// `hash/8` rule, which is exactly why this table exists instead of computing
/// `salt_len` from the name. `dg_hash`/`econtent_hash`/`sig_hash` still come
/// from the name's first three components, same convention as `RSA_LIMBS`
/// above; `(n, k)` is `(120, 35)` for all 15, same as every RSA PKCS#1 v1.5
/// row, so `lookup` uses that literal directly rather than repeating it here.
const PSS_SALT_AND_KEY_LENGTH: &[(&str, usize, u32)] = &[
    // register/instances/*.circom
    ("register_sha256_sha256_sha256_rsapss_65537_32_2048", 32, 2048), // id 4: rsapss_sha256_65537_2048
    ("register_sha512_sha512_sha256_rsapss_65537_32_2048", 32, 2048), // id 4: rsapss_sha256_65537_2048
    ("register_sha256_sha256_sha256_rsapss_65537_32_4096", 32, 4096), // id 12: rsapss_sha256_65537_4096
    ("register_sha256_sha256_sha256_rsapss_65537_32_3072", 32, 3072), // id 19: rsapss_sha256_65537_3072
    ("register_sha512_sha512_sha512_rsapss_65537_64_2048", 64, 2048), // id 42: rsapss_sha512_65537_2048
    ("register_sha256_sha256_sha256_rsapss_3_32_2048", 32, 2048), // id 43: rsapss_sha256_3_2048
    ("register_sha384_sha384_sha384_rsapss_65537_48_2048", 48, 2048), // id 45: rsapss_sha384_65537_2048
    ("register_sha256_sha256_sha256_rsapss_65537_64_2048", 64, 2048), // id 46: rsapss_sha256_65537_2048 salt 64
    // register_id/instances/*.circom
    ("register_id_sha256_sha256_sha256_rsapss_65537_32_2048", 32, 2048), // id 4: rsapss_sha256_65537_2048
    ("register_id_sha512_sha512_sha256_rsapss_65537_32_2048", 32, 2048), // id 4: rsapss_sha256_65537_2048
    ("register_id_sha256_sha256_sha256_rsapss_65537_32_3072", 32, 3072), // id 19: rsapss_sha256_65537_3072
    ("register_id_sha512_sha512_sha512_rsapss_65537_64_2048", 64, 2048), // id 42: rsapss_sha512_65537_2048
    ("register_id_sha256_sha256_sha256_rsapss_3_32_2048", 32, 2048), // id 43: rsapss_sha256_3_2048
    ("register_id_sha384_sha384_sha384_rsapss_65537_48_2048", 48, 2048), // id 45: rsapss_sha384_65537_2048
    ("register_id_sha256_sha256_sha256_rsapss_65537_64_2048", 64, 2048), // id 46: rsapss_sha256_65537_2048 salt 64
];

/// `(name, n, k)` for the 7 RSA PKCS#1 v1.5 DSC circuits (a CSCA signing a
/// DSC), transcribed verbatim from `../self/circuits/circuits/dsc/instances/
/// <name>.circom`'s `DSC(signatureAlgorithm, n, k)` 2nd/3rd arguments. All 7
/// currently use `(120, 35)`, same as every RSA PKCS#1 v1.5 `register`/
/// `register_id` circuit. DSC circuit names carry only one hash tag
/// (`dsc_<sig>_<scheme>`), unlike `register`'s three (`register_<dg>_
/// <econtent>_<sig>_<scheme>`) -- there is no dg1/eContent link at the DSC
/// level, see `lookup`'s DSC branch below.
const DSC_RSA_LIMBS: &[(&str, u32, u32)] = &[
    ("dsc_sha1_rsa_65537_4096", 120, 35),     // alg 11
    ("dsc_sha256_rsa_65537_4096", 120, 35),   // alg 10
    ("dsc_sha512_rsa_65537_4096", 120, 35),   // alg 15
    ("dsc_sha256_rsa_130689_4096", 120, 35),  // alg 48
    ("dsc_sha256_rsa_122125_4096", 120, 35),  // alg 49
    ("dsc_sha256_rsa_107903_4096", 120, 35),  // alg 50
    ("dsc_sha256_rsa_56611_4096", 120, 35),   // alg 51
];

/// `(name, curve, n, k)` for the 6 ECDSA NIST-curve DSC circuits, transcribed
/// verbatim from the same instance files' `DSC(signatureAlgorithm, n, k)`
/// arguments. The 6 brainpool-curve DSC circuits living alongside these in
/// the same directory are deliberately absent -- out of scope for this plan,
/// so `lookup` returns `None` for them (the safe default; see this file's
/// module doc on the false-reject/false-accept asymmetry).
const DSC_ECDSA_LIMBS: &[(&str, &str, u32, u32)] = &[
    ("dsc_sha1_ecdsa_secp256r1", "secp256r1", 64, 4),    // alg 7
    ("dsc_sha256_ecdsa_secp256r1", "secp256r1", 64, 4),  // alg 8
    ("dsc_sha384_ecdsa_secp384r1", "secp384r1", 64, 6),  // alg 9
    ("dsc_sha256_ecdsa_secp384r1", "secp384r1", 64, 6),  // alg 23
    ("dsc_sha256_ecdsa_secp521r1", "secp521r1", 66, 8),  // alg 40
    ("dsc_sha512_ecdsa_secp521r1", "secp521r1", 66, 8),  // alg 41
];

/// `(name, salt_len bytes, key_bits)` for the 5 RSASSA-PSS DSC circuits.
/// Same convention as `PSS_SALT_AND_KEY_LENGTH` above: derived by applying
/// `signatureVerifier.circom`'s `SALT_LEN = 64 if id == 46 else
/// getHashLength(id) / 8` and `KEY_LENGTH = getMinKeyLength(id)` to each
/// circuit's `signatureAlgorithm` ID (the 1st `DSC` argument), not read from
/// the circuit name's own embedded numbers (which happen to agree here, same
/// as every PSS row above).
const DSC_PSS_SALT_AND_KEY_LENGTH: &[(&str, usize, u32)] = &[
    ("dsc_sha256_rsapss_65537_32_4096", 32, 4096), // alg 12
    ("dsc_sha256_rsapss_3_32_3072", 32, 3072),     // alg 16
    ("dsc_sha384_rsapss_65537_48_3072", 48, 3072), // alg 18
    ("dsc_sha256_rsapss_65537_32_3072", 32, 3072), // alg 19
    ("dsc_sha512_rsapss_65537_64_4096", 64, 4096), // alg 39
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
/// cleanly, plus the 7 RSASSA-PSS IDs (4, 12, 19, 42, 43, 45, 46) that appear
/// across the 15 `PSS_SALT_AND_KEY_LENGTH` instance files. Exponents for the
/// exotic RSA PKCS#1 v1.5 IDs (47-51) are carried by the algorithm id itself
/// and are not reconstructible from `getExponentBits`, unlike every PSS id
/// here (3 and 65537 both are) — do not "simplify" this table into a formula.
/// ECDSA IDs are omitted entirely — out of scope so far, and `lookup` already
/// returns `None` for those circuit names, so the drift test below never
/// needs an entry for them.
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
    (4, 256, 65537),   // rsapss_sha256_65537_2048
    (10, 256, 65537),  // rsa_sha256_65537_4096
    (11, 160, 65537),  // rsa_sha1_65537_4096
    (12, 256, 65537),  // rsapss_sha256_65537_4096
    (13, 256, 3),      // rsa_sha256_3_2048
    (14, 256, 65537),  // rsa_sha256_65537_3072
    (15, 512, 65537),  // rsa_sha512_65537_4096
    (19, 256, 65537),  // rsapss_sha256_65537_3072
    (31, 512, 65537),  // rsa_sha512_65537_2048
    (32, 256, 3),      // rsa_sha256_3_4096
    (33, 160, 3),      // rsa_sha1_3_4096
    (34, 384, 65537),  // rsa_sha384_65537_4096
    (42, 512, 65537),  // rsapss_sha512_65537_2048
    (43, 256, 3),      // rsapss_sha256_3_2048
    (45, 384, 65537),  // rsapss_sha384_65537_2048
    (46, 256, 65537),  // rsapss_sha256_65537_2048 salt 64
    (47, 160, 64321),  // rsa_sha1_64321_4096
    (48, 256, 130689), // rsa_sha256_130689_4096
    (49, 256, 122125), // rsa_sha256_122125_4096
    (50, 256, 107903), // rsa_sha256_107903_4096
    (51, 256, 56611),  // rsa_sha256_56611_4096
    // The 3 RSASSA-PSS ids new to this crate (DSC circuits, see DSC_PSS_SALT_
    // AND_KEY_LENGTH below). Transcribed from signatureAlgorithm.circom's
    // "ID to Signature Algorithm" comment table and cross-checked against
    // getHashLength/getExponentBits there, same standard as every row above.
    (16, 256, 3),      // rsapss_sha256_3_3072 (getExponentBits(16) == 2 -> e=3)
    (18, 384, 65537),  // rsapss_sha384_65537_3072
    (39, 512, 65537),  // rsapss_sha512_65537_4096
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

/// `(signatureAlgorithm ID, minimum key length in bits)`, transcribed from
/// `getMinKeyLength(signatureAlgorithm)` in
/// `../self/circuits/circuits/utils/passport/signatureAlgorithm.circom`.
/// Limited to the 7 RSASSA-PSS IDs the drift guard below needs (the same 7
/// covered by `SIGNATURE_ALGORITHM_TABLE`'s PSS rows) — unlike RSA PKCS#1
/// v1.5, where the circuit's own name suffix already carries a key length
/// that's cross-checked elsewhere, PSS's `bits` field is this value
/// specifically (see `PSS_SALT_AND_KEY_LENGTH`'s doc comment), so this table
/// exists to let the drift guard recompute it independently.
///
/// Used only by the `#[cfg(test)]` drift guard below, hence `cfg_attr` rather
/// than a bare `#[allow(dead_code)]`.
#[cfg_attr(not(test), allow(dead_code))]
const MIN_KEY_LENGTH_TABLE: &[(u32, u32)] = &[
    (4, 2048),  // rsapss_sha256_65537_2048
    (12, 4096), // rsapss_sha256_65537_4096
    (19, 3072), // rsapss_sha256_65537_3072
    (42, 2048), // rsapss_sha512_65537_2048
    (43, 2048), // rsapss_sha256_3_2048
    (45, 2048), // rsapss_sha384_65537_2048
    (46, 2048), // rsapss_sha256_65537_2048 salt 64
    // New to this crate for the DSC circuits (see SIGNATURE_ALGORITHM_TABLE's
    // matching comment).
    (16, 3072), // rsapss_sha256_3_3072
    (18, 3072), // rsapss_sha384_65537_3072
    (39, 4096), // rsapss_sha512_65537_4096
];

/// Looks up `getMinKeyLength`'s result for a `signatureAlgorithm` ID from the
/// table above. Used only by the `#[cfg(test)]` drift guard below.
#[cfg_attr(not(test), allow(dead_code))]
fn min_key_length(id: u32) -> Option<u32> {
    MIN_KEY_LENGTH_TABLE
        .iter()
        .find(|(entry_id, _)| *entry_id == id)
        .map(|(_, bits)| *bits)
}

/// `(signatureAlgorithm ID, hash_bits)`, transcribed from `getHashLength` in
/// `../self/circuits/circuits/utils/passport/signatureAlgorithm.circom` for the 6
/// ECDSA NIST-curve IDs that appear as the `signatureAlgorithm` (3rd) argument
/// across the 14 `REGISTER`/`REGISTER_ID` instance files `ECDSA_LIMBS` covers.
/// Kept separate from `SIGNATURE_ALGORITHM_TABLE` rather than merged into it:
/// that table's shape is `(id, hash_bits, exponent)`, and ECDSA has no exponent
/// to put there (see `Scheme::Ecdsa`'s doc comment) — inventing one would be
/// meaningless, not just redundant.
///
/// Used only by the `#[cfg(test)]` drift guard below, hence `cfg_attr` rather
/// than a bare `#[allow(dead_code)]`.
#[cfg_attr(not(test), allow(dead_code))]
const ECDSA_ALGORITHM_TABLE: &[(u32, u32)] = &[
    (7, 160),  // ecdsa_sha1_secp256r1_256
    (8, 256),  // ecdsa_sha256_secp256r1_256
    (9, 384),  // ecdsa_sha384_secp384r1_384
    (23, 256), // ecdsa_sha256_secp384r1_384
    (41, 512), // ecdsa_sha512_secp521r1_521
    (44, 224), // ecdsa_sha224_secp224r1_224
    // New to this crate for the DSC circuits: ecdsa_sha256_secp521r1_256.
    // Transcribed from signatureAlgorithm.circom's "ID to Signature Algorithm"
    // comment table and getHashLength, same standard as every row above.
    (40, 256), // ecdsa_sha256_secp521r1_256
];

/// Looks up `getHashLength`'s result for an ECDSA `signatureAlgorithm` ID from the
/// table above. Used only by the `#[cfg(test)]` drift guard below.
#[cfg_attr(not(test), allow(dead_code))]
fn ecdsa_algorithm_hash_bits(id: u32) -> Option<u32> {
    ECDSA_ALGORITHM_TABLE
        .iter()
        .find(|(entry_id, _)| *entry_id == id)
        .map(|(_, hash_bits)| *hash_bits)
}

pub fn lookup(name: &str) -> Option<CircuitParams> {
    // DSC circuits (a CSCA signing a DSC) get a dedicated branch, not a fall-
    // through into the register parsing below. `dsc_<sig>_<scheme>` carries
    // only ONE hash component; `register_<dg>_<econtent>_<sig>_<scheme>`
    // carries THREE. Reusing the register split logic here would silently
    // misread every DSC name (e.g. reading "rsa" as if it were parts[3] of a
    // 6-part register name) and produce a wrong sig_hash -- a false reject,
    // not a safe skip. See lookup_dsc's own doc comment.
    if let Some(rest) = name.strip_prefix("dsc_") {
        return lookup_dsc(name, rest);
    }

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

    // RSASSA-PSS: `salt_len` and `bits` come from PSS_SALT_AND_KEY_LENGTH
    // (id-derived, per this file's module doc), never from parts[5]/parts[6]
    // below even though those numbers happen to agree for all 15 rows today.
    if parts[3] == "rsapss" {
        if parts.len() != 7 {
            return None;
        }
        let e: u64 = parts[4].parse().ok()?;
        // parts[5] (salt) and parts[6] (bits) are the name's own embedded
        // numbers and are intentionally unused here — see PSS_SALT_AND_
        // KEY_LENGTH's doc comment.

        let (salt_len, bits) = PSS_SALT_AND_KEY_LENGTH
            .iter()
            .find(|(entry_name, _, _)| *entry_name == name)
            .map(|(_, salt_len, bits)| (*salt_len, *bits))?;

        return Some(CircuitParams {
            dg_hash,
            econtent_hash,
            sig_hash,
            scheme: Scheme::RsaPss { e, salt_len, bits },
            n: 120,
            k: 35,
        });
    }

    // ECDSA (NIST curves): curve comes from the circuit name's own trailing
    // component; (n, k) is transcribed in ECDSA_LIMBS (this file's module
    // doc explains why there is no exponent to carry). Brainpool-curve names
    // fall through this `find` unmatched and hit the `?`, returning `None` —
    // the safe default for the out-of-scope case.
    if parts[3] == "ecdsa" {
        if parts.len() != 5 {
            return None;
        }
        let (curve, n, k) = ECDSA_LIMBS
            .iter()
            .find(|(entry_name, _, _, _)| *entry_name == name)
            .map(|(_, curve, n, k)| (*curve, *n, *k))?;

        return Some(CircuitParams {
            dg_hash,
            econtent_hash,
            sig_hash,
            scheme: Scheme::Ecdsa {
                curve: curve.to_string(),
            },
            n,
            k,
        });
    }

    // Only RSA PKCS#1 v1.5 is left; RSASSA-PSS and ECDSA (NIST curves) are
    // handled above.
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

/// Parses a DSC circuit's name, already stripped of its `dsc_` prefix, into
/// `CircuitParams`. Deliberately separate from the `register`/`register_id`
/// parsing in `lookup` above: a DSC circuit name is `<sig>_<scheme>` (one hash
/// tag), not `<dg>_<econtent>_<sig>_<scheme>` (three) — there is no dg1 or
/// eContent link at the DSC level (a CSCA signs a DSC certificate, not a
/// passport data group), so there is nothing for two of those three
/// components to name. `dg_hash` and `econtent_hash` in the returned
/// `CircuitParams` are set to `sig_hash` and are N/A — same precedent as
/// `register_aadhaar` above: a plausible-looking placeholder is safer than an
/// invented distinct value, because `dsc::verify` (Task 2) must never read
/// either field, and a wrong-but-plausible value is a false-reject risk if
/// that invariant is ever violated by accident.
fn lookup_dsc(name: &str, rest: &str) -> Option<CircuitParams> {
    let parts: Vec<&str> = rest.split('_').collect();
    if parts.len() < 2 {
        return None;
    }
    let sig_hash = sha_bits(parts[0])?;
    // N/A: DSC (a CSCA signing a DSC cert) has no dg1<->eContent<->signed_attr
    // chain to describe at all -- see this function's doc comment.
    let dg_hash = sig_hash;
    let econtent_hash = sig_hash;

    if parts[1] == "rsapss" {
        if parts.len() != 5 {
            return None;
        }
        let e: u64 = parts[2].parse().ok()?;
        // parts[3] (salt) and parts[4] (bits) are the name's own embedded
        // numbers and are intentionally unused here -- same convention as
        // PSS_SALT_AND_KEY_LENGTH above: salt_len/bits come from the
        // algorithm id via DSC_PSS_SALT_AND_KEY_LENGTH, never the name.
        let (salt_len, bits) = DSC_PSS_SALT_AND_KEY_LENGTH
            .iter()
            .find(|(entry_name, _, _)| *entry_name == name)
            .map(|(_, salt_len, bits)| (*salt_len, *bits))?;

        return Some(CircuitParams {
            dg_hash,
            econtent_hash,
            sig_hash,
            scheme: Scheme::RsaPss { e, salt_len, bits },
            n: 120,
            k: 35,
        });
    }

    if parts[1] == "ecdsa" {
        if parts.len() != 3 {
            return None;
        }
        let (curve, n, k) = DSC_ECDSA_LIMBS
            .iter()
            .find(|(entry_name, _, _, _)| *entry_name == name)
            .map(|(_, curve, n, k)| (*curve, *n, *k))?;

        return Some(CircuitParams {
            dg_hash,
            econtent_hash,
            sig_hash,
            scheme: Scheme::Ecdsa {
                curve: curve.to_string(),
            },
            n,
            k,
        });
    }

    // Only RSA PKCS#1 v1.5 is left; RSASSA-PSS and ECDSA (NIST curves) are
    // handled above.
    if parts[1] != "rsa" {
        return None;
    }
    if parts.len() != 4 {
        return None;
    }
    let e: u64 = parts[2].parse().ok()?;
    let bits: u32 = parts[3].parse().ok()?;

    let (n, k) = DSC_RSA_LIMBS
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

/// Finds a `DSC(...)` call and returns its `(signatureAlgorithm, n, k)`
/// arguments. `DSC(alg, n, k)` is a different template from `REGISTER(...)`/
/// `REGISTER_ID(...)` in both shape and argument order: `alg` is the 1st
/// argument here (the 3rd for `REGISTER`/`REGISTER_ID`), and there is no
/// dg_hash/econtent_hash pair at all. Reusing `parse_instance_hash_and_sig_
/// algo`/`parse_instance_n_k` on a DSC instance file would misread `n` as
/// `alg` and so on -- exactly the false-reject-generating mistake this file's
/// module doc and `lookup_dsc` both warn about, now also guarded against on
/// the drift-test side.
///
/// Used only by the `#[cfg(test)]` drift guard below.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_dsc_instance_alg_n_k(src: &str) -> Option<(u32, u32, u32)> {
    let args = extract_args(src, "DSC(")?;
    if args.len() < 3 {
        return None;
    }
    let alg: u32 = args[0].parse().ok()?;
    let n: u32 = args[1].parse().ok()?;
    let k: u32 = args[2].parse().ok()?;
    Some((alg, n, k))
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

    #[test]
    fn pss_rows_match_the_circuit_derived_salt_and_key_length() {
        // (name, alg, hash_bits, salt_len, key_bits, e)
        let expect = [
            ("register_sha256_sha256_sha256_rsapss_65537_32_2048", 4, 256, 32, 2048, 65537),
            ("register_sha512_sha512_sha256_rsapss_65537_32_2048", 4, 256, 32, 2048, 65537),
            ("register_id_sha256_sha256_sha256_rsapss_65537_32_2048", 4, 256, 32, 2048, 65537),
            ("register_id_sha512_sha512_sha256_rsapss_65537_32_2048", 4, 256, 32, 2048, 65537),
            ("register_sha256_sha256_sha256_rsapss_65537_32_4096", 12, 256, 32, 4096, 65537),
            ("register_sha256_sha256_sha256_rsapss_65537_32_3072", 19, 256, 32, 3072, 65537),
            ("register_id_sha256_sha256_sha256_rsapss_65537_32_3072", 19, 256, 32, 3072, 65537),
            ("register_sha512_sha512_sha512_rsapss_65537_64_2048", 42, 512, 64, 2048, 65537),
            ("register_id_sha512_sha512_sha512_rsapss_65537_64_2048", 42, 512, 64, 2048, 65537),
            ("register_sha256_sha256_sha256_rsapss_3_32_2048", 43, 256, 32, 2048, 3),
            ("register_id_sha256_sha256_sha256_rsapss_3_32_2048", 43, 256, 32, 2048, 3),
            ("register_sha384_sha384_sha384_rsapss_65537_48_2048", 45, 384, 48, 2048, 65537),
            ("register_id_sha384_sha384_sha384_rsapss_65537_48_2048", 45, 384, 48, 2048, 65537),
            ("register_sha256_sha256_sha256_rsapss_65537_64_2048", 46, 256, 64, 2048, 65537),
            ("register_id_sha256_sha256_sha256_rsapss_65537_64_2048", 46, 256, 64, 2048, 65537),
        ];
        assert_eq!(expect.len(), 15);
        for (name, _alg, hash_bits, salt_len, key_bits, e) in expect {
            let p = lookup(name).unwrap_or_else(|| panic!("no params for {name}"));
            assert_eq!(p.sig_hash, hash_bits, "sig_hash for {name}");
            match p.scheme {
                Scheme::RsaPss { e: got_e, salt_len: got_salt, bits } => {
                    assert_eq!(got_e, e, "exponent for {name}");
                    assert_eq!(got_salt, salt_len, "salt for {name}");
                    assert_eq!(bits, key_bits, "key bits for {name}");
                }
                other => panic!("{name} is not RsaPss: {other:?}"),
            }
        }
    }

    #[test]
    fn alg_46_is_the_salt_rule_exception_and_is_pinned() {
        // sha256 with a 64-byte salt. If this ever reads 32, the salt is being
        // derived from the hash length instead of the algorithm id, and every
        // Danish passport would be falsely rejected.
        let p = lookup("register_sha256_sha256_sha256_rsapss_65537_64_2048").unwrap();
        assert!(matches!(p.scheme, Scheme::RsaPss { salt_len: 64, .. }));
        assert_eq!(p.sig_hash, 256);
    }

    #[test]
    fn ecdsa_rows_match_the_inventory_table() {
        // (name, curve, n, k, sig_hash) -- see task-2-brief.md's inventory table.
        let expect = [
            ("register_sha1_sha1_sha1_ecdsa_secp256r1", "secp256r1", 64, 4, 160), // alg 7
            ("register_id_sha1_sha1_sha1_ecdsa_secp256r1", "secp256r1", 64, 4, 160), // alg 7
            ("register_sha256_sha256_sha256_ecdsa_secp256r1", "secp256r1", 64, 4, 256), // alg 8
            ("register_id_sha256_sha256_sha256_ecdsa_secp256r1", "secp256r1", 64, 4, 256), // alg 8
            ("register_sha384_sha384_sha384_ecdsa_secp384r1", "secp384r1", 64, 6, 384), // alg 9
            ("register_id_sha384_sha384_sha384_ecdsa_secp384r1", "secp384r1", 64, 6, 384), // alg 9
            ("register_sha256_sha256_sha256_ecdsa_secp384r1", "secp384r1", 64, 6, 256), // alg 23
            ("register_id_sha256_sha256_sha256_ecdsa_secp384r1", "secp384r1", 64, 6, 256), // alg 23
            ("register_sha512_sha512_sha512_ecdsa_secp521r1", "secp521r1", 66, 8, 512), // alg 41
            ("register_id_sha512_sha512_sha512_ecdsa_secp521r1", "secp521r1", 66, 8, 512), // alg 41
            ("register_sha256_sha224_sha224_ecdsa_secp224r1", "secp224r1", 32, 7, 224), // alg 44
            ("register_sha256_sha256_sha224_ecdsa_secp224r1", "secp224r1", 32, 7, 224), // alg 44
            ("register_id_sha256_sha224_sha224_ecdsa_secp224r1", "secp224r1", 32, 7, 224), // alg 44
            ("register_id_sha256_sha256_sha224_ecdsa_secp224r1", "secp224r1", 32, 7, 224), // alg 44
        ];
        assert_eq!(expect.len(), 14);
        for (name, curve, n, k, sig_hash) in expect {
            let p = lookup(name).unwrap_or_else(|| panic!("no params for {name}"));
            assert_eq!(p.sig_hash, sig_hash, "sig_hash for {name}");
            assert_eq!((p.n, p.k), (n, k), "(n, k) for {name}");
            match &p.scheme {
                Scheme::Ecdsa { curve: got_curve } => {
                    assert_eq!(got_curve, curve, "curve for {name}");
                }
                other => panic!("{name} is not Ecdsa: {other:?}"),
            }
        }
    }

    #[test]
    fn every_ecdsa_row_s_curve_string_is_recognized_by_the_primitive() {
        // Fix wave item 3: ECDSA_LIMBS's curve strings and
        // primitives::ecdsa::Curve::from_name's match arms are two
        // independently maintained lists that happen to agree today. A typo
        // in a future row (or a Curve::from_name arm renamed out of step)
        // would not fail to compile -- lookup would just build a
        // Scheme::Ecdsa{curve} that Curve::from_name can't parse, and
        // passport::verify degrades that to Skipped, silently, for every
        // document on that circuit. This loops every row in ECDSA_LIMBS
        // (not a hand-copied subset) so a future 15th row is covered
        // automatically.
        use crate::verifier::primitives::ecdsa::Curve;

        assert_eq!(ECDSA_LIMBS.len(), 14, "update this test if ECDSA_LIMBS gains/loses rows");
        for (name, curve, _n, _k) in ECDSA_LIMBS {
            let p = lookup(name).unwrap_or_else(|| panic!("no params for {name}"));
            match &p.scheme {
                Scheme::Ecdsa { curve: got_curve } => {
                    assert_eq!(got_curve, curve, "lookup({name})'s curve string diverged from ECDSA_LIMBS");
                }
                other => panic!("{name} is not Ecdsa: {other:?}"),
            }
            assert!(
                Curve::from_name(curve).is_some(),
                "ECDSA_LIMBS row {name} carries curve string {curve:?}, which \
                 Curve::from_name does not recognize -- this circuit would silently \
                 degrade to Skipped for every document"
            );
        }
    }

    #[test]
    fn secp521r1_uses_non_byte_aligned_66_bit_limbs() {
        // n = 66 is not a typo: secp521r1's 521-bit field does not divide evenly
        // into byte-sized limbs. If this ever reads 64 (the "normal" NIST-curve
        // limb size), chunks::bigint_from_limbs would silently misassemble the
        // key/signature.
        let p = lookup("register_sha512_sha512_sha512_ecdsa_secp521r1").unwrap();
        assert_eq!((p.n, p.k), (66, 8));
    }

    #[test]
    fn alg_44_has_four_distinct_circuits_not_two() {
        // sha256_sha224_sha224 and sha256_sha256_sha224 differ in eContent hash and
        // both exist for register and register_id -- deduplicating by curve or
        // algorithm id would silently drop two live circuits.
        for name in [
            "register_sha256_sha224_sha224_ecdsa_secp224r1",
            "register_sha256_sha256_sha224_ecdsa_secp224r1",
            "register_id_sha256_sha224_sha224_ecdsa_secp224r1",
            "register_id_sha256_sha256_sha224_ecdsa_secp224r1",
        ] {
            assert!(lookup(name).is_some(), "missing {name}");
        }
    }

    #[test]
    fn brainpool_ecdsa_circuits_are_still_out_of_scope() {
        // Brainpool instance files exist alongside the NIST-curve ones this plan
        // covers, but are deliberately not in ECDSA_LIMBS. Absent row -> None ->
        // Skipped, the safe default per this file's module doc.
        assert!(lookup("register_sha256_sha256_sha256_ecdsa_brainpoolP256r1").is_none());
        assert!(lookup("register_id_sha256_sha256_sha256_ecdsa_brainpoolP256r1").is_none());
    }

    #[test]
    fn dsc_rows_match_the_inventory_table() {
        // (name, n, k, sig_hash) -- see task-1-brief.md's Circuit inventory table.
        // scheme details (exponent / curve) are asserted per-branch below.
        let rsa = [
            ("dsc_sha1_rsa_65537_4096", 120, 35, 160, 65537u64),   // alg 11
            ("dsc_sha256_rsa_65537_4096", 120, 35, 256, 65537),    // alg 10
            ("dsc_sha512_rsa_65537_4096", 120, 35, 512, 65537),    // alg 15
            ("dsc_sha256_rsa_130689_4096", 120, 35, 256, 130689),  // alg 48
            ("dsc_sha256_rsa_122125_4096", 120, 35, 256, 122125),  // alg 49
            ("dsc_sha256_rsa_107903_4096", 120, 35, 256, 107903),  // alg 50
            ("dsc_sha256_rsa_56611_4096", 120, 35, 256, 56611),    // alg 51
        ];
        for (name, n, k, sig_hash, e) in rsa {
            let p = lookup(name).unwrap_or_else(|| panic!("no params for {name}"));
            assert_eq!(p.sig_hash, sig_hash, "sig_hash for {name}");
            assert_eq!((p.n, p.k), (n, k), "(n, k) for {name}");
            match p.scheme {
                Scheme::Rsa { e: got_e, .. } => assert_eq!(got_e, e, "exponent for {name}"),
                other => panic!("{name} is not Rsa: {other:?}"),
            }
        }

        let pss = [
            ("dsc_sha256_rsapss_65537_32_4096", 256, 65537u64, 32usize, 4096u32), // alg 12
            ("dsc_sha256_rsapss_3_32_3072", 256, 3, 32, 3072),                    // alg 16
            ("dsc_sha384_rsapss_65537_48_3072", 384, 65537, 48, 3072),            // alg 18
            ("dsc_sha256_rsapss_65537_32_3072", 256, 65537, 32, 3072),            // alg 19
            ("dsc_sha512_rsapss_65537_64_4096", 512, 65537, 64, 4096),            // alg 39
        ];
        for (name, sig_hash, e, salt_len, bits) in pss {
            let p = lookup(name).unwrap_or_else(|| panic!("no params for {name}"));
            assert_eq!(p.sig_hash, sig_hash, "sig_hash for {name}");
            assert_eq!((p.n, p.k), (120, 35), "(n, k) for {name}");
            match p.scheme {
                Scheme::RsaPss { e: got_e, salt_len: got_salt, bits: got_bits } => {
                    assert_eq!(got_e, e, "exponent for {name}");
                    assert_eq!(got_salt, salt_len, "salt for {name}");
                    assert_eq!(got_bits, bits, "key bits for {name}");
                }
                other => panic!("{name} is not RsaPss: {other:?}"),
            }
        }

        let ecdsa = [
            ("dsc_sha1_ecdsa_secp256r1", "secp256r1", 64, 4, 160),   // alg 7
            ("dsc_sha256_ecdsa_secp256r1", "secp256r1", 64, 4, 256), // alg 8
            ("dsc_sha384_ecdsa_secp384r1", "secp384r1", 64, 6, 384), // alg 9
            ("dsc_sha256_ecdsa_secp384r1", "secp384r1", 64, 6, 256), // alg 23
            ("dsc_sha256_ecdsa_secp521r1", "secp521r1", 66, 8, 256), // alg 40
            ("dsc_sha512_ecdsa_secp521r1", "secp521r1", 66, 8, 512), // alg 41
        ];
        for (name, curve, n, k, sig_hash) in ecdsa {
            let p = lookup(name).unwrap_or_else(|| panic!("no params for {name}"));
            assert_eq!(p.sig_hash, sig_hash, "sig_hash for {name}");
            assert_eq!((p.n, p.k), (n, k), "(n, k) for {name}");
            match &p.scheme {
                Scheme::Ecdsa { curve: got_curve } => assert_eq!(got_curve, curve, "curve for {name}"),
                other => panic!("{name} is not Ecdsa: {other:?}"),
            }
        }

        assert_eq!(rsa.len() + pss.len() + ecdsa.len(), 18, "expected exactly 18 DSC rows");
    }

    #[test]
    fn dsc_rows_have_no_meaning_for_dg_or_econtent_hash() {
        // dsc_<sig>_<scheme> has no dg1<->eContent link at all -- there is no
        // register-style 3-hash chain to describe. Following the register_aadhaar
        // precedent above: dg_hash/econtent_hash are set to sig_hash as an
        // explicit "not applicable" placeholder. dsc::verify (Task 2) must never
        // read either field for a DSC circuit.
        let p = lookup("dsc_sha256_rsa_65537_4096").unwrap();
        assert_eq!(p.dg_hash, p.sig_hash);
        assert_eq!(p.econtent_hash, p.sig_hash);
    }

    #[test]
    fn brainpool_dsc_circuits_are_out_of_scope() {
        // The 6 brainpool DSC circuits get no rows -- lookup returns None and
        // callers skip. Skipped is always safe (see this file's module doc on
        // the false-reject/false-accept asymmetry); a wrong row would not be.
        for name in [
            "dsc_sha1_ecdsa_brainpoolP256r1",
            "dsc_sha256_ecdsa_brainpoolP256r1",
            "dsc_sha256_ecdsa_brainpoolP384r1",
            "dsc_sha384_ecdsa_brainpoolP384r1",
            "dsc_sha384_ecdsa_brainpoolP512r1",
            "dsc_sha512_ecdsa_brainpoolP512r1",
        ] {
            assert!(lookup(name).is_none(), "{name} should be out of scope");
        }
    }

    #[test]
    fn dsc_prefix_does_not_fall_through_to_register_parsing() {
        // The trap this task exists to avoid: `dsc_<sig>_<scheme>` carries one
        // hash component, not three. If a DSC name ever fell through into the
        // register branch's `strip_prefix`/`split('_')` logic, it would either
        // return None (safe) or, worse, silently misassign parts[0..2] as
        // dg/econtent/sig and misparse the scheme suffix. Every case below must
        // resolve via the dedicated DSC branch, never register's.
        assert!(!"dsc_sha256_rsa_65537_4096".starts_with("register"));
        let p = lookup("dsc_sha256_rsa_65537_4096").unwrap();
        // A register-shaped misparse of this DSC name would try to read
        // parts[3] as the scheme tag ("rsa_65537_4096" split further) rather
        // than parts[1] ("rsa") -- i.e. it would not even find "rsa" as
        // parts[3] here (parts[3] would be out of range for a 4-part rest),
        // and Option::? would return None. Getting `Some` at all here is
        // already proof the DSC branch (not a register fallthrough) fired.
        assert_eq!(p.sig_hash, 256);
        assert!(matches!(p.scheme, Scheme::Rsa { e: 65537, bits: 4096 }));
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

                    // ECDSA has its own branch, checked first: it does not carry an
                    // exponent, so it cannot go through
                    // signature_algorithm_hash_and_exponent below (that table only
                    // has RSA/PSS ids and would panic on an ECDSA id that's
                    // legitimately absent from it).
                    if let Scheme::Ecdsa { .. } = ours.scheme {
                        let expected_sig_hash =
                            ecdsa_algorithm_hash_bits(sig_algo_id).unwrap_or_else(|| {
                                panic!(
                                    "{stem}: no entry in ECDSA_ALGORITHM_TABLE for \
                                     signatureAlgorithm id {sig_algo_id} (instance file's 3rd \
                                     REGISTER arg) — add it by reading getHashLength in \
                                     signatureAlgorithm.circom, do not guess"
                                )
                            });
                        assert_eq!(
                            ours.sig_hash, expected_sig_hash,
                            "sig_hash drift for {stem}: table says {}, but signatureAlgorithm \
                             id {sig_algo_id} (from the instance file) implies {} via \
                             getHashLength",
                            ours.sig_hash, expected_sig_hash
                        );

                        // ecdsaVerifier.circom:27-41 truncates the digest when
                        // HASH_LEN_BITS >= n*k and otherwise left-pads with zeros.
                        // The native path only implements the left-pad case (it
                        // agrees with RustCrypto's bits2field there); it does not
                        // implement truncation. If a future instance violates this,
                        // the native path would silently disagree with the circuit
                        // and could falsely reject real documents — mark that
                        // circuit Skipped, do not guess at truncation semantics.
                        let nk = ours.n * ours.k;
                        assert!(
                            expected_sig_hash <= nk,
                            "{stem}: HASH_LEN_BITS ({expected_sig_hash}) > n*k \
                             ({}*{}={nk}) — ecdsaVerifier.circom would truncate the digest \
                             here, and the native path does not implement truncation. Mark \
                             this circuit Skipped in params.rs, do not guess.",
                            ours.n, ours.k
                        );
                    } else {
                        let (expected_sig_hash, expected_exponent) =
                            signature_algorithm_hash_and_exponent(sig_algo_id).unwrap_or_else(
                                || {
                                    panic!(
                                        "{stem}: no entry in SIGNATURE_ALGORITHM_TABLE for \
                                         signatureAlgorithm id {sig_algo_id} (instance file's \
                                         3rd REGISTER arg) — add it by reading \
                                         signatureAlgorithm.circom, do not guess"
                                    )
                                },
                            );
                        assert_eq!(
                            ours.sig_hash, expected_sig_hash,
                            "sig_hash drift for {stem}: table says {}, but signatureAlgorithm id \
                             {sig_algo_id} (from the instance file) implies {}",
                            ours.sig_hash, expected_sig_hash
                        );
                        match ours.scheme {
                            Scheme::Rsa { e: ours_e, .. } => {
                                assert_eq!(
                                    ours_e, expected_exponent,
                                    "RSA exponent drift for {stem}: table says e={ours_e}, but \
                                     signatureAlgorithm id {sig_algo_id} (from the instance file) \
                                     implies e={expected_exponent}"
                                );
                            }
                            Scheme::RsaPss {
                                e: ours_e,
                                salt_len: ours_salt_len,
                                bits: ours_bits,
                            } => {
                                assert_eq!(
                                    ours_e, expected_exponent,
                                    "RSASSA-PSS exponent drift for {stem}: table says \
                                     e={ours_e}, but signatureAlgorithm id {sig_algo_id} (from \
                                     the instance file) implies e={expected_exponent}"
                                );

                                // SALT_LEN = 64 if alg == 46 else getHashLength(alg) / 8
                                // (signatureVerifier.circom:95). Algorithm 46 is the
                                // exception this whole guard exists to pin: SHA-256
                                // with a 64-byte salt, not the 32 the hash/8 rule
                                // would otherwise imply.
                                let expected_salt_len: usize = if sig_algo_id == 46 {
                                    64
                                } else {
                                    (expected_sig_hash / 8) as usize
                                };
                                assert_eq!(
                                    ours_salt_len, expected_salt_len,
                                    "salt_len drift for {stem}: table says \
                                     salt_len={ours_salt_len}, but signatureAlgorithm id \
                                     {sig_algo_id} (from the instance file) implies \
                                     salt_len={expected_salt_len} via SALT_LEN = 64 if alg == 46 \
                                     else getHashLength(alg) / 8"
                                );

                                // KEY_LENGTH = getMinKeyLength(alg) (signatureVerifier.circom:94).
                                let expected_key_bits =
                                    min_key_length(sig_algo_id).unwrap_or_else(|| {
                                        panic!(
                                            "{stem}: no entry in MIN_KEY_LENGTH_TABLE for \
                                             signatureAlgorithm id {sig_algo_id} (instance file's \
                                             3rd REGISTER arg) — add it by reading \
                                             getMinKeyLength in signatureAlgorithm.circom, do not \
                                             guess"
                                        )
                                    });
                                assert_eq!(
                                    ours_bits, expected_key_bits,
                                    "key_bits (KEY_LENGTH) drift for {stem}: table says \
                                     bits={ours_bits}, but signatureAlgorithm id {sig_algo_id} \
                                     (from the instance file) implies \
                                     bits={expected_key_bits} via getMinKeyLength"
                                );
                            }
                            other => panic!(
                                "{stem}: table's scheme is {other:?}, but the instance file's \
                                 signatureAlgorithm id {sig_algo_id} is an RSA PKCS#1v15 or \
                                 RSASSA-PSS id"
                            ),
                        }
                    }
                }

                checked += 1;
            }
        }

        // DSC(alg, n, k) is a different template from REGISTER(...)/
        // REGISTER_ID(...) -- different name, different argument order (alg
        // is 1st here, not 3rd), and no dg_hash/econtent_hash pair at all.
        // parse_dsc_instance_alg_n_k is a dedicated parser for exactly that
        // reason (see its doc comment). Unlike the register loop above, every
        // DSC instance file increments `checked` -- including the 6
        // brainpool ones -- because we assert *why* each None is expected
        // (brainpool) rather than silently `continue`-ing past it: that
        // gives this guard directory-completeness coverage (a stray 25th
        // DSC circuit that's neither supported nor brainpool fails loudly)
        // that the register loop's baseline count predates.
        let dsc_dir = root.join("dsc").join("instances");
        if dsc_dir.exists() {
            for entry in std::fs::read_dir(&dsc_dir).unwrap() {
                let path = entry.unwrap().path();
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let src = std::fs::read_to_string(&path).unwrap();
                let (alg, n, k) = parse_dsc_instance_alg_n_k(&src).unwrap_or_else(|| {
                    panic!("could not parse DSC(...) args from {}", path.display())
                });

                match lookup(stem) {
                    None => {
                        assert!(
                            stem.contains("brainpool"),
                            "{stem}: lookup returned None but this is not a brainpool \
                             circuit -- add a row to params.rs (or explain why it's still \
                             out of scope) instead of leaving it silently unsupported"
                        );
                    }
                    Some(ours) => {
                        assert_eq!(
                            (ours.n, ours.k),
                            (n, k),
                            "DSC table drift for {stem}: table says {:?}, instance file says \
                             {:?}",
                            (ours.n, ours.k),
                            (n, k)
                        );

                        if let Scheme::Ecdsa { .. } = ours.scheme {
                            let expected_sig_hash =
                                ecdsa_algorithm_hash_bits(alg).unwrap_or_else(|| {
                                    panic!(
                                        "{stem}: no entry in ECDSA_ALGORITHM_TABLE for \
                                         signatureAlgorithm id {alg} (instance file's 1st DSC \
                                         arg) — add it by reading getHashLength in \
                                         signatureAlgorithm.circom, do not guess"
                                    )
                                });
                            assert_eq!(
                                ours.sig_hash, expected_sig_hash,
                                "sig_hash drift for {stem}: table says {}, but \
                                 signatureAlgorithm id {alg} (from the instance file) implies \
                                 {} via getHashLength",
                                ours.sig_hash, expected_sig_hash
                            );

                            // Same truncation-avoidance check as the register loop above
                            // (ecdsaVerifier.circom:27-41): alg 40 (secp521r1, sha256) is
                            // the widest left-pad in the codebase at n*k = 66*8 = 528.
                            let nk = ours.n * ours.k;
                            assert!(
                                expected_sig_hash <= nk,
                                "{stem}: HASH_LEN_BITS ({expected_sig_hash}) > n*k \
                                 ({}*{}={nk}) — ecdsaVerifier.circom would truncate the \
                                 digest here, and the native path does not implement \
                                 truncation. Mark this circuit Skipped in params.rs, do not \
                                 guess.",
                                ours.n, ours.k
                            );
                        } else {
                            let (expected_sig_hash, expected_exponent) =
                                signature_algorithm_hash_and_exponent(alg).unwrap_or_else(|| {
                                    panic!(
                                        "{stem}: no entry in SIGNATURE_ALGORITHM_TABLE for \
                                         signatureAlgorithm id {alg} (instance file's 1st DSC \
                                         arg) — add it by reading signatureAlgorithm.circom, \
                                         do not guess"
                                    )
                                });
                            assert_eq!(
                                ours.sig_hash, expected_sig_hash,
                                "sig_hash drift for {stem}: table says {}, but \
                                 signatureAlgorithm id {alg} (from the instance file) implies \
                                 {}",
                                ours.sig_hash, expected_sig_hash
                            );
                            match ours.scheme {
                                Scheme::Rsa { e: ours_e, .. } => {
                                    assert_eq!(
                                        ours_e, expected_exponent,
                                        "RSA exponent drift for {stem}: table says \
                                         e={ours_e}, but signatureAlgorithm id {alg} (from \
                                         the instance file) implies e={expected_exponent}"
                                    );
                                }
                                Scheme::RsaPss {
                                    e: ours_e,
                                    salt_len: ours_salt_len,
                                    bits: ours_bits,
                                } => {
                                    assert_eq!(
                                        ours_e, expected_exponent,
                                        "RSASSA-PSS exponent drift for {stem}: table says \
                                         e={ours_e}, but signatureAlgorithm id {alg} (from \
                                         the instance file) implies e={expected_exponent}"
                                    );

                                    // No DSC id is 46 (the salt-64 exception), so the
                                    // hash/8 rule applies unconditionally here.
                                    let expected_salt_len: usize =
                                        (expected_sig_hash / 8) as usize;
                                    assert_eq!(
                                        ours_salt_len, expected_salt_len,
                                        "salt_len drift for {stem}: table says \
                                         salt_len={ours_salt_len}, but signatureAlgorithm id \
                                         {alg} (from the instance file) implies \
                                         salt_len={expected_salt_len} via \
                                         getHashLength(alg) / 8"
                                    );

                                    let expected_key_bits =
                                        min_key_length(alg).unwrap_or_else(|| {
                                            panic!(
                                                "{stem}: no entry in MIN_KEY_LENGTH_TABLE for \
                                                 signatureAlgorithm id {alg} (instance \
                                                 file's 1st DSC arg) — add it by reading \
                                                 getMinKeyLength in signatureAlgorithm.circom, \
                                                 do not guess"
                                            )
                                        });
                                    assert_eq!(
                                        ours_bits, expected_key_bits,
                                        "key_bits (KEY_LENGTH) drift for {stem}: table says \
                                         bits={ours_bits}, but signatureAlgorithm id {alg} \
                                         (from the instance file) implies \
                                         bits={expected_key_bits} via getMinKeyLength"
                                    );
                                }
                                other => panic!(
                                    "{stem}: table's scheme is {other:?}, but the instance \
                                     file's signatureAlgorithm id {alg} is an RSA PKCS#1v15 \
                                     or RSASSA-PSS id"
                                ),
                            }
                        }
                    }
                }

                checked += 1;
            }
        }

        // Exact count, not just > 0: a future parser change that silently matched
        // only one file should fail loudly here, not slip through a bare non-zero check.
        assert_eq!(
            checked, 68,
            "expected to check 68 circuits (44 REGISTER/REGISTER_ID + register_aadhaar, as \
             before, plus all 24 DSC instances -- 18 supported + 6 verified-brainpool) but \
             checked {checked} — table or instance coverage drifted"
        );
    }
}
