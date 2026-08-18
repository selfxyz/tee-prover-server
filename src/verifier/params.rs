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
    RsaPss { e: u64, salt_len: usize, bits: u32 },
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

pub fn lookup(name: &str) -> Option<CircuitParams> {
    // register_aadhaar.circom instantiates REGISTER_AADHAAR(121, 17, 512 * 3) — a
    // different template with a different argument order (n, k, maxDataLength).
    // (n, k) = (121, 17) is transcribed directly from that file's first two args.
    if name == "register_aadhaar" {
        return Some(CircuitParams {
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
