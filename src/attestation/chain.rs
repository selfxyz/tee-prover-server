use std::future::Future;
use std::str::FromStr;
use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};

use crate::attestation::{bootstrap::AttestationProof, EnclaveKey};

// Registration targets the HUB, not IdentityRegistryKycImplV1.
//
// The GCP JWT verification plumbing (verifier address, root-CA hash, PCR0Manager,
// authorized TEE) currently lives only on the KYC registry, which is why an earlier
// draft aimed here. But a prover key is orthogonal to attestation type — this server
// produces passport, EU ID, Aadhaar and KYC proofs alike — and registering it in a
// KYC-specific contract puts it one mapping away from checkPubkeyCommitment, which
// RegisterProofVerifierLib treats as KYC-attestor authority. The hub is the
// attestation-agnostic entry point and has nothing a prover key can be confused with.
//
// registerProverKey does not exist yet; this is written against the agreed signature
// so the feature can be enabled by flipping the `chain` flag. Regenerate this
// interface from the deployed ABI at switch-on rather than trusting the hand-written
// selector, and note the `20` is the gcp_jwt_verifier circuit's public-signal count
// (1 root-CA hash + 4 eat_nonce chunks + 3 image-hash chunks + 12 current_date).
sol! {
    #[sol(rpc)]
    interface IIdentityVerificationHubV2 {
        function registerProverKey(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[20] pubSignals) external;
    }
}

/// Celo Sepolia. Every enclave registers its attested key here: staging proves
/// against it, and production TEEs serve Sepolia proofs alongside mainnet ones.
pub const CELO_SEPOLIA_CHAIN_ID: u64 = 11142220;

/// Secret Manager prefix for the Celo Sepolia registration target.
///
/// Follows the convention self-terraform already establishes for
/// `PROVER_SECRET_PREFIX` (`main.tf`: `prover_secret_prefix =
/// "${var.environment}-PROVER_"`, giving `staging-PROVER_` and
/// `production-PROVER_`). This target is scoped to a chain rather than to an
/// environment -- only production enclaves ever read it, because a staging
/// enclave's primary prefix already points at Celo Sepolia -- so it is named
/// for the chain and sits as a peer of the two environment prefixes in the
/// shared namespace.
///
/// Deliberately NOT `staging-PROVER_`, even though those secrets also describe
/// Celo Sepolia: a production enclave reading staging's funded key is precisely
/// the mistake self-terraform's naming comment exists to prevent.
///
/// Hardcoded rather than delivered as a second env var, and deliberately so:
/// under Confidential Space a new env var means a new name in the
/// `tee.launch_policy.allow_env_override` label, which is part of the image and
/// therefore part of what PCR0 measures. Naming the secrets in the binary keeps
/// the launch policy untouched, and the values themselves stay in Secret
/// Manager -- so the Sepolia hub can be redeployed, or its RPC endpoint
/// rotated, by publishing a new secret version rather than by rebuilding the
/// image and re-allowlisting a new PCR0.
pub const SEPOLIA_SECRET_PREFIX: &str = "sepolia-PROVER_";

/// The per-chain secret suffixes, in the order `secret_names` returns them.
const CONFIG_SUFFIXES: [&str; 3] = ["RPC_URL", "HUB_ADDRESS", "TEE_PRIVATE_KEY"];

/// Attempts per network step, and the base of the exponential backoff between
/// them.
///
/// Registration is fatal by design (an enclave whose key was never registered
/// produces proofs every register call rejects), which puts a third-party RPC
/// endpoint squarely on the boot path. Without retries a momentary blip on the
/// Sepolia provider would take mainnet proving offline; with an unbounded
/// retry a genuine misconfiguration would never surface. Three tries, then
/// fail loudly.
pub const REGISTRATION_ATTEMPTS: u32 = 3;
pub const REGISTRATION_BACKOFF: Duration = Duration::from_secs(2);

/// The three Secret Manager secret ids one registration target is read from.
///
/// Every id is `<prefix><suffix>` -- the convention `PROVER_SECRET_PREFIX`
/// deployments already use, which the hardcoded Sepolia target reuses rather
/// than special-casing.
pub fn secret_names(prefix: &str) -> [String; 3] {
    CONFIG_SUFFIXES.map(|suffix| format!("{prefix}{suffix}"))
}

/// Whether a second, Celo Sepolia registration is needed on top of the primary
/// one.
///
/// A staging enclave's `PROVER_SECRET_PREFIX` already points at Celo Sepolia,
/// so registering again would be a duplicate; a production enclave's points at
/// mainnet, so it needs both. Keyed on the chain id the primary RPC reports
/// rather than on comparing hub addresses: a hub can be deployed to the same
/// address on two chains, and an address comparison would then silently skip
/// Sepolia for a production enclave -- a failure invisible until Sepolia starts
/// rejecting every proof that enclave signs.
pub fn needs_sepolia_registration(primary_chain_id: u64) -> bool {
    primary_chain_id != CELO_SEPOLIA_CHAIN_ID
}

/// One registration target: which chain to register on, and the funded key that
/// pays for it.
///
/// Every field arrives from Secret Manager, never from the process environment.
/// Under Confidential Space an env var is an instance-metadata value, readable
/// by anyone holding `compute.instances.get` on the project: `submitter_pk` is
/// a funded private key and a provider RPC URL routinely embeds an API key in
/// its path, so neither can travel that way. Constructing this type is the only
/// way to reach `register_prover_key`, which is what keeps that decision
/// enforceable -- there is no longer a positional string parameter an env read
/// could be threaded into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverChainConfig {
    pub rpc_url: String,
    pub hub_address: String,
    pub submitter_pk: String,
}

impl ProverChainConfig {
    /// Validates and normalises one target's three secret values.
    ///
    /// Blank fields are rejected here, at construction, rather than inside
    /// `register_prover_key`: with more than one target the whole plan is built
    /// before any transaction is sent, so a missing or empty secret must fail
    /// before the first registration rather than between two of them. Each boot
    /// mints a fresh enclave key, so a mainnet registration followed by a
    /// Sepolia config error would strand a key on mainnet permanently and spend
    /// mainnet gas again on every restart of the resulting crash loop.
    ///
    /// Naming which field is blank matters because all three come from Secret
    /// Manager: a blank one means a secret that is missing, empty, or wrong --
    /// the single most likely way this is misconfigured on first deploy.
    /// Without these guards an empty rpc url surfaces as a connection error and
    /// an empty hub address as an opaque parse failure, neither of which points
    /// at the secret.
    pub fn new(rpc_url: &str, hub_address: &str, submitter_pk: &str) -> Result<Self, String> {
        // The error deliberately does not interpolate any value: it is logged
        // and, on the boot path, becomes a panic message, and both destinations
        // outlive the process.
        if submitter_pk.trim().is_empty() {
            return Err("submitter key is empty".to_string());
        }
        if rpc_url.trim().is_empty() {
            return Err("rpc url is empty".to_string());
        }
        if hub_address.trim().is_empty() {
            return Err("hub address is empty".to_string());
        }
        // Trimmed once, here, rather than at each use site: a Secret Manager
        // payload routinely carries a trailing newline.
        Ok(Self {
            rpc_url: rpc_url.trim().to_string(),
            hub_address: hub_address.trim().to_string(),
            submitter_pk: submitter_pk.trim().to_string(),
        })
    }
}

/// Asks an RPC endpoint which chain it serves.
///
/// Read from the chain rather than configured alongside it, so the dedupe in
/// `needs_sepolia_registration` cannot be defeated by a stale or mistyped
/// constant in a secret.
pub async fn chain_id(rpc_url: &str) -> Result<u64, String> {
    let provider = ProviderBuilder::new()
        .connect(rpc_url.trim())
        .await
        .map_err(|e| format!("failed to connect to RPC_URL: {e}"))?;
    provider
        .get_chain_id()
        .await
        .map_err(|e| format!("eth_chainId failed: {e}"))
}

/// Runs `op` up to `attempts` times, sleeping `base_delay`, then twice that,
/// and so on between tries. Returns the last error if every attempt fails.
///
/// The attempt count is included in the error so a log line distinguishes a
/// step that was retried and still failed from one that was never retried.
pub async fn retry<T, F, Fut>(
    attempts: u32,
    base_delay: Duration,
    mut op: F,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let mut last = "no attempts were made".to_string();
    for attempt in 0..attempts {
        match op().await {
            Ok(value) => return Ok(value),
            Err(e) => {
                last = e;
                if attempt + 1 < attempts {
                    tokio::time::sleep(base_delay * 2u32.pow(attempt)).await;
                }
            }
        }
    }
    Err(format!("after {attempts} attempts: {last}"))
}

/// Parses one G2 coordinate pair and swaps it into the order Solidity reads.
///
/// Split out from `to_u256_array` so the swap is named rather than being an
/// index trick buried in a call site, and so a test can pin it directly.
fn swapped_g2_row(values: &[String], what: &str) -> Result<[alloy::primitives::U256; 2], String> {
    let [x, y] = to_u256_array::<2>(values, what)?;
    Ok([y, x])
}

fn to_u256_array<const N: usize>(values: &[String], what: &str) -> Result<[alloy::primitives::U256; N], String> {
    if values.len() != N {
        return Err(format!("{what} must have {N} elements, got {}", values.len()));
    }
    let mut out = [alloy::primitives::U256::ZERO; N];
    for (i, v) in values.iter().enumerate() {
        out[i] = alloy::primitives::U256::from_str_radix(v, 10)
            .map_err(|e| format!("bad {what}[{i}]: {e}"))?;
    }
    Ok(out)
}

/// Registers the enclave's attested signing key on one chain by submitting the
/// attestation proof to `IIdentityVerificationHubV2.registerProverKey`.
///
/// `key` identifies the attested signing key (its address is what gets
/// registered) but its private material never leaves enclave memory and is
/// never used here. The transaction itself is signed and paid for by
/// `config.submitter_pk`, a separate key that only exists to satisfy the
/// contract's `onlyProverTEE` check and pay gas — it is deliberately distinct
/// from the attested key and must never be conflated with or derived from it.
///
/// Called once per registration target: a production enclave registers the same
/// key on its primary chain and again on Celo Sepolia. The attestation proof
/// carries no chain binding (its public signals are the root-CA hash, the
/// eat_nonce that binds this enclave key, the image hash and the current date),
/// so the identical proof is valid on every chain running the same verifier —
/// which is what makes a second call the whole of the work. The corollary is
/// that the contract's own `onlyProverTEE` check on `msg.sender` is the only
/// thing preventing a third party from replaying an observed registration
/// elsewhere.
///
/// Every input is a parameter; this function reads no environment at all. See
/// `ProverChainConfig` for why that matters under Confidential Space.
pub async fn register_prover_key(
    _key: &EnclaveKey,
    attestation: &AttestationProof,
    config: &ProverChainConfig,
) -> Result<(), String> {
    // Validate the attestation's shape before touching env vars or the network.
    // `AttestationProof`'s fields are `pub` and this fn is public, so nothing
    // upstream guarantees `pi_b` has two rows the way `proof_digest` does on
    // its only current call path — index it only after checking.
    if attestation.proof.pi_b.len() != 2 {
        return Err(format!("pi_b must have exactly 2 rows, got {}", attestation.proof.pi_b.len()));
    }
    let a = to_u256_array::<2>(&attestation.proof.pi_a, "pi_a")?;
    // G2 coordinates are swapped within each pair before submission. A Groth16
    // prover writes pi_b in the library's own order; a Solidity pairing check
    // reads each Fp2 element imaginary-part-first, so the two disagree and the
    // proof simply fails to verify. The monorepo does the same swap wherever it
    // builds calldata -- see common/src/utils/contracts/formatCallData.ts, which
    // emits [b[0][1], b[0][0]] and [b[1][1], b[1][0]].
    //
    // Submitting the unswapped order made registerProverKey revert
    // InvalidProverProof (0x29a48461) from ProverAttestationLib: the transaction
    // reached the verifier and the verifier rejected the proof, which reads as a
    // bad attestation rather than a wire-format error.
    let b = [
        swapped_g2_row(&attestation.proof.pi_b[0], "pi_b[0]")?,
        swapped_g2_row(&attestation.proof.pi_b[1], "pi_b[1]")?,
    ];
    let c = to_u256_array::<2>(&attestation.proof.pi_c, "pi_c")?;
    let pub_signals = to_u256_array::<20>(&attestation.public_inputs, "public_inputs")?;

    // Blank and untrimmed values were already rejected by
    // `ProverChainConfig::new`, before any target's transaction was sent.

    // The error deliberately does not interpolate the key material.
    let signer = PrivateKeySigner::from_str(&config.submitter_pk)
        .map_err(|_| "submitter key is not a valid secp256k1 private key".to_string())?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(&config.rpc_url)
        .await
        .map_err(|e| format!("failed to connect to RPC_URL: {e}"))?;

    let addr = Address::from_str(&config.hub_address)
        .map_err(|e| format!("invalid hub address: {e}"))?;
    let contract = IIdentityVerificationHubV2::new(addr, provider);

    contract
        .registerProverKey(a, b, c, pub_signals)
        .send()
        .await
        .map_err(|e| format!("registerProverKey transaction failed to send: {e}"))?
        .watch()
        .await
        .map_err(|e| format!("registerProverKey transaction failed to confirm: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The swap is the whole point: a Groth16 prover emits each G2 coordinate pair
    /// in the library's order, and a Solidity pairing check reads it
    /// imaginary-part-first. Submitting the prover's order made
    /// registerProverKey revert InvalidProverProof (0x29a48461) -- the verifier
    /// was reached and rejected the proof.
    #[test]
    fn a_g2_row_is_swapped_for_solidity() {
        let row = vec!["11".to_string(), "22".to_string()];
        let out = swapped_g2_row(&row, "pi_b[0]").expect("must parse");
        assert_eq!(out[0], alloy::primitives::U256::from(22u64), "imaginary part must come first");
        assert_eq!(out[1], alloy::primitives::U256::from(11u64));
    }

    /// Matches common/src/utils/contracts/formatCallData.ts, which emits
    /// [b[0][1], b[0][0]] and [b[1][1], b[1][0]] -- the same transposition this
    /// repo must apply, pinned here so the two cannot drift apart silently.
    #[test]
    fn the_swap_matches_the_monorepos_calldata_ordering() {
        let r0 = vec!["1".to_string(), "2".to_string()];
        let r1 = vec!["3".to_string(), "4".to_string()];
        let b = [
            swapped_g2_row(&r0, "pi_b[0]").unwrap(),
            swapped_g2_row(&r1, "pi_b[1]").unwrap(),
        ];
        let u = |n: u64| alloy::primitives::U256::from(n);
        assert_eq!(b, [[u(2), u(1)], [u(4), u(3)]]);
    }

    #[test]
    fn a_malformed_g2_row_is_still_rejected() {
        let err = swapped_g2_row(&vec!["1".to_string()], "pi_b[0]").unwrap_err();
        assert_eq!(err, "pi_b[0] must have 2 elements, got 1");
    }

    #[test]
    fn to_u256_array_rejects_short_input() {
        let values = vec!["1".to_string()];
        let err = to_u256_array::<2>(&values, "pi_a").unwrap_err();
        assert_eq!(err, "pi_a must have 2 elements, got 1");
    }

    #[test]
    fn to_u256_array_rejects_long_input() {
        let values = vec!["1".to_string(), "2".to_string(), "3".to_string()];
        let err = to_u256_array::<2>(&values, "pi_a").unwrap_err();
        assert_eq!(err, "pi_a must have 2 elements, got 3");
    }

    #[test]
    fn to_u256_array_rejects_non_decimal_string() {
        let values = vec!["not_a_number".to_string(), "2".to_string()];
        let err = to_u256_array::<2>(&values, "pi_a").unwrap_err();
        assert!(err.starts_with("bad pi_a[0]:"), "unexpected error message: {err}");
    }

    #[test]
    fn to_u256_array_accepts_exact_length_decimal_strings() {
        let values = vec!["1".to_string(), "2".to_string()];
        let out = to_u256_array::<2>(&values, "pi_a").unwrap();
        assert_eq!(out[0], alloy::primitives::U256::from(1u64));
        assert_eq!(out[1], alloy::primitives::U256::from(2u64));
    }

    fn sample_proof() -> crate::db::Proof {
        crate::db::Proof {
            pi_a: vec!["1".into(), "2".into()],
            pi_b: vec![vec!["3".into(), "4".into()], vec!["5".into(), "6".into()]],
            pi_c: vec!["7".into(), "8".into()],
            protocol: "groth16".into(),
        }
    }

    /// `AttestationProof`'s fields are `pub` and `register_prover_key` is a public
    /// async fn, so nothing stops a future caller from constructing one with a
    /// malformed `pi_b` directly (bypassing the shape checks `proof_digest`
    /// already runs on the only current call path). This pins the guard added
    /// to `register_prover_key` so a bad `pi_b` produces a clean `Err` instead
    /// of an index-out-of-bounds panic.
    #[tokio::test]
    async fn register_prover_key_rejects_malformed_pi_b_before_indexing() {
        let mut proof = sample_proof();
        proof.pi_b = vec![vec!["3".into(), "4".into()]]; // only one row, must be 2

        let attestation = AttestationProof {
            proof,
            public_inputs: vec!["0".to_string(); 20],
        };
        let key = EnclaveKey::generate();

        let config = ProverChainConfig::new(
            "http://rpc.invalid",
            "0x0000000000000000000000000000000000000001",
            "0xdeadbeef",
        )
        .expect("config must build");

        let err = register_prover_key(&key, &attestation, &config).await.unwrap_err();
        assert_eq!(err, "pi_b must have exactly 2 rows, got 1");
    }

    /// A malformed submitter key must not put key material in the error.
    ///
    /// The error is logged and, on the boot path, becomes a panic message. Both
    /// destinations outlive the process, so interpolating the key would leak it
    /// on exactly the failure most likely to be pasted into a bug report.
    #[tokio::test]
    async fn an_invalid_submitter_key_is_not_echoed_in_the_error() {
        let attestation = AttestationProof {
            proof: sample_proof(),
            public_inputs: vec!["0".to_string(); 20],
        };
        let key = EnclaveKey::generate();
        let secret = "totally-not-a-valid-private-key-but-secret";

        let config = ProverChainConfig::new(
            "http://rpc.invalid",
            "0x0000000000000000000000000000000000000001",
            secret,
        )
        .expect("a non-empty key still builds a config; only parsing rejects it");

        let err = register_prover_key(&key, &attestation, &config).await.unwrap_err();

        assert!(!err.contains(secret), "error must not echo the key material: {err}");
        assert_eq!(err, "submitter key is not a valid secp256k1 private key");
    }

    // ---- Celo Sepolia registration ----------------------------------------

    /// The exact secret names this build asks Secret Manager for, pinned.
    ///
    /// Each one needs an IAM binding on the attestation-federated
    /// workload-identity principal (see `update_creds.sh`), and a binding is
    /// granted against a literal name. A typo here is not a compile error and
    /// not a test failure elsewhere -- it is a boot-time panic in production,
    /// discovered only after the image is deployed and the enclave refuses to
    /// start. Pin the names so the binding and the build cannot drift.
    #[test]
    fn the_sepolia_secret_names_are_pinned() {
        assert_eq!(
            secret_names(SEPOLIA_SECRET_PREFIX),
            [
                "sepolia-PROVER_RPC_URL",
                "sepolia-PROVER_HUB_ADDRESS",
                "sepolia-PROVER_TEE_PRIVATE_KEY",
            ]
        );
    }

    /// The hardcoded Sepolia target is not a special case in the naming scheme:
    /// it expands through the same `<prefix><suffix>` convention every
    /// `PROVER_SECRET_PREFIX` deployment already uses.
    #[test]
    fn secret_names_follow_the_existing_prefix_convention() {
        // The prefix self-terraform hands a staging instance as
        // PROVER_SECRET_PREFIX.
        assert_eq!(
            secret_names("staging-PROVER_"),
            [
                "staging-PROVER_RPC_URL",
                "staging-PROVER_HUB_ADDRESS",
                "staging-PROVER_TEE_PRIVATE_KEY",
            ]
        );
    }

    /// The invariant, stated once: every enclave ends up registered on Celo
    /// Sepolia. A prod enclave's primary chain is Celo mainnet, so it needs the
    /// second registration; a staging enclave's primary chain already IS Celo
    /// Sepolia, so a second registration would be a duplicate.
    ///
    /// Deliberately keyed on the chain id reported by the primary RPC rather
    /// than on comparing hub addresses: hubs can be deployed to the same
    /// address on both chains, and an address comparison would then silently
    /// skip Sepolia for a prod enclave -- a failure only visible later, as
    /// Sepolia rejecting every proof that enclave signs.
    #[test]
    fn sepolia_is_registered_only_when_the_primary_chain_is_not_sepolia() {
        const CELO_MAINNET: u64 = 42220;
        assert!(!needs_sepolia_registration(CELO_SEPOLIA_CHAIN_ID));
        assert!(needs_sepolia_registration(CELO_MAINNET));
    }

    /// Pinned because the dedupe above is only as correct as this constant. Too
    /// low and a staging enclave registers on Sepolia twice; too high and a
    /// production enclave never registers on Sepolia at all, which surfaces only
    /// as Sepolia rejecting every proof that enclave signs.
    #[test]
    fn the_celo_sepolia_chain_id_is_pinned() {
        assert_eq!(CELO_SEPOLIA_CHAIN_ID, 11142220);
    }

    /// Validation moved from `register_prover_key` to config construction so a
    /// misconfigured secret is caught while the plan is being built -- before
    /// ANY registration is sent. The ordering matters: each boot mints a fresh
    /// enclave key, so a mainnet registration followed by a Sepolia config
    /// error leaves a permanently orphaned key on mainnet and burns mainnet gas
    /// on every restart of the resulting crash loop.
    #[test]
    fn each_blank_config_field_is_rejected_by_name() {
        const RPC: &str = "http://rpc.invalid";
        const HUB: &str = "0x0000000000000000000000000000000000000001";
        const PK: &str = "0xdeadbeef";

        let cases = [
            ((RPC, HUB, "  "), "submitter key is empty"),
            (("", HUB, PK), "rpc url is empty"),
            ((RPC, " \t ", PK), "hub address is empty"),
        ];
        for ((rpc, hub, pk), expected) in cases {
            let err = ProverChainConfig::new(rpc, hub, pk).unwrap_err();
            assert_eq!(err, expected, "for inputs ({rpc:?}, {hub:?}, {pk:?})");
        }
    }

    /// Secret Manager payloads routinely carry a trailing newline. Trimming at
    /// construction means every consumer sees the same clean value, rather than
    /// each call site remembering to trim (the old code trimmed at three
    /// separate use sites).
    #[test]
    fn a_config_trims_every_field_once_at_construction() {
        let config = ProverChainConfig::new(
            " http://rpc.invalid\n",
            "0x0000000000000000000000000000000000000001\n",
            " 0xdeadbeef ",
        )
        .expect("must build");
        assert_eq!(config.rpc_url, "http://rpc.invalid");
        assert_eq!(config.hub_address, "0x0000000000000000000000000000000000000001");
        assert_eq!(config.submitter_pk, "0xdeadbeef");
    }

    /// A transient RPC failure must not take a prod enclave offline. Registration
    /// is fatal by design, and a public testnet endpoint on that path would
    /// otherwise turn a momentary blip into a mainnet proving outage.
    #[tokio::test]
    async fn retry_stops_as_soon_as_an_attempt_succeeds() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = std::sync::Arc::new(AtomicU32::new(0));
        let seen = std::sync::Arc::clone(&calls);

        retry(3, std::time::Duration::ZERO, move || {
            let seen = std::sync::Arc::clone(&seen);
            async move {
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err("transient".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await
        .expect("second attempt must succeed");

        assert_eq!(calls.load(Ordering::SeqCst), 2, "must not keep trying after success");
    }

    /// Exhaustion still fails: a genuine misconfiguration must panic the boot,
    /// not be retried into silence. The last error is preserved so the operator
    /// sees the real cause, not just the attempt count.
    #[tokio::test]
    async fn retry_reports_the_last_error_after_exhausting_every_attempt() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = std::sync::Arc::new(AtomicU32::new(0));
        let seen = std::sync::Arc::clone(&calls);

        let err = retry(3, std::time::Duration::ZERO, move || {
            let seen = std::sync::Arc::clone(&seen);
            async move {
                let n = seen.fetch_add(1, Ordering::SeqCst);
                // Annotated because this closure never returns `Ok`, so nothing
                // else pins `retry`'s success type.
                Err::<(), String>(format!("boom {n}"))
            }
        })
        .await
        .unwrap_err();

        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(err, "after 3 attempts: boom 2");
    }

}
