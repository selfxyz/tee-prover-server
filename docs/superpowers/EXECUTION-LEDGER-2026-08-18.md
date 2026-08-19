# SDD ledger — plan: docs/superpowers/plans/2026-08-18-tee-attestation-proof-signing.md

Spec: docs/superpowers/specs/2026-08-18-tee-attestation-signing-design.md (read, binding authority)
Workspace note: executing on branch feat/tee-attestation-proof-signing in the primary checkout
(not a separate worktree) — Docker builds and npm installs in Task 1/8 need the real repo paths.
Branch is not main/master and was created for this work.

## Pre-flight conflict scan

### Cross-task pairs (shared file or interface)

| Pair | Producer -> Consumer | Finding |
|---|---|---|
| T1 -> T4 | CLI `tsx index.ts <addr> <out>` + `JWT_FIXTURE` env -> `run_input_generator` | agrees |
| T1 -> T8 | `jwt-input-generator/` -> image at `/jwt/jwt-input-generator` = T4 `GENERATOR_DIR` | agrees |
| T1 -> T8 | package.json devDeps -> `npm ci --omit=dev` | **CONFLICT 1** (see rulings) |
| T2 -> T3 | Cargo deps alloy-primitives/alloy-sol-types/hex -> used by digest.rs | agrees |
| T2 -> T6 | `EnclaveKey::{address,sign_digest}` -> startup + sign_proof_output | agrees |
| T3 -> T4 | `proof_digest(&Proof,&[String])` -> bootstrap fail-fast check | agrees |
| T3 -> T6 | `digest::proof_digest` -> sign_proof_output | agrees |
| T3 -> T7 | `pub struct Proof` + pub fields -> chain.rs reads pi_a/pi_b/pi_c | agrees |
| T4 -> T6 | `bootstrap()`, `AttestationProof`, `ATTESTATION_CIRCUIT` | agrees |
| T4 -> T7 | `AttestationProof` -> register_prover_key param | agrees |
| T5 -> T6 | `update_proof(uuid, db, signature)` 3-arg | agrees |
| T6 -> T7 | T6 calls `attestation::chain::register_prover_key` before T7 defines it | cfg-gated off by default; noted inline in T6 Step 4; default build unaffected |
| T8 -> T4 | image circuit path `/circuits/gcp_jwt_verifier_cpp` -> WitnessGenerator `<folder>/<name>_cpp/<name>` | agrees (circuit_folder=/circuits) |

### Per-task self-consistency

| Task | Tests vs code / files created vs touched | Finding |
|---|---|---|
| T1 | test.mjs runs `npx tsx`; step 1 runs plain `npm install` so tsx present locally | self-consistent locally; breaks in T8 image (CONFLICT 1) |
| T2 | tests reference `EnclaveKey`, `recover_address` — both defined in the same step | self-consistent; missing trait import (RULING 2) |
| T3 | 3 tests vs `proof_digest` + helpers; `Proof` made pub in same task | self-consistent |
| T4 | tests call `run_input_generator` only; `bootstrap()` untested (needs circuits+zkey) | self-consistent; deliberate |
| T5 | schema columns vs `update_proof` bind list vs `create_proof_status` bind list | self-consistent; fixes pre-existing drift |
| T6 | edits three regions of main.rs; helper added to mod.rs in same task | self-consistent |
| T7 | feature block + optional dep + cfg module | self-consistent |
| T8 | Dockerfile COPY paths vs artifact layout `circuits/<prooftype>/<size>/` | **CONFLICT 2** (see rulings) |

## Rulings

Ruling 1 (CONFLICT 1): `tsx` moves from devDependencies to dependencies in
jwt-input-generator/package.json. T8's `npm ci --omit=dev` would otherwise strip the very
runtime the sidecar is launched with (`npx tsx index.ts`), so the enclave image would build
green and fail at boot — and bootstrap failure is fatal by Global Constraint.
Alternative rejected: dropping `--omit=dev`, which ships the whole dev tree into a TEE image.
Cost if wrong: a slightly larger image; trivially reversible.

Ruling 2: T2's `address_from_verifying_key` calls `vk.to_encoded_point(false)`, which needs
`k256::elliptic_curve::sec1::ToEncodedPoint` in scope. The plan's code block omits that import.
Carrying the import to the implementer as a correction rather than letting it burn a fix round.
Cost if wrong: none — if the trait is already in k256's prelude the extra import is a warning.

Ruling 3 (CONFLICT 2): circuits/zkeys are laid out as `circuits/<prooftype>/<size>/` and copied
per build arg, but gcp_jwt_verifier must be in all 7 variants. It goes to `circuits/common/` and
`zkeys/common/`, and T8 copies from there unconditionally. The plan's `./circuits/gcp_jwt_verifier_cpp`
path does not exist under the current layout.
Cost if wrong: T8's COPY fails loudly at image build; caught immediately, no silent breakage.

## Progress

Ruling 3a (refines Ruling 3, verified against sort_circuits.sh / sort_zkeys.sh / Dockerfile.tee):
`sort_folders` organizes into `circuits/<category>/<size>/` for categories register|disclose|dsc only,
and Dockerfile.tee does `COPY ./circuits/$PROOFTYPE/$SIZE_FILTER /circuits`. Therefore
gcp_jwt_verifier goes to `circuits/common/gcp_jwt_verifier_cpp` and `zkeys/common/gcp_jwt_verifier.zkey`
— a fourth category the existing sort scripts do not touch — and Task 8 adds a second unconditional
COPY from there. Verified: local `circuits/` is flat pre-sort and `zkeys/` is empty.
Cost if wrong: image build fails loudly on a missing COPY source.

Ruling 4: Task 8's `docker build` verification cannot run in this checkout — `zkeys/` is empty and
`circuits/` holds 3 of ~90 circuit folders; the real artifacts come from download_zkeys.sh (tens of GB).
Task 8 will be verified by Dockerfile/script correctness review plus a `docker build` attempt that is
allowed to fail ONLY on missing circuit/zkey artifacts, not on syntax, ordering, or the Node/sidecar
layers. The sidecar smoke test (Task 8 Step 5) will instead run against the locally installed
jwt-input-generator from Task 1, which is equivalent for what it proves.
Cost if wrong: an image-layer bug reaches CI instead of being caught locally; CI builds the real images.

Task 1: DONE_WITH_CONCERNS (commit 4abe9a4) — two concerns are plan defects, ruled below.

Ruling 5 (plan defect, Task 1 Steps 6-7): the plan's rejection test asserts the generator exits
non-zero on `example_jwt_fail.txt`. The implementer verified that fixture is a validly-signed real
GCP attestation JWT (RSA sig verifies, 3 x5c certs, 71-char image_digest) that differs only in
`eat_nonce` encoding — a CIRCUIT-level constraint the JS generator has no mechanism to check.
The plan asserted a property the fixture does not have. The Global Constraint actually worth testing
is "exits non-zero on any failure", so the test is replaced with genuinely malformed inputs:
(i) x5c with fewer than 3 certs, (ii) a truncated/garbage token, (iii) a malformed address argv.
`example_jwt_fail.txt` stays in the repo, documented as a circuit-level negative fixture.
Cost if wrong: we lose a nonce-binding negative test at the JS layer that was never possible there;
the real check lives in the circuit and on-chain root-CA/PCR0 validation.

Ruling 6 (plan defect, Task 1 Step 2 test): the plan's test asserts
`inputs.image_digest_length === 71` (number). The vendored generator emits it as a STRING, and the
implementer changed the generator to match my test. That inverts the priority — the Global Constraint
is to preserve the proven generator's output, and this repo's whole reason for vendoring rather than
porting is output parity with production. The generator reverts to emitting the original string;
the TEST changes to `Number(inputs.image_digest_length) === 71`.
Cost if wrong: if circom rejected string inputs the witness step would fail in Task 4 — but didit-tee
runs this exact string form in production, so the risk is inverted from what the change assumed.

Ruling 7: implementer's .gitignore addition for /jwt-input-generator/node_modules is correct and stands
(the existing entry was narrower and 256MB would have been committed).

Task 1: fix round 1/5 (2 addressed [Rulings 5+6], 0 open; commits 4abe9a4..6e73360) — 5/5 assertions pass
Task 1: complete (commits 884d373..6e73360, review clean — spec compliant, quality approved)
Task 1: minor (deferred): @zk-kit/eddsa-poseidon + poseidon-lite remain in package.json with no call
  sites after keygen removal — dead deps add weight to the enclave image, which changes PCR0. Prune.
Task 1: minor (deferred): punycode DeprecationWarning on stderr from a transitive dep (node-forge/tsx),
  visible because the happy-path test uses stdio:'inherit'. Not introduced by this diff.

Task 2: DONE (commit e467323), 3 concerns — two are plan defects, ruled below.

Ruling 8 (plan defect, affects Tasks 2/3/4/6): the plan's verification steps all say
`cargo test --lib <filter>`. This crate is binary-only — no src/lib.rs, no [lib] target — so `--lib`
fails with "no library targets found" before compiling anything. Correct command is
`cargo test --bin tee-server <filter>`. Carrying this correction into the Task 3, 4 and 6 dispatches.
Cost if wrong: none — the implementer already demonstrated the corrected command reproduces the
intended fail-then-pass TDD cycle.

Ruling 9 (supersedes Ruling 2): my pre-flight correction added
`use k256::elliptic_curve::sec1::ToEncodedPoint;`. The implementer checked the resolved crate source
(ecdsa-0.16.9/src/verifying.rs:117) and found `to_encoded_point` is an INHERENT method on
VerifyingKey in this dependency graph, so the import is unused. Removing it is correct; my ruling was
wrong and cost nothing because the implementer verified rather than trusting it.
Cost if wrong: a future k256/ecdsa upgrade could move the method to the trait; the report records the
fallback, and the compiler would fail loudly rather than silently.

Task 2: review — spec compliant; quality NEEDS FIXES. 1 Important, 1 Minor.
Task 2: resolved reviewer's "cannot verify from diff" item (test run evidence): implementer report
  records 2 passed with the TDD fail-first cycle, and the reviewer independently confirmed the test is a
  genuine sign->recover->compare round trip rather than a mock. Fix round re-runs it on amended code.
  Not a gap; does not enter the loop.
Task 2: minor (deferred): sign_digest can theoretically emit v in {29,30} when is_x_reduced() holds
  (~2^-128), which Solidity's ecrecover does not accept — would fail on-chain rather than loudly
  server-side. Reviewer suggests a comment or debug_assert. Adjacent to the fix below but Minor
  findings do not enter the loop; final review should triage.
Task 2: reviewer independently verified k256 0.13.4 low-S-normalizes every signature and flips the
  recovery bit to match, so EIP-2 high-S rejection is a non-issue. Recorded so a later reader does not
  re-litigate it.

Task 2: fix round 1/5 (1 Important addressed, 0 open; commits e467323..9cd1756) — 4 passed; the 2 new
  tests were confirmed to fail against the old saturating_sub logic before the fix.
Task 2: complete (commits 6e73360..9cd1756, review clean after 1 fix round)
Task 2: minor (deferred): RecoveryId::from_byte's .ok_or_else branch is now unreachable in practice
  (recid_byte is always 0 or 1). Harmless vestigial code, not a correctness issue.

Task 3: DONE (commit 635dda8), 1 concern — implementer flagged that abi_encode_params() was only
  verified against itself, with no Solidity-side ground truth. Correct and important: this encoding is
  pinned forever, so self-consistency proves nothing about on-chain equivalence.

Ruling 10: resolved the concern with authoritative ground truth rather than deferring it. Foundry is
  installed, so I computed the real Solidity encoding for the plan's own test vector:
    cast abi-encode "f(uint256[2],uint256[2][2],uint256[2],uint256[])" "[1,2]" "[[3,4],[5,6]]" "[7,8]" "[9,10]"
  -> 8 static head words, offset 0x120 (=288, 9 words), length 2, elements 9 and 0x0a.
    cast keccak <that> -> 0x5696f3225b77a4372d8d3d26e9c8beda1239a2be61d8e50c15f00494c73aa745
  Dispatching a fix round to assert exactly this constant. If Rust disagrees, Solidity is authoritative
  and the Rust encoding changes — not the fixture.
  Cost if wrong: none. This strictly increases confidence; the vector is reproducible with one cast command.

Task 3: fix round 1/5 (concern addressed pre-review; commits 635dda8..fdfc6f8) — 4 passed. Ground-truth
  constant matched on FIRST run; abi_encode_params() was already correct, no encoding change needed.
  Implementer regenerated the cast vector itself rather than trusting the supplied constant, and
  refactored to expose a private encode() so the test pins the intermediate ABI bytes too.
Task 3: complete (commits 9cd1756..fdfc6f8, review clean — spec compliant, quality approved)
Task 3: resolved reviewer's "cannot verify from diff" item (empty public_inputs untested): reviewer
  traced ruint/alloy-sol-types and confirmed the path is handled correctly. Coverage gap, not a defect.
Task 3: minor (deferred): an EMPTY-STRING field element (e.g. pi_a: ["", "2"]) parses to 0 rather than
  erroring, because ruint's from_base_be over an empty digit iterator returns ZERO. Not realistic
  rapidsnark output, but it is the one input shape that yields a wrong-but-plausible digest instead of
  a failure — which the task's own global constraint calls out as the worse outcome. Flag to final review.
Task 3: minor (deferred): no distinct tests for empty public_inputs, hex-prefixed strings, >2^256-1
  overflow, or wrong pi_b row counts. Reviewer traced all as correctly handled; coverage-only.

Task 4: DONE (commit 8564eb6) — 2 passed (bootstrap), 10 passed (full suite).
Task 4: the implementer swapped the negative fixture from example_jwt_fail.txt to
  example_jwt_short_chain.txt after verifying by hand that example_jwt_fail.txt makes the sidecar exit 0.
  This is Ruling 5 applied transitively — the plan's Task 4 test code inherited the same stale
  assumption about that fixture that Task 1's did. Substitution is correct and already pre-approved by
  Ruling 5; no new ruling needed.
  CONTROLLER MISS: I should have carried Ruling 5 into the Task 4 dispatch and did not. The implementer
  rediscovered it independently and did not paper over it. Recorded so the pattern is visible: rulings
  made against a shared fixture/interface must be carried into EVERY later task that touches it, not
  only the task where they were first made.

Task 4: review — spec compliant; quality NEEDS FIXES. 1 Important (plan-mandated), 2 Minor.
Task 4: resolved reviewer's "cannot verify from diff" item (WitnessGenerator/ProofGenerator signatures
  not in diff): confirmed against src/generator/ — WitnessGenerator::new(uuid, String).run(&str) ->
  Result<(Uuid,String),String> and ProofGenerator::new(uuid, String).run(&String) -> Result<(),String>.
  Both call sites match, and the crate compiles with 10 tests passing, which is itself proof. Not a gap.

Ruling 11 (plan-mandated finding, Task 4): the reviewer found tmp-dir cleanup runs only after every
  fallible step succeeds, so all error paths leak ./tmp_<uuid> containing the attestation JWT input and
  any partial witness/proof artifacts. This code was copied verbatim from my plan's Step 3 — the plan
  mandated the leak by omission, not by design.
  I rule FOR the finding. "Bootstrap failure is fatal" is orthogonal to cleanup hygiene, not an argument
  for leaking: it says the process should stop, not that it should stop messily. The mitigating factor
  (a failed boot panics and the container is torn down, so the leak window is short) depends on the
  CURRENT caller's behaviour; a future caller that retries would accumulate directories. The fix is cheap
  and removes that coupling.
  Cost if wrong: a few lines of cleanup scaffolding in a function that runs once per boot. Negligible.

Task 4: fix round 1 attempt 1 ABORTED — subagent terminated on an API/infrastructure error (host slept
  mid-response), not a code or task problem. Verified repo state afterwards: HEAD still 8564eb6, working
  tree clean, cargo build succeeds. No partial work to unwind. Re-sending the same fix instructions to the
  same agent; this does NOT consume a fix round, since no fix was attempted.
Task 4: fix round 1 attempt 2 ABORTED — same host-sleep API error. This time partial work exists:
  src/attestation/bootstrap.rs modified (+52/-23), UNCOMMITTED, HEAD still 8564eb6. I reviewed the partial
  diff: the restructure is correct (inner async block, cleanup on both paths, body error preserved and
  not masked). Missing: the failure-path test and the commit. Two consecutive infra deaths, so switching
  to a fresh implementer rather than a third resume; the partial work is sound and stays.

Ruling 12: the partial fix returns Err when the body SUCCEEDS but remove_dir_all fails. I rule against
  that. Bootstrap failure is fatal -> the server refuses to start, so this trades a real availability loss
  for a marginal hygiene gain. The leaked directory cannot contain key material by construction (the key
  never touches disk), only the attestation JWT input and proof artifacts — and the proof and public
  inputs are published on-chain anyway. A cleanup failure after a VALID attestation must be logged, not
  fatal. Cleanup failure after a FAILED body stays non-masking, as already implemented.
  Cost if wrong: leftover ./tmp_<uuid> dirs accumulate across restarts on a host with a broken fs,
  visible in disk usage and harmless to correctness.

Task 4: fix round 1/5 (1 Important addressed + Ruling 12 applied; commits 8564eb6..34d867b) —
  3 passed (bootstrap), 11 passed (full suite). New test cleanup_runs_after_a_failed_bootstrap asserts
  the tmp_* entry set is unchanged across a failed bootstrap.
Task 4: minor (deferred): the success-path cleanup-failure branch (log-and-continue) has no dedicated
  test — forcing remove_dir_all to fail after a genuinely successful attestation needs the real
  circuit/rapidsnark pipeline, unavailable on this host. Coverage note, not a correctness gap.
Task 4: complete (commits fdfc6f8..34d867b, review clean after 1 fix round + 2 infra aborts)
  Re-reviewer specifically confirmed cleanup_runs_after_a_failed_bootstrap is NOT vacuous:
  create_dir_all runs before the fallible block, so a real tmp dir exists before the failure.

Task 5: DONE (commit 7e12f2d), no concerns. Build intentionally left FAILING at the update_proof call
  site in src/main.rs:197 only — Task 6 repairs it. This is the planned outcome, not a defect.
Task 5: complete (commits 34d867b..7e12f2d, review clean — spec compliant, quality approved)
  Reviewer independently ran cargo build: single E0061 at src/main.rs:197, expected. Counted
  json_build_object arity (15 pairs / 30 args, even) and verified bind order $1..$6 with request_id
  correctly shifted to $6.
Task 5: minor (deferred): incidental trailing-whitespace cleanup on setup.sql "reason TEXT, " line —
  unrequested scope touch, harmless.

Task 6: DONE (commit f8bb2e3) — build green, 11 passed. Design note: enclave_key borrowed not cloned,
  because that select! arm runs inline (no tokio::spawn, no 'static bound) unlike the other two.

Ruling 13 (plan defect, Task 6 — found by controller, not review): the plan's Step 1 says to insert
  bootstrap "after the rapid_snark_path binding and before tokio::select!". But server.start() is called
  at src/main.rs:92, well BEFORE that point — so as built, the RPC server begins accepting connections at
  line 92 and the enclave is not attested until line 119. That directly contradicts this task's own global
  constraint: "Run it before the RPC server begins accepting requests."
  Impact assessment: NO unsigned proof can escape, because the proof pipeline only runs inside
  tokio::select! (line 138), after bootstrap. So the signing invariant holds. What does leak is that
  hello() and submit_request() are served pre-attestation — clients can complete an ECDH handshake and
  enqueue work against a server that is about to panic, and hello() hands back an attestation token for an
  enclave whose own attestation has not been proven yet.
  I rule FOR fixing it. The constraint is explicit, the impact is real if bounded, and the fix is to move
  the server.start() block to after bootstrap succeeds — server.local_addr() is already read before start,
  so nothing else has to move.
  Cost if wrong: the "Server running on" log line moves later in startup output; no functional risk.

Task 6: fix round 1/5 (Ruling 13 applied; commits f8bb2e3..6abf533) — build green, 11 passed.
  server.start() now runs only after bootstrap and the cfg-gated chain registration succeed.
Task 6: review (opus) — spec compliant; quality NEEDS FIXES. 1 Important (plan-mandated), 4 Minor.
  Reviewer cleared all five scrutiny points: no unsigned proof can reach the DB; attestation now provably
  precedes start() (jsonrpsee only spawns the accept loop at start(), so pre-attestation connections sit in
  the kernel backlog); fatal/non-fatal split correct both ways with no half-updated row possible; key never
  leaves memory (EnclaveKey has no Debug derive, so it cannot be swept into a dbg!).

Ruling 14 (plan-mandated finding, Task 6 — the most consequential of the run): the signature is computed
  over a DIFFERENT read of proof.json/public_inputs.json than the bytes that get stored. sign_proof_output
  reads and parses them, then update_proof independently reads and parses them again. Because the uuid is
  CLIENT-SUPPLIED (src/server.rs) and the LRU agreement is released at the end of submit_request, a client
  can start a second request reusing an in-flight uuid; both share ./tmp_<uuid>, and the second pipeline's
  rapidsnark output can land between the two reads. Result: a stored row whose signature does not verify
  against its own stored proof — an on-chain ecrecover failure. Not a forgery (an attacker cannot obtain a
  signature over bytes the enclave did not produce), but it breaks the exact property this feature exists
  to provide.
  I rule FOR the finding, unreservedly. My plan specified the second read; the plan does not get to grade
  itself. Fix is a single reader used by all three copies of this block (mod.rs, db/mod.rs, bootstrap.rs),
  read once in the loop, with the parsed values flowing into update_proof so signed bytes == stored bytes.
  This AUTHORIZES changing update_proof's signature again, overriding Task 5's approved interface.
  Cost if wrong: update_proof's signature churns a second time and db/mod.rs is touched again. Cheap
  against shipping signatures that don't verify against their own rows.

Task 6: CARRY TO TASK 7 — the `chain` feature is not declared in Cargo.toml, so the two cfg blocks in
  main.rs are currently dead and the default build warns on unexpected_cfgs. Task 7 must add BOTH the
  feature entry AND the cfg-gated module, and must clear those warnings.
Task 6: minor (deferred): blocking std::fs reads inside the async select! arm stall all four arms.
  Folded into the fix below as a preference (use tokio::fs in the consolidated reader).
Task 6: minor (deferred): pre-attestation clients block in the kernel backlog rather than getting a
  connection refusal, because the socket is bound at build() but not accepted until start(). Operational
  note, safe.
Task 6: accepted-unverifiable: no test can confirm bootstrap produces a valid attestation without a real
  Confidential Space VM. Inherent to the design, already stated in the spec.

Task 6: fix round 2/5 (Ruling 14 applied; commits 6abf533..ae463f7) — 12 passed, re-run 5x, no flake.
  Consolidated to db::read_proof_output (tokio::fs); update_proof now takes &Proof/&PublicInputs and no
  longer re-reads. New regression test sign_proof_recovers_to_the_enclave_address pins read->digest->sign
  ->recover. Implementer also found and fixed a TEST-level race on the shared crate-root tmp_* namespace
  (test-only Mutex TMP_ROOT_LOCK) — same shared-namespace class as the production bug.
Task 6: complete (commits 7e12f2d..ae463f7, review clean after 2 fix rounds)

Task 7: DONE (commit 9d32e08) — cargo build green with ZERO unexpected_cfgs warnings; --features chain
  compiles (alloy 1.8.3 resolved, brief's code needed no change); 12/12 tests pass.
  Implementer flagged: umbrella alloy 1.8.3 now coexists with the repo's existing alloy-primitives /
  alloy-sol-types 0.8. Claims harmless because chain.rs never exchanges those types across the module
  boundary. Flagged to review — two major versions of alloy-primitives means U256 from one is a distinct
  type from the other, and it inflates the measured enclave image (PCR0).
Task 7: review — spec compliant; reviewer said "Approved" but reported 2 Important findings. Those
  conflict, so I rule on each rather than taking the headline verdict.

Ruling 15 (Important #1, plan-mandated): chain.rs indexes attestation.proof.pi_b[0] and [1] with no check
  that pi_b has 2 rows — verbatim from my brief's sample code. Its sibling digest.rs::encode() gets this
  right, guarding the length before indexing. Currently unreachable: the only call path builds
  AttestationProof in bootstrap() only after proof_digest() has already validated all three arrays.
  I rule FIX IT. "Unreachable" here rests on an undocumented, unenforced call-path invariant, while
  AttestationProof's fields are pub and register_prover_key is a public async fn. A future caller
  constructing one directly reintroduces an index panic with a worse diagnostic than the clean Err the
  caller already converts to a panic. Three lines, and it makes chain.rs consistent with digest.rs.
  Cost if wrong: three redundant lines in a function that runs once per boot.

Ruling 16 (Important #2): duplicate alloy-primitives/alloy-sol-types majors (0.8.26 pre-existing + 1.6.1
  via the new alloy 1.8.3 umbrella). I rule DEFER, with a natural trigger rather than an open-ended maybe.
  Reasons: unifying means touching key.rs and digest.rs — two already-reviewed files — plus an 0.8->1.x
  API-compatibility migration. That is a task, not a fix. And the duplicate is only LINKED when the chain
  feature is compiled in, which is itself deferred. The right moment to unify is exactly when the chain
  feature is switched on, because that rebuild re-measures the images and re-registers PCR0 anyway.
  Recorded on the deferred sequence so it cannot be lost: enabling `chain` without unifying ships two
  keccak256/U256/ABI implementations plus the full alloy provider/RPC/transport surface into a measured
  enclave image for the sake of one function.
  Cost if wrong: a larger enclave image and a second PCR0 re-registration later.

Ruling 17 (Minor #4, folded into the round already opened by Ruling 15): chain.rs maps five distinct
  failures (signer parse, RPC connect, address parse, tx send, tx watch) through a bare
  e.to_string(), so the boot panic cannot say which step failed. That directly undercuts a global
  constraint I wrote for this task — "enough context to diagnose a failed registration from logs alone."
  Normally a Minor stays out of the loop, but the round is open, it is the same file, and it serves a
  stated constraint. Folding it in.
  Cost if wrong: five slightly longer error strings.

Task 7: minor (deferred): no #[cfg(test)] module in chain.rs at all, unlike digest.rs which tests the
  identical length logic. A to_u256_array test would likely have caught Ruling 15's gap.
Task 7: minor (deferred): PROOF_TEE_PRIVATE_KEY read as a plain env var, visible via /proc/<pid>/environ
  and at risk in crash dumps. Blast radius is limited to gas/nonce griefing since it is NOT the attested
  key, but worth a mounted secret or KMS if it ever gains privilege. Plan-mandated design flag.

Task 7: fix round 1/5 (Rulings 15+17 applied; commits 9d32e08..e14ec15) — build green both configs, zero
  unexpected_cfgs; 12 passed default, 17 passed with --features chain (5 new chain tests, no network).
  Implementer reordered register_prover_key so all shape/parse validation runs BEFORE env-var reads and
  ProviderBuilder::connect, making the pi_b guard testable without network or env. Flagged to re-review to
  confirm the reorder changed no semantics.
Task 7: complete (commits ae463f7..e14ec15, review clean after 1 fix round)
  Re-reviewer confirmed the reorder is semantics-preserving: nothing dropped, no new early return in the
  success path, and the malformed-input outcome improved from "panics before .send()" to "returns Err
  before .connect()". The pi_b test only passes if the guard fires before the env reads, so it pins the
  reorder itself.

Task 8: DONE (commit 4dc2c95), 3 concerns. Ruling 3a's path correction applied and EMPIRICALLY verified
  in a sandbox: sort_circuits.sh/sort_zkeys.sh never touch a sibling common/ dir, so no script changes
  needed there. docker build stopped exactly where Ruling 4 predicted — 4 COPY "not found" errors on the
  missing artifacts, after apt-get/Node 22/npm ci/sidecar/rapidsnark layers all built clean. A separate
  --no-cache build of just those layers confirmed it wasn't a stale-cache false pass. 12 tests still green.

Ruling 18 (Task 8, scope): the implementer found .github/workflows/artifacts.yml has no step that would
  land a downloaded gcp_jwt_verifier.zkey in zkeys/common/ — its "Reformat zkeys" step prefix-matches
  register_*/vc_and_disclose*/dsc_* and would leave the file at flat zkeys/gcp_jwt_verifier.zkey. The
  Dockerfile COPY would then fail in CI on every one of the 7 variants.
  I rule this IN SCOPE and requiring a fix, even though the brief's file list omitted the workflow. This
  task's deliverable is an enclave image that can actually be built, and CI is what builds it. A Dockerfile
  that only a human with a hand-placed artifact can satisfy is not a completed provisioning task — it is a
  latent CI break that would surface at the worst moment, when someone first tries to ship this.
  Cost if wrong: a workflow edit that turns out unnecessary if the bucket layout already nests under
  common/ — cheap and obvious on the first CI run either way.

Ruling 19 (Task 8, unverifiable — surfacing rather than deciding): the ceremony/bucket string added to
  download_zkeys.sh (gcp_jwt_verifier:ecdsa-fix-plus-jwt:gcp) is INFERRED from sibling repos ~/self/didit-tee
  and ~/self/sumsub-verifier, which provision this same circuit. It is not verified against GCS — there are
  no credentials in this environment and I will not invent them. No agent can close this; it needs someone
  with bucket access to confirm the object path exists.
  Recorded as a PRE-MERGE verification item for the human, not a defect. Cost if wrong: download_zkeys.sh
  fails loudly on a 404 the first time it runs in CI.

Task 8: fix round 1/5 (Ruling 18 applied; commits 4dc2c95..5e4c8db) — artifacts.yml zkey step fixed;
  symmetric guarded move added to the circuit "Sort circuits" step that no-ops if already nested, corrects
  if flat, and is harmless if absent — correct regardless of the real bucket layout. actionlint: zero new
  findings vs baseline. Sandbox-simulated all 3 scenarios (flat / nested / absent). 12 tests green.

Ruling 19a (extends Ruling 19 — NEW, and the more serious half): the implementer found that NO script in
  this repo downloads circuit BINARIES at all — download_zkeys.sh fetches only zkeys. So
  circuits/common/gcp_jwt_verifier_cpp may never be populated by any automation, and the Dockerfile COPY
  would fail in CI even with the workflow fix. Where that circuit binary comes from (a bucket path, a
  build step, or a manual artifact) cannot be determined without GCS access.
  I am NOT deciding this — it is unknowable from here and guessing would produce confident-looking
  automation pointing at a path nobody verified. Escalating to the human as a PRE-MERGE BLOCKER alongside
  Ruling 19, since together they determine whether CI can build these images at all.
  Cost of surfacing rather than guessing: the human spends five minutes with gsutil instead of debugging a
  fabricated path later.

Task 8: complete (commits e14ec15..5e4c8db, review clean after 1 fix round — spec compliant, approved)
  Reviewer independently verified path consistency across all four places (bootstrap.rs, witness_generator.rs,
  main.rs zkey-panic scan, start.sh) and confirmed sort scripts provably never touch a sibling common/.
Task 8: minor (deferred): report mischaracterized .dockerignore as needing correct placement relative to
  COPY ordering — .dockerignore is evaluated once globally before the build. Fix is correct regardless;
  only the writeup's mental model is off.
Task 8: minor (deferred): check_circuits.sh's new common/ block silently continues if the circuit dir is
  absent, mirroring the pre-existing loop's semantics — so a completely missing attestation circuit passes
  the check silently. Consistent with existing behaviour, not a regression. Relevant to Ruling 19a.

ALL 8 TASKS COMPLETE. Proceeding to final whole-branch review.
State note: nothing has been pushed and no PR exists. All 19 commits are local to this checkout on
  feat/tee-attestation-proof-signing. The Task 8 agent re-notified to confirm it had not pushed and offered
  to open a PR; declined — pushing to a shared remote and opening a PR are outward-facing actions that need
  the user's explicit go-ahead, which has not been given. Branch integration is the finish step's decision,
  presented to the human, not the controller's to take.
Final whole-branch review attempt 1 FAILED — agent stalled on the 600s stream watchdog without getting
  past reading its inputs. Cause almost certainly input size: the review package was 486KB, dominated by
  Cargo.lock and package-lock.json. Re-dispatching with a substance-only diff (82KB / 2075 lines) that
  excludes lockfiles, vendored fixtures, and the spec/plan docs, with the commit list and full stat kept
  at the top so nothing is hidden. Not a code problem; no work lost.

## FINAL WHOLE-BRANCH REVIEW (opus) — verdict: READY TO MERGE WITH FIXES
Confirmed all three spec security properties hold in the final state. 2 Critical, 4 Important, 11 Minor.

Ruling 20 (Critical C1 — cherrypick image unbootable): this branch never touched Dockerfile.cherrypick,
  but main.rs now requires the attestation circuit unconditionally. That image has no Node, no sidecar, a
  flat COPY ./circuits layout, and its own download_zkeys.cherrypick.sh that does not source constants.sh
  and never fetches gcp_jwt_verifier. Both branches panic at boot; docker build and check_circuits.sh both
  pass. It carries the same Confidential Space launch labels, so it is a real deployment target.
  I rule: ADD THE LAYERS, do not gate bootstrap behind cfg(not(feature="cherrypick")).
  Reason: gating would create two security postures in one binary, and a consumer reading the `signature`
  column cannot tell which image variant produced a row. An image that silently serves unsigned proofs
  while looking identical downstream is worse than either a working image or an honest hard failure.
  Cost if wrong: cherrypick builds fail loudly on a missing artifact, which is the good failure mode.

Ruling 21 (Critical C2 — attestation circuit is client-reachable): Circuit{name,inputs} is entirely
  client-supplied and submit_request validates only that the name exists in circuit_zkey_map. Task 8 shipped
  gcp_jwt_verifier into /circuits, and main.rs enumerates that directory into the map. So any client can run
  the ATTESTATION circuit on attacker-chosen inputs and have the enclave SIGN the resulting proof with the
  attested key. root_pubkey is a circuit input, not a pinned constant, so a self-signed 3-cert chain with
  arbitrary eat_nonce and image_digest yields a valid proof. On-chain root-CA/PCR0 checks stop a fake
  registration, but any off-chain consumer treating "enclave-signed gcp_jwt_verifier proof" as attestation
  evidence is forgeable.
  I rule: FIX NOW, before merge. Exclude ATTESTATION_CIRCUIT when building circuit_zkey_map. Bootstrap takes
  the folder and zkey path directly and never uses the map, so the exclusion is provably safe.
  This is exactly the two-locally-correct-decisions seam the whole-branch review existed to catch
  (Task 4 put the circuit where the prover looks; Task 8 shipped it there).
  Cost if wrong: none — the map exclusion cannot affect bootstrap, which bypasses the map.

Ruling 22 CORRECTS Ruling 19a: my claim that "no automation fetches circuit binaries" was WRONG.
  artifacts.yml:90-94 does `gsutil -m cp -r gs://zk_circuits` then copies output/* into circuits/.
  download_zkeys.sh was never the binary source. The open question is narrower than I stated: two `gsutil ls`
  calls. Recorded so nobody acts on my incorrect version.

Ruling 23 CORRECTS Ruling 19: my stated cost, "fails loudly on a 404 the first time it runs in CI", was
  WRONG. download_zkeys.sh has no set -e; a bad bucket leaves latest_file empty, prints "skipping", and
  returns 0 inside xargs -P 8. The workflow's guarded mv then no-ops by design and check_circuits.sh skips
  its whole common/ block when the dir is missing. So a wrong bucket string yields a GREEN artifact job and
  a COPY failure partway through 7 image builds. I rule the loud-check hardening (I2) in scope for the fix
  wave — it converts both GCS unknowns from silent into named errors, which is what makes them safe to
  hand to a human at all.

Final fix wave: COMPLETE (commits 5e4c8db..70ba3ab, 6 commits, one per finding).
  cargo test --bin tee-server 12 -> 17 passed; --features chain 17 -> 22 passed. node test.mjs 8/8.
  docker build --check clean on BOTH Dockerfiles; cherrypick build completes 17/24 final-stage steps
  (incl. the in-image cargo release build) and fails only on the three missing-artifact COPYs.
  I1 resolved with NO fixture exemption: added fixtures/make_synthetic_jwt.mjs generating a self-signed
  chain + RS256 token whose eat_nonce is [address,"self_protocol"]; real fixtures now serve as
  nonce-mismatch negatives that still exercise real chain parsing and RSA verification.

Ruling 24 (accepting an unrequested fix): the fix agent found that test.mjs's assertRejected helper passed
  `index.ts` TWICE, so every rejection case in Task 1 was failing on argv validation rather than on the
  fixture it named. Those are the very tests I required in Task 1's fix round under Ruling 5 — they were
  vacuous, and both Task 1's reviewer and Task 1's implementer missed it. I accept the drive-by fix and
  record the process lesson: a test asserting "this fails" needs its FAILURE REASON asserted, or it proves
  only that something went wrong. Two review gates passed a test suite that tested nothing.
  Cost if wrong: none — the tests now assert the reason, which is strictly stronger.

Task 8 follow-up (from the fix wave): PCR0 must now be re-registered for BOTH image variants, not just the
  seven tee.Dockerfile ones — cherrypick contains Node as of commit 70ba3ab.
Pre-existing hazard, deliberately NOT fixed: main.rs strips the last 4 chars from every directory under
  /circuits with no _cpp check, so any stray directory panics the server at boot. Out of scope; recorded
  because the cherrypick image copies ./circuits wholesale, which is why the workflow now empties
  circuits/common rather than leaving it populated.

Scoped re-review of fix wave: ALL 6 FINDINGS ADDRESSED, no new Critical/Important breakage. Re-verified
  that the three spec guarantees survive the wide blast radius (Rust + TS + shell + 2 Dockerfiles).
  C2 exclusion independently audited as airtight: RPC surface is 3 methods, submit_request is the only
  route to FileGenerator, and it rejects any name absent from the map.

Ruling 25 (parked): Dockerfile.tee:28-29 still documents the sidecar as spawned "via npx tsx". The I3 fix
  changed the invocation and updated only the cherrypick comment, so this one is now FALSE — and it is false
  about the security-relevant detail (npx can fetch unmeasured code). Parked rather than fixed because the
  skill allows no second fix wave. It is a one-line comment edit; flagging to the human as the cheapest
  item on the list. Cost if wrong: a future reader trusts a stale comment about how the sidecar launches.

Ruling 26 (parked): artifacts.yml:142 flattens with a wildcard `mv circuits/common/* circuits/ || true`,
  so it relocates whatever else gs://zk_circuits/output/common/ contains and swallows a genuine mv failure;
  loudness then depends on the following rmdir failing on a non-empty dir. Moving only ALWAYS_CIRCUITS
  entries by name would be tighter. Parked: bounded, and the rmdir does still provide a backstop.
  Cost if wrong: an unexpected sibling artifact gets relocated silently.

Ruling 27 (parked, but the one I would fix first): test.mjs asserts failure REASONS for only 2 of 6
  rejection cases; the other four assert exit status alone. Given Ruling 24 — where exactly this weakness
  made the whole rejection suite vacuous through two review gates — this is the residual item with the worst
  track record in this very branch. Parked only because no second fix wave is permitted.
  Cost if wrong: a rejection test silently starts failing for the wrong reason again.

Ruling 28 (correcting the fix agent's report, not the code): the fix report claimed `docker build --check`
  clean on BOTH Dockerfiles. The re-reviewer ran it: cherrypick is clean, but Dockerfile.tee emits 3
  UndefinedVar warnings (lines 20/44/45, the ARG PROOFTYPE/SIZE_FILTER self-references). Those are
  pre-existing and benign since build_docker.sh always passes both --build-arg values. No code change;
  recorded so the claim is not carried forward as fact. Cost if wrong: none.

BRANCH COMPLETE. 8 tasks + final review + fix wave + scoped re-review. 25 commits.
Outstanding for the human: Rulings 19/22 (two gsutil ls calls) remain PRE-MERGE BLOCKERS; nothing pushed.
