// Test stub for src/verifier/sidecar.rs: returns well-formed JSON that is
// nonetheless not one of the three documented verdict shapes
// (`{"verdict":"valid"}` / `{"verdict":"invalid","reason":...}` /
// `{"verdict":"skipped","reason":...}`) -- simulating a malformed or
// out-of-contract sidecar response. Must be caught as `Verdict::Skipped`,
// never `Verdict::Invalid` -- this is not a signature the sidecar evaluated
// and rejected.
process.stdout.write(`${JSON.stringify({ error: 'stub: simulated malformed response' })}\n`);
