// Test stub for src/verifier/sidecar.rs: exits non-zero without
// ever writing a JSON payload, simulating the sidecar crashing before it can
// answer. Must be caught as `Verdict::Skipped`, never `Verdict::Invalid`.
process.exit(1);
