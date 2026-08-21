// Test stub for src/verifier/sidecar.rs: exits cleanly (status
// 0) without writing anything to stdout, simulating an empty response. Must
// be caught as `Verdict::Skipped`, never `Verdict::Invalid`.
process.exit(0);
