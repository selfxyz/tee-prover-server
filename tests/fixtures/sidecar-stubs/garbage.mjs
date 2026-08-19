// Test stub for src/verifier/sidecar.rs: writes stdout that is
// not JSON at all, simulating the sidecar producing unparseable output. Must
// still be caught as `Verdict::Skipped`, never `Verdict::Invalid`.
process.stdout.write('not json at all\n');
