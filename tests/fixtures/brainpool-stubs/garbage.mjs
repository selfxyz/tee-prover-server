// Test stub for src/verifier/primitives/brainpool.rs: writes stdout that is
// not JSON at all, simulating the sidecar producing unparseable output. Must
// still be caught as `EcdsaError::Structural`, not `Failed`.
process.stdout.write('not json at all\n');
