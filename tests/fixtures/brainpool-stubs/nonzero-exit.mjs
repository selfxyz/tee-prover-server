// Test stub for src/verifier/primitives/brainpool.rs: exits non-zero without
// ever writing a JSON payload, simulating the sidecar crashing before it can
// answer. Must be caught as `EcdsaError::Structural`, not `Failed`.
process.exit(1);
