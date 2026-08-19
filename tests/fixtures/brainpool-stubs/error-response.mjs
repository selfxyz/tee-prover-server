// Test stub for src/verifier/primitives/brainpool.rs: returns the sidecar's
// documented `{"error":...}` shape, e.g. an unrecognised curve or hash name.
// Must be caught as `EcdsaError::Structural`, not `Failed` -- `{"error":...}`
// is never a signature the sidecar evaluated and rejected.
process.stdout.write(`${JSON.stringify({ error: 'stub: simulated structural failure' })}\n`);
