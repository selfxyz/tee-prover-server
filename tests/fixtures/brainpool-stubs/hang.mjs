// Test stub for src/verifier/primitives/brainpool.rs: simulates the sidecar
// hanging past the caller's timeout. Never writes to stdout and never exits
// on its own -- `setInterval` keeps the event loop alive indefinitely, so the
// only way this process ends is the caller killing it after its timeout
// elapses. Proves `verify_brainpool` kills the child rather than blocking
// forever, and still reports `EcdsaError::Structural`, never `Failed`.
setInterval(() => {}, 1000);
