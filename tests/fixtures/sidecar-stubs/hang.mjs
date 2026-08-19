// Test stub for src/verifier/sidecar.rs: simulates the sidecar
// hanging past the caller's timeout. Never writes to stdout and never exits
// on its own -- `setInterval` keeps the event loop alive indefinitely, so the
// only way this process ends is the caller killing it after its timeout
// elapses. Proves the sidecar client kills the child rather than blocking
// forever, and still reports `Verdict::Skipped`, never `Verdict::Invalid`.
setInterval(() => {}, 1000);
