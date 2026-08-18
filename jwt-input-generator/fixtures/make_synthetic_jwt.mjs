/**
 * Regenerates `synthetic_jwt.txt` + `synthetic_jwt.address.txt`.
 *
 * Why a synthetic fixture exists at all: `index.ts` now requires `eat_nonce` to be
 * exactly the nonce list it asked Google to attest, which is the one property the
 * whole sidecar exists to establish. The real captured fixtures
 * (`example_jwt.txt`, `example_jwt_fail.txt`) were minted for *other* keys —
 * `example_jwt.txt`'s nonce is a didit-tee EdDSA pubkey — and their payloads cannot
 * be edited to carry an address of ours because the JWT signature is verified
 * (`@zk-email/jwt-tx-builder-helpers` -> `verifyJWT`) and Google's leaf private key
 * is, obviously, not available. So the only fixture that can exercise the happy path
 * under that check is one we sign ourselves.
 *
 * The real fixtures stay in the repo and stay useful: they still exercise real GCP
 * certificate-chain parsing and real RSA signature verification, all of which runs
 * *before* the nonce check, and they now serve as nonce-mismatch negative fixtures.
 *
 * This chain is self-signed and deliberately NOT a valid attestation: the root here
 * is a throwaway key, and what makes a real token trustworthy is the on-chain root-CA
 * pin plus PCR0 registration, neither of which this fixture can or should satisfy.
 * It exercises the sidecar's parsing and binding logic only.
 *
 * Keys are generated fresh on every run and never written out, so re-running this
 * script produces a different-but-equivalent fixture. Consumers must read the address
 * from `synthetic_jwt.address.txt` rather than hardcoding it.
 *
 * Usage: node fixtures/make_synthetic_jwt.mjs   (cwd = jwt-input-generator)
 */

import forge from 'node-forge';
import { writeFileSync } from 'node:fs';

const ENCLAVE_ADDRESS = '0x' + 'ab12cd34'.repeat(5);
const SCOPE_NONCE = 'self_protocol';
const IMAGE_DIGEST = 'sha256:' + 'a1'.repeat(32);

if (!/^0x[0-9a-f]{40}$/.test(ENCLAVE_ADDRESS)) {
  throw new Error(`ENCLAVE_ADDRESS is not a lowercase 20-byte hex address: ${ENCLAVE_ADDRESS}`);
}
if (IMAGE_DIGEST.length !== 71) {
  throw new Error(`IMAGE_DIGEST must be 71 chars, got ${IMAGE_DIGEST.length}`);
}

const b64url = (buf) => buf.toString('base64url');
const derOf = (cert) =>
  Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');

function makeCert({ subjectCN, issuerCN, publicKey, signingKey, serial, isCa }) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = serial;
  // Wide validity window: the circuit checks the certs are valid at the current date,
  // and a fixture that expires would look like a code regression years from now.
  cert.validity.notBefore = new Date(Date.UTC(2020, 0, 1));
  cert.validity.notAfter = new Date(Date.UTC(2099, 0, 1));
  cert.setSubject([{ name: 'commonName', value: subjectCN }]);
  cert.setIssuer([{ name: 'commonName', value: issuerCN }]);
  cert.setExtensions([{ name: 'basicConstraints', cA: isCa }]);
  cert.sign(signingKey, forge.md.sha256.create());
  return cert;
}

console.log('[fixture] generating 3 RSA-2048 keypairs (a few seconds)...');
const root = forge.pki.rsa.generateKeyPair(2048);
const intermediate = forge.pki.rsa.generateKeyPair(2048);
const leaf = forge.pki.rsa.generateKeyPair(2048);

// root self-signed -> signs intermediate -> signs leaf, matching the x5c ordering
// index.ts expects: [leaf, intermediate, root].
const rootCert = makeCert({
  subjectCN: 'synthetic-fixture-root',
  issuerCN: 'synthetic-fixture-root',
  publicKey: root.publicKey,
  signingKey: root.privateKey,
  serial: '01',
  isCa: true,
});
const intermediateCert = makeCert({
  subjectCN: 'synthetic-fixture-intermediate',
  issuerCN: 'synthetic-fixture-root',
  publicKey: intermediate.publicKey,
  signingKey: root.privateKey,
  serial: '02',
  isCa: true,
});
const leafCert = makeCert({
  subjectCN: 'synthetic-fixture-leaf',
  issuerCN: 'synthetic-fixture-intermediate',
  publicKey: leaf.publicKey,
  signingKey: intermediate.privateKey,
  serial: '03',
  isCa: false,
});

const header = {
  alg: 'RS256',
  typ: 'JWT',
  x5c: [derOf(leafCert), derOf(intermediateCert), derOf(rootCert)].map((der) =>
    der.toString('base64')
  ),
};

// Field shape mirrors a real Confidential Space PKI token (see example_jwt_fail.txt),
// trimmed to the claims index.ts actually reads plus enough context to stay realistic.
const iat = Math.floor(Date.UTC(2026, 0, 1) / 1000);
const payload = {
  aud: 'USER',
  exp: iat + 3600,
  iat,
  iss: 'https://confidentialcomputing.googleapis.com',
  nbf: iat,
  sub: 'https://www.googleapis.com/compute/v1/projects/synthetic/zones/us-west1-b/instances/fixture',
  // Bare hex, no `0x`: matches what index.ts's requestedNonces() now sends Google
  // (the on-chain decoder is a pure hex decode expecting exactly 40 characters).
  eat_nonce: [ENCLAVE_ADDRESS.slice(2), SCOPE_NONCE],
  secboot: true,
  hwmodel: 'GCP_AMD_SEV',
  swname: 'CONFIDENTIAL_SPACE',
  dbgstat: 'disabled',
  submods: {
    confidential_space: { monitoring_enabled: { memory: false } },
    container: {
      image_reference: 'us-docker.pkg.dev/synthetic/fixture/tee-server:latest',
      image_digest: IMAGE_DIGEST,
      restart_policy: 'Never',
    },
  },
};

const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
  Buffer.from(JSON.stringify(payload))
)}`;

const md = forge.md.sha256.create();
md.update(signingInput, 'utf8');
const signature = Buffer.from(leaf.privateKey.sign(md), 'binary');

const jwt = `${signingInput}.${b64url(signature)}`;

writeFileSync(new URL('synthetic_jwt.txt', import.meta.url), jwt + '\n');
writeFileSync(new URL('synthetic_jwt.address.txt', import.meta.url), ENCLAVE_ADDRESS + '\n');

console.log(`[fixture] wrote synthetic_jwt.txt (${jwt.length} chars)`);
console.log(`[fixture] enclave address: ${ENCLAVE_ADDRESS}`);
