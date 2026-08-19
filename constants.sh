PROOFS_SIZES=(
    "register:small"
    "register:medium"
    "register:large"
    "disclose:small"
    "dsc:small"
    "dsc:medium"
    "dsc:large"
)

register_circuits=(
  "register_sha512_sha512_sha512_ecdsa_secp521r1:large"
  "register_sha512_sha512_sha512_ecdsa_brainpoolP512r1:large" 
  "register_sha384_sha384_sha384_ecdsa_brainpoolP512r1:large" 
  "register_sha256_sha256_sha256_ecdsa_brainpoolP384r1:medium" 
  "register_sha256_sha256_sha256_ecdsa_secp384r1:medium" 
  "register_sha384_sha384_sha384_ecdsa_brainpoolP384r1:medium" 
  "register_sha384_sha384_sha384_ecdsa_secp384r1:medium"
  "register_id_sha512_sha512_sha512_ecdsa_secp521r1:large"
  "register_id_sha512_sha512_sha512_ecdsa_brainpoolP512r1:large" 
  "register_id_sha384_sha384_sha384_ecdsa_brainpoolP512r1:large" 
  "register_id_sha256_sha256_sha256_ecdsa_brainpoolP384r1:medium" 
  "register_id_sha256_sha256_sha256_ecdsa_secp384r1:medium" 
  "register_id_sha384_sha384_sha384_ecdsa_brainpoolP384r1:medium" 
  "register_id_sha384_sha384_sha384_ecdsa_secp384r1:medium"
)

dsc_circuits=(
  "dsc_sha256_ecdsa_secp521r1:large"
  "dsc_sha512_ecdsa_secp521r1:large"
  "dsc_sha384_ecdsa_brainpoolP512r1:large" 
  "dsc_sha512_ecdsa_brainpoolP512r1:large" 
  "dsc_sha256_ecdsa_brainpoolP384r1:medium" 
  "dsc_sha256_ecdsa_secp384r1:medium" 
  "dsc_sha384_ecdsa_brainpoolP384r1:medium" 
  "dsc_sha384_ecdsa_secp384r1:medium"
)

# Circuits needed by every image variant regardless of PROOFTYPE/SIZE_FILTER.
# These live in circuits/common and zkeys/common (no small/medium/large split)
# instead of one of the size-filtered categories above, since sort_circuits.sh
# and sort_zkeys.sh only ever operate on the register/disclose/dsc category
# directories and never touch a sibling "common" directory.
ALWAYS_CIRCUITS=(
  "gcp_jwt_verifier"
)