#!/bin/bash

source "$(dirname "${BASH_SOURCE[0]}")/constants.sh"

circuits=(
  "register_aadhaar:self-trusted-setup-new-aadhaar-ph2-ceremony:aws"
  "register_kyc:register-kyc-fix-nullifier:gcp"
  "register_sha256_sha256_sha256_rsa_65537_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_ecdsa_brainpoolP256r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_rsa_65537_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_ecdsa_brainpoolP256r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "vc_and_disclose:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "vc_and_disclose_id:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "vc_and_disclose_aadhaar:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "vc_and_disclose_kyc:trusted-setup-kyc:gcp"
  "dsc_sha256_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_ecdsa_brainpoolP256r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
)

# Circuits present in every image variant (see ALWAYS_CIRCUITS in constants.sh). The
# cherrypick image is a real deployment target carrying the same Confidential Space
# launch labels, and tee-server requires the attestation circuit unconditionally, so
# this list cannot be a subset that omits it. Mirrors download_zkeys.sh, including the
# 4th "required" field that makes an empty bucket listing fatal rather than a skip.
for always_circuit in "${ALWAYS_CIRCUITS[@]}"; do
  case "$always_circuit" in
    gcp_jwt_verifier)
      circuits+=("gcp_jwt_verifier:ecdsa-fix-plus-jwt:gcp:required")
      ;;
    *)
      echo "No bucket mapping for always-present circuit: $always_circuit" >&2
      exit 1
      ;;
  esac
done

download_zkey() {
  circuit_with_path="$1"
  
  # Parse circuit:bucket_name:provider format
  circuit=$(echo "$circuit_with_path" | cut -d':' -f1)
  bucket_name=$(echo "$circuit_with_path" | cut -d':' -f2)
  provider=$(echo "$circuit_with_path" | cut -d':' -f3)
  # Optional 4th field: "required" means an empty result is fatal, not a skip.
  required=$(echo "$circuit_with_path" | cut -d':' -f4)
  
  # Default to aws if provider not specified
  if [[ -z "$provider" ]]; then
    provider="aws"
  fi
  
  circuit_lc=$(echo "$circuit" | tr '[:upper:]' '[:lower:]')
  
  if [[ "$provider" == "gcp" ]]; then
    circuit_path="gs://${bucket_name}/circuits/${circuit_lc}/contributions/"
    
    latest_file=$(gsutil ls "$circuit_path" | grep '\.zkey$' | sort | tail -n 1 | xargs basename)
    
    if [[ -z "$latest_file" ]]; then
      if [[ "$required" == "required" ]]; then
        # Non-zero exit inside `bash -c` makes xargs return non-zero, which fails the
        # calling CI step — the loud failure this circuit's absence deserves.
        echo "FATAL: no .zkey found for required circuit $circuit at $circuit_path" >&2
        exit 1
      fi
      echo "No .zkey found for $circuit — skipping." >&2
      return
    fi
    
    gs_url="${circuit_path}${latest_file}"
    fixed_filename=$(echo "$latest_file" | sed -E 's/brainpoolp([0-9]+r1)/brainpoolP\1/g')
    base_name=$(echo "$fixed_filename" | sed -E 's/_0000[0-9]+\.zkey$/.zkey/')
    
    echo "Downloading $gs_url -> $base_name"
    gsutil cp "$gs_url" "$base_name"
  else
    # Default to AWS
    circuit_path="s3://${bucket_name}/circuits/${circuit_lc}/contributions/"
    
    latest_file=$(aws s3 ls "$circuit_path" | grep '\.zkey' | awk '{print $4}' | sort | tail -n 1)
    
    if [[ -z "$latest_file" ]]; then
      if [[ "$required" == "required" ]]; then
        # See the GCP branch above: exit non-zero so xargs fails the CI step.
        echo "FATAL: no .zkey found for required circuit $circuit at $circuit_path" >&2
        exit 1
      fi
      echo "No .zkey found for $circuit — skipping." >&2
      return
    fi
    
    s3_url="${circuit_path}${latest_file}"
    fixed_filename=$(echo "$latest_file" | sed -E 's/brainpoolp([0-9]+r1)/brainpoolP\1/g')
    base_name=$(echo "$fixed_filename" | sed -E 's/_0000[0-9]+\.zkey$/.zkey/')
    
    echo "Downloading $s3_url -> $base_name"
    aws s3 cp "$s3_url" "$base_name"
  fi
}

export -f download_zkey

# Feed all circuits into xargs with parallelism
printf "%s\n" "${circuits[@]}" | xargs -n 1 -P 8 -I {} bash -c 'download_zkey "$@"' _ {}
