#!/bin/bash

circuits=(
  "register_aadhaar:self-trusted-setup-new-aadhaar-ph2-ceremony:aws"
  "register_kyc:trusted-setup-kyc:gcp"
  "register_sha1_sha1_sha1_rsa_64321_4096:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "register_sha1_sha1_sha1_ecdsa_brainpoolP224r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha1_sha1_sha1_ecdsa_secp256r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha256_sha1_sha1_rsa_65537_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha1_sha1_sha1_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha1_sha256_sha256_rsa_65537_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha224_sha224_sha224_ecdsa_brainpoolP224r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha256_sha224_sha224_ecdsa_secp224r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha256_sha256_sha224_ecdsa_secp224r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_ecdsa_brainpoolP256r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_ecdsa_brainpoolP384r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_ecdsa_secp256r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_ecdsa_secp384r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_rsa_3_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_rsa_65537_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_rsapss_3_32_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_rsapss_65537_32_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_rsapss_65537_32_3072:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_rsapss_65537_32_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha256_sha256_sha256_rsapss_65537_64_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha512_sha512_sha256_rsapss_65537_32_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha384_sha384_sha384_ecdsa_brainpoolP384r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha384_sha384_sha384_ecdsa_brainpoolP512r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha384_sha384_sha384_ecdsa_secp384r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha512_sha512_sha256_rsapss_65537_32_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha384_sha384_sha384_rsapss_65537_48_2048:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha512_sha512_sha256_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha512_sha512_sha512_ecdsa_brainpoolP512r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_sha512_sha512_sha512_ecdsa_secp521r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha512_sha512_sha512_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_sha512_sha512_sha512_rsapss_65537_64_2048:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha1_sha1_sha1_ecdsa_brainpoolP224r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha1_sha1_sha1_ecdsa_secp256r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha1_sha1_sha1_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha1_sha256_sha256_rsa_65537_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha224_sha224_sha224_ecdsa_brainpoolP224r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha256_sha224_sha224_ecdsa_secp224r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha224_ecdsa_secp224r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_ecdsa_brainpoolP256r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_ecdsa_brainpoolP384r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_ecdsa_secp256r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_ecdsa_secp384r1:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_rsa_3_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_rsa_65537_4096:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_rsapss_3_32_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_rsapss_65537_32_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_rsapss_65537_32_3072:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha256_sha256_sha256_rsapss_65537_64_2048:self-trusted-setup-sha-256-bytes-ph2-ceremony:aws"
  "register_id_sha384_sha384_sha384_ecdsa_brainpoolP384r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha384_sha384_sha384_ecdsa_brainpoolP512r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha384_sha384_sha384_ecdsa_secp384r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha384_sha384_sha384_rsapss_65537_48_2048:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha512_sha512_sha256_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha512_sha512_sha512_ecdsa_brainpoolP512r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha512_sha512_sha512_ecdsa_secp521r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha512_sha512_sha512_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "register_id_sha512_sha512_sha512_rsapss_65537_64_2048:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "vc_and_disclose:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "vc_and_disclose_id:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "vc_and_disclose_aadhaar:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "vc_and_disclose_kyc:trusted-setup-kyc:gcp"
  "dsc_sha256_rsa_107903_4096:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "dsc_sha256_rsa_122125_4096:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "dsc_sha256_rsa_130689_4096:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "dsc_sha256_rsa_56611_4096:self-trusted-setup-aadhaar-rsa-ph2-ceremony:aws"
  "dsc_sha1_ecdsa_brainpoolP256r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha1_ecdsa_secp256r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha1_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_ecdsa_brainpoolP256r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_ecdsa_brainpoolP384r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_ecdsa_secp256r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_ecdsa_secp384r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_ecdsa_secp521r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_rsapss_3_32_3072:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_rsapss_65537_32_3072:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha256_rsapss_65537_32_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha384_rsapss_65537_48_3072:self-trusted-setup-for-serbia:aws"
  "dsc_sha384_ecdsa_brainpoolP384r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha384_ecdsa_brainpoolP512r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha384_ecdsa_secp384r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha512_ecdsa_brainpoolP512r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha512_ecdsa_secp521r1:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha512_rsa_65537_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
  "dsc_sha512_rsapss_65537_64_4096:self-zk-passport-ceremony-extended---ethcc-version-ph2-ceremony:aws"
)
download_zkey() {
  circuit_with_path="$1"
  
  # Parse circuit:bucket_name:provider format
  circuit=$(echo "$circuit_with_path" | cut -d':' -f1)
  bucket_name=$(echo "$circuit_with_path" | cut -d':' -f2)
  provider=$(echo "$circuit_with_path" | cut -d':' -f3)
  
  # Default to aws if provider not specified
  if [[ -z "$provider" ]]; then
    provider="aws"
  fi
  
  circuit_lc=$(echo "$circuit" | tr '[:upper:]' '[:lower:]')
  
  if [[ "$provider" == "gcp" ]]; then
    circuit_path="gs://${bucket_name}/circuits/${circuit_lc}/contributions/"
    
    latest_file=$(gsutil ls "$circuit_path" | grep '\.zkey$' | sort | tail -n 1 | xargs basename)
    
    if [[ -z "$latest_file" ]]; then
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
