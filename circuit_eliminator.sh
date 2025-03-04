#!/bin/bash

register_circuits=(
  "register_sha512_sha512_sha512_ecdsa_brainpoolP512r1:large" 
  "register_sha384_sha384_sha384_ecdsa_brainpoolP512r1:large" 
  "register_sha256_sha256_sha256_ecdsa_brainpoolP384r1:medium" 
  "register_sha256_sha256_sha256_ecdsa_secp384r1:medium" 
  "register_sha384_sha384_sha384_ecdsa_brainpoolP384r1:medium" 
  "register_sha384_sha384_sha384_ecdsa_secp384r1:medium"
)
dsc_circuits=(
  "dsc_sha384_ecdsa_brainpoolP512r1:large" 
  "dsc_sha512_ecdsa_brainpoolP512r1:large" 
  "dsc_sha256_ecdsa_brainpoolP384r1:medium" 
  "dsc_sha256_ecdsa_secp384r1:medium" 
  "dsc_sha384_ecdsa_brainpoolP384r1:medium" 
  "dsc_sha384_ecdsa_secp384r1:medium"
)
disclose_circuits=()

proof_type=$1
size_filter=$2

echo $proof_type
echo $size_filter
declare -A keep_circuits

define_circuits() {
  local size_filter="$1"
  local -n circuits_ref=$2
  for circuit in "${circuits_ref[@]}"; do
    IFS=":" read -r name size <<< "$circuit"
    if [[ "$size_filter" == "small" ]]; then
      keep_circuits["/circuits/${name}_cpp"]=-1
      keep_circuits["/zkeys/${name}.zkey"]=-1
    elif [[ "$size_filter" == "$size" ]]; then
      keep_circuits["/circuits/${name}_cpp"]=1
      keep_circuits["/zkeys/${name}.zkey"]=1
    fi
  done
}

case "$proof_type" in
  "register")
    define_circuits "$size_filter" register_circuits
    ;;
  "dsc")
    define_circuits "$size_filter" dsc_circuits
    ;;
  "disclose")
    define_circuits "$size_filter" disclose_circuits
    ;;
  *)
    echo "Invalid proof type: $proof_type"
    exit 1
    ;;
esac

all_circuit_dirs=(/circuits/*_cpp)
all_zkey_files=(/zkeys/*.zkey)

for dir in "${all_circuit_dirs[@]}"; do
  if [[ ("$size_filter" != "small" && ! -v keep_circuits[$dir]) || keep_circuits[$dir] -eq -1 ]]; then
    echo "Removing $dir"
    rm -rf "$dir"
  fi
done

for file in "${all_zkey_files[@]}"; do
  if [[ ("$size_filter" != "small" && ! -v keep_circuits[$file]) || keep_circuits[$file] -eq -1 ]]; then
    echo "Removing $file"
    rm -rf "$file"
  fi
done

echo "Cleanup complete, only specified $proof_type circuits of size $size_filter remain."
