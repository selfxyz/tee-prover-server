#!/bin/bash

set -euo pipefail

# 1) Move all disclose circuits into ./circuits (they don't depend on zkey names here)
if [[ -d "./circuits/disclose" ]]; then
  shopt -s nullglob
  for dir in ./circuits/disclose/*; do
    [[ -d "$dir" ]] || continue
    mv "$dir" ./circuits
  done
  shopt -u nullglob
fi

# 2) For every zkey present locally, move the matching circuit folder from
#    ./circuits/{register|dsc}/<circuit_name[[_cpp]]> into ./circuits
shopt -s nullglob
for zkey in zkeys/*.zkey; do
  name="${zkey#zkeys/}"
  name="${name%.zkey}"
  echo "Processing $name"

  # Determine category based on filename prefix
  if [[ "$name" == register* ]]; then
    category="register"
  elif [[ "$name" == dsc* ]]; then
    category="dsc"
  elif [[ "$name" == vc_and_disclose* ]]; then
    # Disclose circuits were already moved en-masse above; skip
    continue
  else
    # Unknown prefix; skip gracefully
    continue
  fi

  base="./circuits/${category}/${name}_cpp"

  # warn if the folder doesn't exist
  if [[ ! -d "${base}" ]]; then
    echo "Warning: circuit folder not found for ${name} under ./circuits/${category}/" >&2
    continue
  fi

  mv "${base}" ./circuits
  echo "Moved ${base} to ./circuits/"
done
shopt -u nullglob

# 3) Cleanup category folders
rm -rf ./circuits/disclose/ ./circuits/dsc/ ./circuits/register/
