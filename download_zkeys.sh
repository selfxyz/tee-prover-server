#!/bin/bash

echo -e "s3://self-protocol/zkeys_small.tar.zst\ns3://self-protocol/zkeys_medium.tar.zst\ns3://self-protocol/zkeys_large.tar.zst" | \
xargs -n 1 -P 3 -I {} bash -c '
    filename=$(basename "{}")
    echo "Downloading $filename..."
    aws s3 cp "{}" .
    
    echo "Extracting $filename..."
    tar --zstd -xf "$filename"
'