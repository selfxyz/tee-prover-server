#!/bin/bash

ZKEYS_DIR="/zkeys"

echo "Merging all split files in $ZKEYS_DIR..."

# Find all unique filenames (without .part extensions)
for base_name in $(ls "$ZKEYS_DIR"/*.part* | sed -E 's/\.part[0-9]+$//' | sort -u); do
    output_file="$base_name"

    echo "Merging parts into $output_file..."

    # Concatenate all parts in order
    cat "$base_name".part* > "$output_file"

    # Check if merge was successful
    if [ $? -eq 0 ]; then
        echo "Successfully reconstructed: $output_file"
        
        # Remove the split parts
        rm -v "$base_name".part*
    else
        echo "Error reconstructing $output_file!"
        exit 1
    fi
done

echo "All files merged and original parts removed successfully!"