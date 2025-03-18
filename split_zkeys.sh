#!/bin/bash

ZKEY_FOLDER="/zkeys"
PARTS=5

# Loop through all .zkey files ending with 512r1.zkey
for FILE in "$ZKEY_FOLDER"/*512r1.zkey; do
    # Check if there are matching files
    if [[ ! -f "$FILE" ]]; then
        echo "No matching files found in $ZKEY_FOLDER"
        exit 0
    fi

    # Get total file size
    FILE_SIZE=$(stat -c%s "$FILE")
    PART_SIZE=$((FILE_SIZE / PARTS))

    echo "Splitting $FILE into $PARTS parts of approx $PART_SIZE bytes each..."

    # Split the file into 5 parts
    split -b $PART_SIZE -d "$FILE" "$FILE.part"

    echo "Split complete. Generated files:"
    ls -lh "$FILE".part*

    # Remove the original file
    rm -rf "$FILE"
done

for FILE in "$ZKEY_FOLDER"/*521r1.zkey; do
    # Check if there are matching files
    if [[ ! -f "$FILE" ]]; then
        echo "No matching files found in $ZKEY_FOLDER"
        exit 0
    fi

    # Get total file size
    FILE_SIZE=$(stat -c%s "$FILE")
    PART_SIZE=$((FILE_SIZE / PARTS))

    echo "Splitting $FILE into $PARTS parts of approx $PART_SIZE bytes each..."

    # Split the file into 5 parts
    split -b $PART_SIZE -d "$FILE" "$FILE.part"

    echo "Split complete. Generated files:"
    ls -lh "$FILE".part*

    # Remove the original file
    rm -rf "$FILE"
done