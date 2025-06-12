#!/bin/bash

KEY="mysecretkey"  # You can change this
SUFFIX=".enc"

for file in *; do
    # Skip if it's already encrypted or a directory
    if [[ -f "$file" && "$file" != *.enc ]]; then
        openssl enc -aes-256-cbc -salt -in "$file" -out "$file$SUFFIX" -k "$KEY"
        echo "🔐 Encrypted: $file -> $file$SUFFIX"
    fi
done

echo "✅ All files encrypted in current folder."
