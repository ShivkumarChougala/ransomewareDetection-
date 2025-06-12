#!/bin/bash

WATCH_DIR="/sandbox/watched_folder"
echo "📂 Watching $WATCH_DIR for new files..."

inotifywait -m -e create -e moved_to --format '%f' "$WATCH_DIR" | while read FILENAME; do
    FILEPATH="$WATCH_DIR/$FILENAME"
    echo "🧪 New file detected: $FILEPATH"

    if [ -f "$FILEPATH" ]; then
        chmod +x "$FILEPATH"
        timeout 5s strace -f -o "/sandbox/logs/${FILENAME}_strace.log" "$FILEPATH"
        echo "✅ Analysis done for $FILENAME"
    else
        echo "⚠️ File $FILENAME vanished before analysis."
    fi
done
