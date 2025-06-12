#!/bin/bash

TARGET_FILE="$1"

if [[ -z "$TARGET_FILE" || ! -f "$TARGET_FILE" ]]; then
    echo "❌ No file provided or file does not exist: $TARGET_FILE"
    exit 1
fi

echo "🔍 Running analysis on: $TARGET_FILE"

LOG_DIR="/sandbox/logs"
mkdir -p "$LOG_DIR"

# Monitor file system events
inotifywatch -t 10 -e modify,create,delete,open,close_write "$(dirname "$TARGET_FILE")" > "$LOG_DIR/inotify.log" 2>&1 &
INOTIFY_PID=$!

# Trace system calls
strace -f -tt -T -o "$LOG_DIR/strace.log" "$TARGET_FILE" > "$LOG_DIR/program_output.log" 2>&1 &
STRACE_PID=$!

# Monitor network traffic
tcpdump -i any -w "$LOG_DIR/tcpdump.pcap" > /dev/null 2>&1 &
TCPDUMP_PID=$!

# Let the processes run for a while
sleep 10

# Kill them
kill $INOTIFY_PID $STRACE_PID $TCPDUMP_PID 2>/dev/null

echo "✅ Analysis complete. Logs saved in $LOG_DIR"
