#!/bin/bash
# Setup cron job for inbox batch processing
# This script adds a cron job to run process_inbox_batch.py daily at 23:00

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PYTHON3_PATH=$(which python3)
BATCH_SCRIPT="$REPO_ROOT/tools/process_inbox_batch.py"
LOG_DIR="$HOME/logs"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Cron job entry: Run daily at 23:00
CRON_ENTRY="0 23 * * * cd $REPO_ROOT && $PYTHON3_PATH $BATCH_SCRIPT >> $LOG_DIR/inbox_batch.log 2>&1"

echo "Setting up cron job for inbox batch processing..."
echo ""
echo "Cron entry to be added:"
echo "$CRON_ENTRY"
echo ""

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -q "$BATCH_SCRIPT"; then
    echo "⚠️  A cron job for inbox batch processing already exists."
    echo ""
    echo "Current crontab entries:"
    crontab -l | grep -v "^#" | grep -v "^$" || echo "(none)"
    echo ""
    read -p "Do you want to replace it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled. No changes made."
        exit 0
    fi
    # Remove existing entry
    crontab -l 2>/dev/null | grep -v "$BATCH_SCRIPT" | crontab -
fi

# Add new cron job
(crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -

echo "✅ Cron job added successfully!"
echo ""
echo "The inbox batch processing will run daily at 23:00 (11:00 PM)."
echo "Logs will be written to: $LOG_DIR/inbox_batch.log"
echo ""
echo "To view current crontab entries:"
echo "  crontab -l"
echo ""
echo "To remove this cron job:"
echo "  crontab -l | grep -v '$BATCH_SCRIPT' | crontab -"
echo ""
echo "To test the batch processing manually:"
echo "  cd $REPO_ROOT && $PYTHON3_PATH $BATCH_SCRIPT"

