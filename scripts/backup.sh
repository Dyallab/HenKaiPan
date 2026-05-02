#!/bin/bash
#
# HenKaiPan ASPM Backup Script
# Creates a timestamped PostgreSQL backup and prints restore instructions.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"

# Load DATABASE_URL from .env if not set
if [ -z "$DATABASE_URL" ] && [ -f "$PROJECT_ROOT/.env" ]; then
    export DATABASE_URL=$(grep "^DATABASE_URL=" "$PROJECT_ROOT/.env" | cut -d'=' -f2-)
fi

if [ -z "$DATABASE_URL" ]; then
    echo "Error: DATABASE_URL not set and not found in .env"
    exit 1
fi

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate timestamp for filename
TIMESTAMP=$(date -u +"%Y-%m-%dT%H-%M-%S")
BACKUP_FILE="$BACKUP_DIR/aspm-backup-$TIMESTAMP.sql"

echo "HenKaiPan ASPM Backup"
echo "====================="
echo ""
echo "Database: $DATABASE_URL"
echo "Backup file: $BACKUP_FILE"
echo ""

# Run pg_dump
echo "Creating backup..."
pg_dump "$DATABASE_URL" > "$BACKUP_FILE"

# Get file size
FILE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)

echo ""
echo "✓ Backup completed successfully!"
echo "  File: $BACKUP_FILE"
echo "  Size: $FILE_SIZE"
echo ""
echo "To restore this backup:"
echo "  psql \"$DATABASE_URL\" < $BACKUP_FILE"
echo ""
echo "Or using docker compose:"
echo "  docker compose exec -T postgres psql -U aspm -d aspm < $BACKUP_FILE"
echo ""
