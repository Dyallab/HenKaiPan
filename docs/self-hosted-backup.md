# Backup & Restore Guide — HenKaiPan ASPM

This guide covers how to backup and restore your self-hosted HenKaiPan ASPM instance.

## Quick Start

### Create a Backup

```bash
# Using the backup script (recommended)
./scripts/backup.sh

# Manual backup with docker compose
docker compose exec postgres pg_dump -U aspm -d aspm > backup-$(date +%Y%m%d-%H%M%S).sql
```

### Restore from Backup

```bash
# Using psql directly
psql "$DATABASE_URL" < aspm-backup-2026-05-02T10-30-00.sql

# Using docker compose
docker compose exec -T postgres psql -U aspm -d aspm < aspm-backup-2026-05-02T10-30-00.sql
```

---

## Backup Script

The backup script (`scripts/backup.sh`) automates the backup process:

- Reads `DATABASE_URL` from `.env` or environment
- Creates timestamped backup in `backups/` directory
- Prints restore instructions on completion

### Usage

```bash
# Default: reads DATABASE_URL from .env
./scripts/backup.sh

# Or set DATABASE_URL explicitly
DATABASE_URL="postgresql://user:pass@localhost:5432/aspm" ./scripts/backup.sh

# Custom backup directory
BACKUP_DIR=/path/to/backups ./scripts/backup.sh
```

### Output

```
HenKaiPan ASPM Backup
=====================

Database: postgresql://aspm:***@localhost:5432/aspm
Backup file: /path/to/backups/aspm-backup-2026-05-02T10-30-00.sql

Creating backup...

✓ Backup completed successfully!
  File: /path/to/backups/aspm-backup-2026-05-02T10-30-00.sql
  Size: 1.2M

To restore this backup:
  psql "postgresql://aspm:***@localhost:5432/aspm" < /path/to/backups/aspm-backup-2026-05-02T10-30-00.sql

Or using docker compose:
  docker compose exec -T postgres psql -U aspm -d aspm < /path/to/backups/aspm-backup-2026-05-02T10-30-00.sql
```

---

## Automated Backups

### Daily Backup (cron)

Add to crontab (`crontab -e`):

```cron
# Daily backup at 2:00 AM
0 2 * * * /path/to/appsec-aspm/scripts/backup.sh >> /var/log/aspm-backup.log 2>&1
```

### Weekly Backup with Retention

```bash
#!/bin/bash
# /usr/local/bin/aspm-weekly-backup.sh

BACKUP_DIR="/backups/aspm"
DATE=$(date +%Y%m%d)
WEEK_OLD=$(date -d "7 days ago" +%Y%m%d)

# Create backup
/path/to/appsec-aspm/scripts/backup.sh

# Delete backups older than 7 days
find "$BACKUP_DIR" -name "aspm-backup-*.sql" -mtime +7 -delete

echo "Backup completed. Old backups cleaned."
```

Cron entry:
```cron
0 2 * * 0 /usr/local/bin/aspm-weekly-backup.sh >> /var/log/aspm-backup.log 2>&1
```

---

## Backup Retention Recommendations

| Frequency | Retention | Storage |
|-----------|-----------|---------|
| Daily | 7 days | Local disk |
| Weekly | 4 weeks | Offsite backup |
| Monthly | 6 months | Archive storage |

### Storage Best Practices

1. **Offsite copies**: Sync backups to S3, GCS, or another server
2. **Encryption**: Encrypt backups containing sensitive data
3. **Test restores**: Periodically verify backups can be restored
4. **Monitor disk space**: Set alerts when backup directory exceeds threshold

---

## Troubleshooting

### `pg_dump: command not found`

Install PostgreSQL client tools:

```bash
# Ubuntu/Debian
sudo apt-get install postgresql-client

# macOS
brew install postgresql

# Or use docker compose directly
docker compose exec postgres pg_dump -U aspm -d aspm > backup.sql
```

### `DATABASE_URL not set`

Ensure `.env` file exists in project root with valid `DATABASE_URL`:

```env
DATABASE_URL=postgresql://aspm:aspm@localhost:5432/aspm?sslmode=disable
```

### Permission denied on backup file

```bash
# Check backup directory permissions
ls -la backups/

# Fix if needed
chmod 755 backups/
```

### Restore fails with "database already exists"

The backup contains `CREATE TABLE` statements. Drop existing tables first or restore to a fresh database:

```bash
# Drop and recreate database (WARNING: destroys existing data)
docker compose exec postgres psql -U aspm -d aspm -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Then restore
docker compose exec -T postgres psql -U aspm -d aspm < backup.sql
```

### Restore fails with connection error

Verify database is running and accessible:

```bash
# Check postgres container
docker compose ps postgres

# Test connection
docker compose exec postgres psql -U aspm -d aspm -c "SELECT 1"
```

---

## What's Backed Up

The backup includes:

- ✅ All database tables (users, teams, apps, projects, scans, findings, etc.)
- ✅ Migrations history
- ✅ Policies and suppressions
- ✅ Knowledge articles
- ✅ Webhook configurations
- ✅ Scan schedules
- ✅ Audit logs

### Not Backed Up

- ❌ Docker volumes (scanner data, logs)
- ❌ `.env` file (store separately!)
- ❌ Custom scanner configurations
- ❌ Log files

---

## Migration to New Server

1. **Backup source server**:
   ```bash
   ./scripts/backup.sh
   ```

2. **Copy backup to new server**:
   ```bash
   scp aspm-backup-*.sql user@new-server:/path/to/backup.sql
   ```

3. **Restore on new server**:
   ```bash
   # Start infrastructure
   docker compose up -d postgres
   
   # Wait for postgres to be ready
   sleep 10
   
   # Restore
   docker compose exec -T postgres psql -U aspm -d aspm < /path/to/backup.sql
   
   # Start full stack
   docker compose up -d
   ```

4. **Verify**:
   - Check `/api/health` endpoint
   - Login to frontend
   - Verify projects and scans are visible
