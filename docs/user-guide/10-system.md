# System Status

Monitor the health of your HenKaiPan instance with real-time metrics.

![System](/presentation/12-audit.png)

## Health Check

Real-time status of core components:

| Component | Status | Details |
|-----------|--------|---------|
| API | 🟢 Healthy | Responding on port 8080 |
| Worker | 🟢 Healthy | Processing queue |
| PostgreSQL | 🟢 Healthy | Connection pool healthy |
| Redis | 🟢 Healthy | Queue transport ready |
| Disk | 🟡 Warning | 75% used |

## Queue Metrics

Asynq queue statistics:
- Pending jobs
- Active jobs (currently executing)
- Completed jobs (last 24h)
- Failed jobs
- Dead Letter Queue size

### Queue Throughput
- Jobs enqueued per minute
- Average processing time
- Retry rate

## Database Stats

- Total connections / max connections
- Query latency (p50, p95, p99)
- Table sizes (findings, scans, projects)
- Migration status

## Version Information

- Current version (e.g., `v0.9.0`)
- Build timestamp
- Git commit hash
- "New version available" indicator (if update exists)

## Backup Status

- Last backup timestamp
- Backup size
- Backup location
- Next scheduled backup

## Logs

Recent application logs:
- Filter by severity (INFO, WARN, ERROR)
- Search by keyword
- Download as text file

## Performance

- API response times (p50, p95, p99)
- Worker job duration
- Scanner execution times
- Memory usage

## Alerts

System alerts and warnings:
- High queue depth (>100 pending jobs)
- Database connection pool exhaustion
- Disk space low (<20% free)
- Worker offline (>5 minutes without heartbeat)

## Self-Hosted Operations

### Backup & Restore
- `scripts/backup.sh` — Full database backup
- [Backup & Restore Guide](https://henkaipan.dyallab.com.ar/docs/backup) — Restore procedure

### Upgrade Path
1. Pull new Docker images
2. Run migrations (automatic on startup)
3. Verify health check
4. Review release notes

### Scaling Workers
- Run multiple worker instances
- Redis handles load balancing
- Monitor queue depth for scaling decisions

---

**Previous:** [← Reports](/dashboard/documentation?page=reports)  
**Next:** [← Back to Introduction](/dashboard/documentation?page=introduction)
