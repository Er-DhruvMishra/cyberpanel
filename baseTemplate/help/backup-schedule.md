# Scheduled backups

Scheduled backups run full website backups daily or weekly to a local folder or an SFTP server.

## Steps

1. Add a destination first; see [Backup destinations](/base/help/backup-destinations).
2. Open **Backups > Schedule Backup** (`/backup/scheduleBackup`).
3. Under **Create New Backup Schedule**, **Select Destination**, enter a **Schedule Name**, choose the **Backup Frequency** (Daily or Weekly) and the **Backup Retention in days** (0 keeps all).
4. Click **Add Schedule**.
5. Under **Manage Existing Backup Schedules**, **Select Job**, then either click **Enable All Sites** (all current and future websites) or add sites one by one and click **Use Selected Sites**.

**View Logs** shows the result of each run. **Last Run** and **Current Status** show whether the last run worked.

## Common problems

- **Job never runs**: the backup cron job is missing; check root's crontab for the panel backup entries.
- **Disk fills up**: set a retention, and send backups to a remote destination.
- [Backup V2](/addons/backup/) offers incremental, encrypted schedules that use far less space.
