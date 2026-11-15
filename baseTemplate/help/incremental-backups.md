# Incremental backups

Incremental backups store only what changed since the last run, using restic. They save space and time compared with full backups.

## Requirements

`restic` must be installed on the server (`dnf install restic` or `apt install restic`). The panel tries to install it automatically; if that fails, install it by hand.

## Create a backup

1. Add a destination; see [Incremental backup destinations](/base/help/incremental-backup-destinations).
2. Open the incremental **Create Backup** page (`/IncrementalBackups/createBackup`, the **Legacy v1** tile under **Backups**).
3. **Select Website** and the **Backup Destination**.
4. Tick the **Backup Content**: Website Data, Databases, Email Accounts.
5. Click **Create Backup**.

**Existing Backups** lists the backup jobs. Open **Restore Points** to restore one snapshot or **Delete** it.

## Schedule

**Schedule Backup** (`/IncrementalBackups/scheduleBackups`) runs the same backups daily or weekly for the sites you choose, with a retention.

## Common problems

- **"It seems restic is not installed" [5009]**: install restic as shown above, then retry.
- For a more complete tool with previews, safe in-place restores and more storage types, use [Backup V2](/addons/backup/).
