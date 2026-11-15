# Restoring incremental backups

## From this server's jobs

On the incremental **Create Backup** page (`/IncrementalBackups/createBackup`), open **Restore Points** of a backup job and click **Restore** on the snapshot you want.

## From a remote destination

Use this when the backups were made on another server, or the local job list was lost.

1. Open **Restore Remote Incremental Backups** (`/IncrementalBackups/restoreRemoteBackups`).
2. **Select Website**, the **Destination**, and enter the **Encrypted Backup Password** of the repository.
3. Click **Fetch Restore Points**. Snapshots are listed with their ID, date, host and path.
4. Click **Restore** on the snapshot.

## Common problems

- **Wrong password**: the repository password is needed exactly; without it the backups cannot be read.
- Restores overwrite current files. Take a fresh backup first if the site has changed since.
- [Backup V2](/addons/backup/) can preview a snapshot and restore to another folder first.
