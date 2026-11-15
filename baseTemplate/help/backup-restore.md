# Backing up and restoring a website

A full website backup is one `.tar.gz` file with the site's files, databases, email and settings. It can be restored on this server or on another server running this panel.

## Create a backup

1. Open **Backups > Create Backup** (`/backup/backupSite`).
2. **Select Website** and the **Destination** (**Home** keeps it on this server).
3. Click **Create Backup** and follow **Backup Status**.

The file is saved as `/home/<domain>/backup/backup-<domain>-<date>.tar.gz`. **Existing Backups** lists the backups of the site; you can delete old ones there. Download them with the File Manager or SFTP to keep a copy off the server.

## Restore a backup

1. Copy the backup file into `/home/backup/` on the server (for example with SFTP as root, or the Root File Manager).
2. Open **Backups > Restore Backup** (`/backup/restoreSite`).
3. Choose the file under **Available Backups** and click **Start Restoration**.

## Common problems

- **Site related to this backup already exists**: delete the website first, or restore on another server.
- **Backup fails**: check free disk space; the backup needs roughly the size of the site again.
- For automatic, encrypted, space-saving backups use [Backup V2](/addons/backup/); see [Backup V2](/base/help/backup-v2). Schedules: [Scheduled backups](/base/help/backup-schedule).
