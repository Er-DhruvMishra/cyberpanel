# Backup V2

Backup V2 makes encrypted, deduplicated incremental backups of site files, databases, mail and configuration.

## Recommended: the Backup V2 add-on

Open [Backup V2](/addons/backup/) in Universal Add-ons. It uses `restic` (install it with `dnf install restic` or `apt install restic`).

1. **Repositories**: add a **Local directory**, **SFTP** (use **Show this server's SSH key** to authorise it), **S3 / Wasabi / B2 / MinIO**, or an **rclone remote** (create it first with `rclone config`, for Google Drive or OneDrive). Click **Save and initialise**.
2. **Schedules**: choose daily, hourly, weekly or manual, the hour, what to include (files, databases, mail, vhost & SSL config), whether to verify the repository, and how many daily, weekly and monthly snapshots to keep. Apply it to all sites or chosen ones.
3. **Snapshots & restore**: **List snapshots**, **Browse snapshot**, then **Restore this folder** or **Restore whole snapshot**. Restores can go to another folder; in-place restores take a safety snapshot first.

Keep the repository password safe: without it the backups cannot be restored.

## Built-in Backup V2 pages

The **Create V2 Backup**, **Restore V2 Backups**, **Schedule V2 Backup** and **Delete V2 Repo** pages (`/IncrementalBackups/...`) work with repositories set up under **ConfigureV2Backup** (Google Drive or SFTP accounts). On servers without a paid licence they send you to the setup page or to the add-on.

## Common problems

- **restic is not installed**: install it, then reload the add-on.
- **SFTP repository fails**: add the server's SSH key to the remote user's `authorized_keys`.
