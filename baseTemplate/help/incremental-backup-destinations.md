# Incremental backup destinations

Incremental backups need a destination for their restic repository.

## Steps

1. Open **Backups > Incremental Backups** (`/IncrementalBackups/backupDestinations`).
2. Choose the **Destination Type**. This page supports **AWS S3**.
3. Enter the **AWS Access Key ID** and **AWS Secret Access Key** (from your AWS IAM console) and click **Add Destination**.
4. Use the destination in [Incremental backups](/base/help/incremental-backups).

Create an IAM user that can only access the backup bucket, and keep the secret key private.

## Other storage

[Backup V2](/addons/backup/) supports local folders, SFTP, S3-compatible storage (Wasabi, Backblaze B2, MinIO) and rclone remotes such as Google Drive and OneDrive.
