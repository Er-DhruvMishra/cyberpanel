# Backup destinations

Destinations tell scheduled backups where to store files: a folder on this server or an SFTP server.

## Steps

1. Open **Backups > Destinations** (`/backup/backupDestinations`).
2. **Select Destination Type**: **Local Storage** or **SFTP Server**.
3. For local storage, enter a **Local Path** such as `/backup` (ideally a separate disk) and click **Add Local Destination**.
4. For SFTP, enter a **Name**, the server **IP Address**, **Username**, **Password**, **SSH Port** and **Remote Path**, then click **Add SFTP Destination**.
5. Use the destination in [Scheduled backups](/base/help/backup-schedule).

Configured destinations are listed below the form with a **Delete** button.

## Common problems

- **SFTP destination fails**: test the login with an SFTP client from this server, and check that the remote path exists and is writable.
- A local destination on the same disk does not protect against disk failure. Keep at least one copy elsewhere.
