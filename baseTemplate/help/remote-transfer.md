# Transferring websites from another server

**Remote Backups** copies websites from another server running CyberPanel (or this panel) to this server: it backs them up there, transfers the files and restores them here.

## Prepare the old server

- Enable **API Access** for its admin account (**Users & Plans > API Access**).
- The old panel must answer on port 8090 (this page always uses that port), and SSH must be open between the two servers: they exchange an SSH key to copy the backups.

## Steps

1. Open **Backups > Remote Backups** (`/backup/remoteBackups`).
2. Enter the **Remote Server IP Address** and the **Remote CyberPanel Admin Password** (the panel admin password, not the root SSH password).
3. Click **Fetch Accounts**. The websites on the remote server are listed with their PHP version, package and email.
4. Select the websites and click **Start Transfer**. Follow the backup, transfer and restore progress.

## Common problems

- **Could not connect**: API access is off on the remote panel, the password is wrong, or a firewall blocks port 8090 or SSH.
- **A website already exists here**: delete or rename it before transferring.
- After the transfer, update DNS to point to this server and issue SSL again.
