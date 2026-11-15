# FTP accounts

FTP accounts give access to a website's files through Pure-FTPd. Each account is locked to a folder of one website.

## Create an account

1. Open **Databases & FTP > Create FTP Account** (`/ftp/createFTPAccount`).
2. **Select Website**.
3. Enter the **FTP Username**. It is prefixed with the owner's username, for example `admin_deploy`.
4. Enter or **Generate** an **FTP Password**.
5. **Path (Relative)**: leave empty for the website's home directory, or enter a sub-folder such as `public_html/uploads`.
6. Click **Create FTP Account**.

Connect with an FTP client to the server's hostname or IP, port 21, using explicit TLS (FTPES) when your client supports it.

## Service (administrator)

**Server > Pure-FTPd** (`/manageservices/managePureFtpd`) starts or stops the FTP service. Make sure port 21 and the passive port range (40110-40210) are open in the firewall.

## Common problems

- **Login fails**: use the full prefixed username.
- **Directory listing times out**: passive ports are blocked by a firewall; open them or switch the client to active mode.
- Prefer [SFTP](/base/help/ssh-manager): it is encrypted and uses the SSH port only.
