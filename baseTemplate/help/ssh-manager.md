# SSH and SFTP access

Every website has its own Linux user. You can give that user a password or SSH keys so the site owner can log in with SSH or SFTP.

## Per-website access

1. Open the website's page and click **SSH/SFTP Access**.
2. The **SSH User** shown is the site's Linux user. Set a **Password** and click **Save Changes**.
3. Under **SSH Keys**, click **Add Key**, paste a public key (for example the contents of `id_ed25519.pub`) and click **Save Key**.
4. Connect with an SFTP client (FileZilla, WinSCP) or `ssh user@server` on the server's SSH port.

On CloudLinux servers the same page turns **CageFS** on or off for the user; see [CloudLinux and CageFS](/base/help/cloudlinux).

## Server SSH settings (administrator)

**Security > Secure SSH** (`/firewall/secureSSH`) sets the **SSH Port**, turns **Permit Root Login** on or off and manages root's SSH keys. Before disabling root login, make sure another account with sudo works. After changing the port, open it in the firewall first.

The [SSH Security](/addons/ssh-security/) add-on adds login analysis, an sshd hardening audit and an IP blocklist.

## Common problems

- **Connection refused**: wrong port, or the port is closed in the firewall.
- **Permission denied (publickey)**: the key was added to a different user, or the client uses another key.
