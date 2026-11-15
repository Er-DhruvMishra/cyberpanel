# Backups to Google Drive

There are two ways to back up to Google Drive. For a server you host yourself, the Backup V2 add-on is the simpler and fully self-hosted one.

## Recommended: Backup V2 with rclone

1. On the server, run `rclone config` as root and create a Google Drive remote (for example named `gdrive`).
2. Open [Backup V2](/addons/backup/), add a repository of type **rclone remote (Google Drive, OneDrive…)** using that remote, and click **Save and initialise**.
3. Add a schedule. Backups are encrypted before they leave the server.

See [Backup V2](/base/help/backup-v2) for details.

## Built-in Google Drive page

**Backups > Google Drive** (`/backup/gDrive`) uploads full website backups to Google Drive.

1. Click **Setup New Account**, enter an **Account Name** (letters, digits, `-` and `_`), and the **client ID** (ends with `.apps.googleusercontent.com`) and **client secret** of your own Google OAuth client. The client only gets access to files it creates.
2. Click **Continue Setup** and approve access in the Google window.
3. **Select Google Drive Account**, choose the **Backup Frequency** (Daily or Weekly) and add websites with **Add Site**. **View Logs** shows each run.

The Google sign-in step of this page goes through the panel vendor's sign-in relay (platform.cyberpersons.com). When that relay is not configured on this server, the page reports that new Google Drive enrolment is unavailable; existing accounts and schedules keep working. Use Backup V2 in that case.

## Common problems

- **Enrolment unavailable**: see above; use Backup V2.
- **Setup window expires**: finish the Google approval within five minutes, then try again.
