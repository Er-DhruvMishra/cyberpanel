# Upgrading the panel

Upgrades install the latest code of this panel's fork from GitHub and then restart the panel services.

## Check your version

Open **Settings > Version Management** (`/base/versionManagment`). It shows the current and latest version, build and commit. A note appears when the installed commit differs from the latest one.

## Upgrade from the panel

1. Take a backup of important sites first (see [Backups](/base/help/backup-restore)).
2. On **Version Management**, choose the branch under **Select Branch**.
3. Click **Upgrade CyberPanel to selected branch** and follow the **Upgrade Progress Log**.
4. When the log reports completion, reload the page and confirm the new commit.

## Upgrade from SSH

As root, run the upgrade script of the fork:

```
sh <(curl https://raw.githubusercontent.com/Er-DhruvMishra/cyberpanel/main/preUpgrade.sh || wget -O - https://raw.githubusercontent.com/Er-DhruvMishra/cyberpanel/main/preUpgrade.sh)
```

## Common problems

- **Latest version shows nothing**: the server could not reach GitHub. Check outbound HTTPS and DNS.
- **Upgrade refused on servers with CSF**: the panel reports a firewall migration message; follow it before upgrading.
- Upgrades replace panel files, so hand-made changes to panel code are lost. Keep such changes in your own branch.
