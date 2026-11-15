# Universal Add-ons

Universal Add-ons are free modules that ship with this panel and replace the paid CyberPanel add-on bundle. Open them from **Universal Add-ons** in the sidebar (`/addons/`).

## What is included

- [Email Debugger](/addons/email-debugger/): DNS, blocklist, port, TLS and queue checks, message tracing and spam scoring.
- [Email Limits](/addons/email-limits/): outbound limits per domain and per mailbox.
- [Backup V2](/addons/backup/): encrypted incremental backups with restic.
- [Apache Manager](/addons/apache/): serve chosen sites through Apache and PHP-FPM behind OpenLiteSpeed.
- [Web Terminal](/addons/terminal/): a browser shell as the website's Linux user.
- [.htaccess for OpenLiteSpeed](/addons/htaccess/), [SSL V2](/addons/ssl/), [Rspamd Manager](/addons/rspamd/), [Root File Manager](/addons/root-file-manager/), [WordPress Manager Pro](/addons/wordpress/), [Resource Limits](/addons/limits/), [Storage Cleaner](/addons/storage/), [SSH Security](/addons/ssh-security/), [MySQL Manager](/addons/mysql/) and more.

## Access for users

Administrators see every add-on. On the hub page they choose which add-ons resellers and users may open; everyone else sees only those.

## Common problems

- An add-on card says a requirement is missing (for example `restic` for Backup V2): install that package on the server, then reload the hub.
- Panel pages that used to say "requires the CyberPanel Add-ons bundle" now send you to this hub.
