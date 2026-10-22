# Universal Add-ons: plan

Seven modules for CyberPanel Universal, written as our own code in one Django app
(`universalAddons`). Upstream sells comparable features as paid add-ons and gates them
through `ACLManager.CheckForPremFeature` (a remote licence check against
platform.cyberpersons.com). We do **not** remove, bypass or call into those gated paths. The
upstream pages stay as they are, so syncing with upstream remains a plain merge. Our modules
sit beside them and depend only on:

- ungated, general helpers in `plogical/`: `ProcessUtilities`, `ACLManager.loadedACL`,
  `DNS.createDNSRecord`, `sslUtilities.installSSLForDomain`, `mailUtilities.FetchPostfixHostname`,
  `restic` jobs in `IncBackups`, the path-safety helpers in `filemanager/`;
- standard tools: acme.sh, restic, rclone, wp-cli, rspamd and the system's own daemons.

None of them call cyberpanel.net or cyberpersons.com.

## Shared foundation (milestone 0)

| item | design |
|---|---|
| App | `universalAddons/` with one sub-package per module (`emaildebug/`, `rootfm/`, …), each holding `views.py`, `service.py` (logic, no Django), `urls.py`, templates and tests |
| Routing | `/addons/<module>/…`, included once from `CyberCP/urls.py` |
| Navigation | one sidebar entry ("Universal Add-ons") placed at the `{# pluginsList #}` marker, plus a hub page listing the modules and their status on this host |
| Access | `@admin_required` (JSON and page variants) built on `ACLManager.loadedACL`, the same check upstream's admin pages use. Write actions are POST + CSRF only |
| Host awareness | each module declares its requirements (OS family, services, binaries). The hub shows "unavailable on this host" using `cyberpanel_os_profile` and `/etc/cyberpanel/disabled_features` instead of failing |
| Jobs | long operations (installs, issuance, backups) run detached with a status file under `/home/cyberpanel/universal-addons/<job>.json`, polled by the page, matching upstream's install-status pattern |
| Commands | argv lists only (`subprocess.run([...])`), never shell strings built from request data. Every user-supplied domain, path or email is validated against strict patterns |
| Tests | `service.py` logic is unit-tested without root or a database (`python3 -m unittest universalAddons...`), and must pass on Python 3.9 |

## Modules, in build order

Order is set by value to this server, risk to production and dependency on shared code.

### 1. Email Debugger: *read-only diagnostics* (started)
Debug delivery issues: SMTP logs, connection testing, DNS verification, spam score.

- **DNS checks per domain:**
  - MX present and resolving to this server;
  - `mail.<domain>` A/AAAA;
  - SPF: exactly one record, includes the sending IP, and stays under 10 DNS lookups;
  - DKIM: the `default._domainkey` TXT record matches `/etc/opendkim/keys/<d>/default.txt`;
  - DMARC: present, with policy shown;
  - PTR of the sending IP, plus forward-confirmed rDNS (FCrDNS) against `myhostname`;
  - each record gets pass/warn/fail with a fix hint.
- **DNSBL:** look up the sending IP on major DNS blocklists (Spamhaus ZEN, SpamCop, Barracuda, …).
- **Ports and TLS:** connect to 25/465/587/993/995/143/110 locally. For TLS ports, show the
  certificate subject, SAN match for `mail.<domain>`, expiry and self-signed status.
- **Postfix log analyser:** parse `/var/log/maillog` or `mail.log`.
  - Per-queue-ID message trace: from, to, status, relay, dsn, delay.
  - Search by address, domain or time range.
  - Top senders, deferral and bounce reasons, SASL auth failures by IP.
- **Queue summary:** size, oldest message, top destinations (read-only; upstream's queue page already handles actions).
- **Test message:** send to a given address with `sendmail` and follow its log trace live.
- **Spam score:** run a stored or pasted message through `rspamc` when Rspamd is present,
  or SpamAssassin when present. Otherwise header and authentication-results analysis only.

### 2. Root File Manager
Full-server file management from the browser (admin only).
- Own UI and API under `/addons/rootfm/`. Operations: list, read, write, upload, download,
  create, rename, copy, move, delete to `/root/.cp-trash` with restore, chmod/chown,
  archive/extract, and search.
- **Safety:**
  - Everything runs as root through `ProcessUtilities` with argv lists, after `realpath` normalisation.
  - Writes are refused under a protected list (`/proc`, `/sys`, `/dev`, `/boot`, `/etc/shadow`, …) unless explicitly unlocked per session.
  - A size cap applies to the editor, and every write is recorded in an audit log (`/var/log/cyberpanel_rootfm.log`).
- Re-uses the existing site file-manager front-end conventions where practical.

### 3. Rspamd Manager
Spam filtering that replaces SpamAssassin: Bayes, DKIM signing, greylisting, statistics.
- **Pre-flight:** detect SpamAssassin's `content_filter`, MailScanner and any existing 11332
  milter. The pre-flight is shown before anything changes, with a dry-run diff of `main.cf`.
- **Install:**
  - rspamd plus redis from distro or rspamd.com repos (EL8/9/10, Debian/Ubuntu);
  - milter on 127.0.0.1:11332, chained after OpenDKIM, or replacing it when Rspamd DKIM signing is enabled;
  - controller password generated;
  - every change is reversible via an uninstall that restores backed-up configs.
- **Settings UI (local.d overrides only):**
  - action thresholds (reject, add header, greylist);
  - Bayes autolearn plus learn spam/ham from a mailbox folder;
  - greylisting;
  - DKIM signing (migrate keys from OpenDKIM);
  - allow and deny lists;
  - ClamAV optional;
  - ratelimit integration with the existing email limits.
- **Stats:** from `rspamc stat` and the history API: scanned, actions and top symbols.

### 4. SSL V2
Automatic issuance and renewal, DNS-01 verification, wildcards, one-click management.
- Our own issuance through acme.sh with:
  - DNS-01 for wildcards and for sites behind proxies;
  - providers: **local PowerDNS** and **Cloudflare**;
  - HTTP-01 fallback via the existing free `sslUtilities` path.
- **PowerDNS:** a new hook (`dns_cpuniversal.sh`) that edits our own PowerDNS through the panel
  CLI. The pdns HTTP API is **not** opened to `0.0.0.0` (unlike upstream's helper).
- **Inventory:** every vhost and mail host, showing issuer, SANs, expiry and challenge type,
  with one-click issue, reissue, renew and remove.
- **Install:** into OLS/LSWS through the existing ungated `installSSLForDomain`.
- **Renewal:** acme.sh cron plus our own expiry monitor. It alerts and retries on failure, and
  covers the hostname and mail-server certificates.

### 5. Backup V2
Incremental, scheduled, remote (SFTP/S3/Google Drive), one-click restore.
- **restic** repositories (deduplicated, encrypted). Back ends:
  - local;
  - SFTP;
  - S3-compatible;
  - rclone, which covers Google Drive, B2, OneDrive and more.
- **Units:** site files, databases (`mysqldump --single-transaction` streamed into restic),
  mail and the vhost config. Policies set retention (keep daily/weekly/monthly) and a schedule
  via our own cron entry.
- **Restore:** a whole site, a single file or path, or only the database, to the original or
  an alternate location, with dry-run listing.
- **Protection:**
  - repository password stored root-only;
  - optional append-only and object-lock S3 to resist ransomware;
  - periodic `restic check`;
  - failure notification.

### 6. WordPress Manager Pro
Clone, stage and migrate with one click, plus auto-updates, hardening and performance.
- Our own wp-cli wrapper (runs as the site user).
- **Discovery:** detect WordPress installs under each site.
- **Lifecycle:** install, clone to a new domain, create a staging copy (files plus DB with URL
  search-replace), and push staging to production with a pre-push backup through Backup V2.
- **Updates:**
  - core, plugin and theme updates on demand or scheduled (minor/all);
  - a safe-update mode that snapshots, updates, runs an HTTP health check and rolls back on failure.
- **Hardening:** file editing off, XML-RPC block, wp-config permissions, salts rotation,
  admin user audit, and a vulnerable-plugin check against the public WPScan/WordFence feeds where available.
- **Performance:** LSCache plugin setup, object cache (Redis) toggle, cron to system cron.

### 7. .htaccess for OpenLiteSpeed
Full Apache `.htaccess` compatibility: PHP directives, security headers, URL rewrites, brute-force protection.

Stock OLS only reads rewrite rules from `.htaccess`. Upstream's answer is a prebuilt C module
that this fork disables on non-native distros. Ours is a **translator**:
- **Watcher:** an inotify service (cron fallback) parses each site's `.htaccess` files.
- **Generator:** writes the equivalent OLS configuration into a managed include per vhost,
  then gracefully reloads OLS (debounced):

  | directive | OLS equivalent |
  |---|---|
  | `php_value` / `php_flag` / `php_admin_*` | `phpIniOverride` |
  | `Header` / `RequestHeader` | context `extraHeaders` |
  | `Order` / `Allow` / `Deny`, `Require ip` | context `accessControl` |
  | `Redirect` / `RedirectMatch` | rewrite rules |
  | `ErrorDocument` | `errorPage` |
  | `<Files>` / `<FilesMatch>` | contexts |
  | `Expires*` | `expires` |
  | `DirectoryIndex`, `Options -Indexes` | — |

  Rewrites stay native.
- **Brute-force protection:**
  - OLS per-client throttling;
  - a log-driven guard for `wp-login.php` / `xmlrpc.php` that feeds the firewall (firewalld,
    nftables or CSF, whichever the host uses).
- **Reporting:** a per-site page of what was translated, plus a list of unsupported directives
  with line numbers, so nothing is silently ignored.

Highest effort and risk; built last, behind a per-site opt-in.

## Delivery

Each module ships the same way:

1. `service.py` with unit tests.
2. Views and templates.
3. Hub entry.
4. Installer and upgrader hook, if it needs packages.
5. A test install on a disposable VM, **then** this server.
6. An entry in UNIVERSAL.md.

Modules can be released one at a time on `main`.
