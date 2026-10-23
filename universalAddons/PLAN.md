# Universal Add-ons: plan

**Status (2026-10-24):** all seven modules are built and tested (`python manage.py test universalAddons`, 182 tests). See each module below for what is verified on a live server and what still needs a first real run.

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

## Review of the official modules, and what ours adds

Feature-level review of upstream's gated implementations (2026-10-23). "Parity" lists what the
official module does, which ours matches. "Fixes" lists defects found in the official code,
which ours avoids by design. "Extra" lists features we add beyond it.

### Email Debugger: **built** (milestone 1)
- **Parity:**
  - mail-SSL self-signed check;
  - port connect test on 25/587/465/110/143/993/995;
  - per-site check that `mail.<domain>` resolves here and port 993 is not self-signed.
- **Fixes:**
  - port tests that came only from the server itself;
  - `openssl s_client` with no timeout;
  - only "self-signed" was detected; expired and wrong-hostname certificates passed;
  - a destructive "Reset" that took no backups and dropped the Rspamd milter.
- **Extra:**
  - MX / SPF (include, redirect, 10-lookup limit) / DKIM-vs-signing-key / DMARC / PTR+FCrDNS checks;
  - six blocklists (DNSBL);
  - STARTTLS certificate name, expiry and issuer;
  - a Postfix message tracer, plus deferral and bounce reasons;
  - SASL brute-force IP list;
  - queue summary;
  - spam score (Rspamd or SpamAssassin);
  - test send with live trace.
- **Next:**
  - external port check via a public TCP-probe service (opt-in);
  - DMARC aggregate-report (rua) parser;
  - per-mailbox send volume over time, to spot compromised accounts;
  - one-click DNS fixes through the panel's DNS when the zone is local.

### Root File Manager
- **Parity:** browse, create, delete, copy, move, rename, edit, upload, download, extract,
  compress, permissions.
- **Fixes:**
  - root deletes were permanent (no trash);
  - chmod and the code editor did not work in root mode;
  - a recursive `chattr` on `/` ran on failure;
  - `/etc/shadow` was readable and writable through the editor;
  - there was no audit log.
- **Extra:**
  - trash with restore and purge;
  - chown;
  - one protected-path policy for every write (unlock per action);
  - credential files never writable;
  - atomic saves with a lost-update check (sha256);
  - zip-slip, symlink and device-file safe extraction;
  - name search and directory size;
  - sha256 checksum;
  - a JSON audit log (`/var/log/cyberpanel_rootfm.log`).

### Rspamd Manager
- **Official reality:** it is effectively a ClamAV-through-Rspamd configurator plus milter fields.
- **Fixes:**
  - the enable toggle stopped the service but left the milter, so mail tempfailed;
  - uninstall left the milter in `main.cf`;
  - saves always reported success and never reloaded anything;
  - inputs were not validated;
  - milter detection was keyed to the `8891` line.
- **Extra:**
  - pre-flight conflict detection;
  - dry-run `main.cf` diff;
  - reversible install;
  - thresholds and actions;
  - allow and deny lists;
  - Bayes learning from Junk/Inbox folders;
  - greylisting;
  - DKIM signing with key migration from OpenDKIM, plus ARC;
  - statistics and history;
  - per-domain settings;
  - protected access to the Rspamd web UI.

### SSL V2
- **Parity:**
  - wildcard and apex issuance over DNS-01 (Cloudflare or local PowerDNS), with fallback to
    non-wildcard;
  - installation for OLS and LSWS;
  - readable ACME errors.
- **Fixes:**
  - the PowerDNS API was opened to `0.0.0.0/0` on a page GET (**present on this server**);
  - Cloudflare scoped tokens were not supported (Global API Key only);
  - renewal ran through the HTTP-01 v1 path, dropping wildcards, with no reload hook;
  - leftover `cptest` records;
  - lost error output.
- **Extra:**
  - local PowerDNS through the panel CLI (no API exposure);
  - Cloudflare API tokens;
  - choice of CA (Let's Encrypt or ZeroSSL) and key type;
  - certificate inventory with expiry alerts;
  - DNS-01 renewal with a reload command;
  - hostname and mail certificates;
  - SAN for alias domains.

### Backup V2
- **Parity:**
  - per-site SFTP, Google Drive and local repositories;
  - data, database and mail selection;
  - snapshot browse and restore;
  - delete snapshot or repository;
  - schedules with retention;
  - failure email.
- **Fixes:**
  - repositories were unencrypted (`--password ""`);
  - no lock, so backup runs could overlap;
  - hard-coded backup path;
  - retention only applied to weekly schedules;
  - unvalidated shell input (SFTP password, restore path, repository name);
  - `config.json` stored admin password hashes, the API token and the 2FA secret;
  - no `check`;
  - no safe restore.
- **Extra:**
  - restic with a per-repository key (root-only);
  - S3, B2 and any rclone back end;
  - a lock per job;
  - `restic check` after backup;
  - restore to an alternate location, of a single file, or of the database only, with dry-run;
  - a safety snapshot before restore;
  - append-only and object-lock options;
  - retention for every schedule.

### WordPress Manager Pro
- **Parity:**
  - create with options;
  - list and import;
  - plugins and themes (update, delete, activate);
  - settings (debug, indexing, maintenance, LSCache);
  - core reinstall and checksum verification;
  - auto-login;
  - staging and sync to production;
  - backup and restore (local, SFTP, S3);
  - schedules.
- **Fixes:**
  - the WP-Cron toggle was not implemented;
  - password protection ignored the user's credentials and overwrote `.htaccess`;
  - SFTP restore added the remote host to root's `authorized_keys`;
  - https was downgraded to http on sync and restore;
  - no backup before syncing;
  - `cp -R` never removed deleted files;
  - missing ownership checks;
  - plaintext credentials;
  - a permanent `autologin` admin account.
- **Extra:**
  - run everything as the site user;
  - mirror sync (rsync `--delete`) with a database search-replace that preserves the scheme;
  - automatic pre-sync snapshot;
  - safe update (snapshot, update, HTTP health check, roll back);
  - hardening checklist;
  - one-time auto-login tokens;
  - vulnerability feed check.

### .htaccess for OpenLiteSpeed
- **Official:**
  - a closed-source `cyberpanel_ols.so` (with a custom OLS build) covering
    Header, RequestHeader (as env vars), SetEnv, SetEnvIf, Order/Allow/Deny, Redirect,
    ErrorDocument, FilesMatch, Expires, php_value/php_flag and a wp-login brute-force quota;
  - no panel UI;
  - a 3-minute cron that runs a full restart, scanning `public_html` only.
- **Gaps:**
  - Basic auth (`AuthType`/`Require`);
  - `Require ip`;
  - `<Files>`;
  - `DirectoryIndex`;
  - `AddType`;
  - child-domain document roots;
  - brute-force state lost on reboot.
- **Ours:**
  - an open translator to native OLS configuration (works with stock OLS);
  - Basic auth through OLS realms;
  - `Require`;
  - all document roots;
  - reload on file change (debounced, graceful);
  - per-site translation report;
  - firewall-backed brute-force guard.

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

### 1. Email Debugger: *read-only diagnostics* (built)
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
