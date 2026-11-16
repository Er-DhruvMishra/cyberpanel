"""The add-on modules, and whether each can run on this host."""
import os
import shutil

from collections import namedtuple

Module = namedtuple('Module', 'key title icon summary url_name state')

# state: 'ready' (usable), 'building' (in development, not yet usable)
MODULES = (
    Module('emaildebug', 'Email Debugger', 'fa-envelope-open-text',
           'SMTP log tracing, DNS and blocklist checks, port and TLS tests, spam scoring.',
           'ua-emaildebug', 'ready'),
    Module('rootfm', 'Root File Manager', 'fa-folder-tree',
           'Full server file management with protected paths, trash and an audit log.',
           'ua-rootfm', 'ready'),
    Module('rspamd', 'Rspamd Manager', 'fa-shield-virus',
           'Rspamd spam filtering: Bayes learning, DKIM signing, greylisting and statistics.',
           'ua-rspamd', 'ready'),
    Module('sslv2', 'SSL V2', 'fa-lock',
           'Wildcard and DNS-01 certificates, inventory, renewal monitoring.',
           'ua-sslv2', 'ready'),
    Module('backupv2', 'Backup V2', 'fa-box-archive',
           'Encrypted incremental backups to SFTP, S3 or Google Drive with one-click restore.',
           'ua-backupv2', 'ready'),
    Module('wordpress', 'WordPress Manager Pro', 'fa-blog',
           'Clone, stage, push to production, safe auto-updates and hardening.',
           'ua-wordpress', 'ready'),
    Module('apps', 'Node.js, Python, .NET, Java, Ruby, Go & more', 'fa-cubes',
           'Run Node.js, Python, ASP.NET Core, Java/Kotlin, Ruby on Rails, Go, Deno and Bun apps as sandboxed services behind OpenLiteSpeed.',
           'ua-apps', 'ready'),
    Module('mssql', 'SQL Server databases', 'fa-database',
           'Microsoft SQL Server Express with per-site databases and logins.',
           'ua-mssql', 'ready'),
    Module('storage', 'Storage Cleaner', 'fa-broom',
           'See where disk space went and reclaim it: caches, old logs, bloated MySQL tables, junk files.',
           'ua-storage', 'ready'),
    Module('emaillimits', 'Email Limits', 'fa-paper-plane',
           'Per-domain and per-mailbox outbound sending limits, enforced by the cpecs policy daemon.',
           'ua-emaillimits', 'ready'),
    Module('smtprelay', 'SMTP Relay', 'fa-route',
           'Send outgoing mail through your own SMTP smarthost: global or per-sender-domain relays, '
           'test message with transcript, queue and log status.',
           'ua-smtprelay', 'ready'),
    Module('sshsec', 'SSH Security', 'fa-user-shield',
           'SSH login analysis, sshd hardening audit and a firewalld IP blocklist.',
           'ua-sshsec', 'ready'),
    Module('mysqlmgr', 'MySQL Manager', 'fa-server',
           'Database status, running queries, a tuning advisor and an upgrade-readiness report for MariaDB/MySQL.',
           'ua-mysqlmgr', 'ready'),
    Module('roundcube', 'Roundcube webmail', 'fa-envelope',
           'Free Roundcube 1.6 LTS on a site of your choice, using this server\'s Dovecot and Postfix.',
           'ua-roundcube', 'ready'),
    Module('limits', 'Resource Limits', 'fa-gauge-high',
           'Per-site PHP memory, process and connection limits enforced by OpenLiteSpeed, with preview and automatic rollback.',
           'ua-limits', 'ready'),
    Module('apache', 'Apache Manager', 'fa-feather',
           'Serve chosen sites through Apache httpd and per-site PHP-FPM behind OpenLiteSpeed, for full .htaccess support.',
           'ua-apache', 'ready'),
    Module('webterm', 'Web Terminal', 'fa-terminal',
           'A browser shell as the website\'s own Linux user, carried over the site\'s HTTPS.',
           'ua-webterm', 'ready'),
    Module('appsvc', 'Applications', 'fa-layer-group',
           'Elasticsearch, Redis and Memcached: install, tune memory and security, service controls, connection info.',
           'ua-appsvc', 'ready'),
    Module('htaccess', '.htaccess for OpenLiteSpeed', 'fa-file-code',
           'Apache .htaccess directives translated into OpenLiteSpeed configuration.',
           'ua-htaccess', 'ready'),
    Module('freesub', 'Free subdomains', 'fa-globe',
           'Give new websites a free name under your own domain: local PowerDNS zone, Cloudflare or deSEC.',
           'ua-freesub', 'ready'),
    Module('cloudflare', 'Cloudflare', 'fa-cloud',
           'Your Cloudflare zones with your own API token: DNS, cache purge, SSL/TLS, security, speed, '
           'analytics and Origin CA certificates.',
           'ua-cloudflare', 'ready'),
    Module('laravel', 'Laravel Toolkit', 'fa-layer-group',
           'Detect and install Laravel, run whitelisted artisan and composer commands, scheduler, queue worker, '
           '.env editor and logs, all as the site user.',
           'ua-laravel', 'ready'),
    Module('gitdeploy', 'Git deploy', 'fa-code-branch',
           'Deploy a site from GitHub, GitLab, Bitbucket or Gitea: deploy keys, signed webhooks, build steps, '
           'releases with rollback.',
           'ua-gitdeploy', 'ready'),
    Module('sitetools', 'Site Tools', 'fa-screwdriver-wrench',
           'Staging copies of any site (files and databases) with push back, password-protected directories, '
           'a redirect editor, custom error pages and hotlink protection.',
           'ua-sitetools', 'ready'),
    Module('autoresponder', 'Autoresponders & Spam Rules', 'fa-reply-all',
           'Per-mailbox out-of-office replies, move-to-Junk, spam score threshold and sender allow/block lists, '
           'as a managed Sieve script that runs before Roundcube filters.',
           'ua-autoresponder', 'ready'),
    Module('appcatalog', 'App Catalogue', 'fa-store',
           'One page of installable apps per site: the panel installers plus verified Drupal, Nextcloud, phpBB, '
           'MediaWiki, Matomo, Grav and Ghost installs.',
           'ua-appcatalog', 'ready'),
    Module('notify', 'Notifications', 'fa-bell',
           'Alerts by e-mail, Telegram, Slack, Discord or signed webhook: uptime, failed backups, expiring '
           'certificates, disk quota, new sign-ins and server health.',
           'ua-notify', 'ready'),
    Module('uptime', 'Uptime Monitoring', 'fa-heart-pulse',
           'HTTP(S), keyword, response-time, TLS-expiry and TCP checks every 1, 5 or 15 minutes, with 30 days of '
           'history, uptime percentages and incidents.',
           'ua-uptime', 'ready'),
    Module('visitstats', 'Visitor Statistics', 'fa-chart-line',
           'GoAccess reports per site from its access log (nightly and on demand), served privately to the '
           'site owner, with optional IP anonymisation.',
           'ua-visitstats', 'ready'),
    Module('pgsql', 'PostgreSQL databases', 'fa-database',
           'PostgreSQL databases and roles per website: package quota, backups to the site home, restore, '
           'one-click Adminer.',
           'ua-pgsql', 'ready'),
    Module('dnstools', 'DNS tools', 'fa-key',
           'DNSSEC signing with DS records for the registrar, and editable DNS templates for new zones '
           '(per reseller too).',
           'ua-dnstools', 'ready'),
    Module('bans', 'Fail2ban bans', 'fa-ban',
           'Every fail2ban jail and its banned addresses: search, ban, unban, and a managed ignoreip whitelist.',
           'ua-bans', 'ready'),
)


def disabled_features(path='/etc/cyberpanel/disabled_features'):
    try:
        with open(path) as handle:
            return {line.strip() for line in handle if line.strip()}
    except OSError:
        return set()


def requirement_problems(key, which=shutil.which, exists=os.path.exists):
    """Return a list of reasons the module cannot run on this host (empty = fine)."""
    problems = []
    if key == 'backupv2' and not which('restic'):
        problems.append('restic is not installed (dnf/apt install restic).')
    if key == 'apache' and not exists('/usr/local/lsws/bin/openlitespeed'):
        problems.append('Apache runs behind OpenLiteSpeed, which is not installed.')
    if key == 'limits' and not exists('/usr/local/lsws/bin/openlitespeed'):
        problems.append('Limits are enforced by OpenLiteSpeed, which is not installed.')
    if key == 'roundcube':
        if not exists('/usr/local/lsws/bin/openlitespeed'):
            problems.append('Roundcube is served by OpenLiteSpeed, which is not installed.')
        if not which('mysql'):
            problems.append('The mysql client is not installed.')
        if not which('doveconf'):
            problems.append('Dovecot is not installed.')
    if key == 'mysqlmgr' and not which('mysql'):
        problems.append('The mysql client is not installed.')
    if key == 'emaillimits' and not exists('/etc/postfix/main.cf'):
        problems.append('Postfix is not configured on this server.')
    if key == 'smtprelay':
        if not exists('/etc/postfix/main.cf'):
            problems.append('Postfix is not configured on this server.')
        if not which('postmap'):
            problems.append('postmap (Postfix) is not installed.')
    if key == 'htaccess' and not exists('/usr/local/lsws/bin/openlitespeed'):
        problems.append('This server does not run OpenLiteSpeed.')
    if key == 'apps' and not exists('/usr/local/lsws/bin/openlitespeed'):
        problems.append('Apps are proxied by OpenLiteSpeed, which is not installed.')
    if key == 'sitetools':
        if not exists('/usr/local/lsws/bin/openlitespeed'):
            problems.append('Site Tools writes OpenLiteSpeed configuration, which is not installed.')
        if not which('rsync'):
            problems.append('rsync is not installed (dnf/apt install rsync).')
    if key == 'autoresponder':
        if not which('sievec') and not exists('/usr/bin/sievec'):
            problems.append('Pigeonhole (Dovecot Sieve) is not installed, so the managed scripts are saved but not '
                            'run. See the drop-in on the add-on page.')
    if key == 'pgsql' and not any(exists('/usr/pgsql-%d/bin/psql' % major) for major in (17, 16)):
        problems.append('PostgreSQL is not installed: install it from Applications.')
    if key == 'dnstools' and not exists('/usr/bin/pdnsutil'):
        problems.append('PowerDNS (pdnsutil) is not installed.')
    if key == 'bans' and not which('fail2ban-client') and not exists('/usr/bin/fail2ban-client'):
        problems.append('fail2ban is not installed.')
    if key == 'gitdeploy' and not which('git'):
        problems.append('git is not installed (dnf/apt install git).')
    if key == 'emaildebug':
        if not which('dig'):
            problems.append('dig is not installed (bind-utils / dnsutils).')
        if not exists('/etc/postfix/main.cf'):
            problems.append('Postfix is not configured on this server.')
    return problems


def module_status():
    status = []
    for module in MODULES:
        problems = requirement_problems(module.key) if module.state == 'ready' else []
        status.append({
            'key': module.key, 'title': module.title, 'icon': module.icon, 'summary': module.summary,
            'url_name': module.url_name, 'state': module.state, 'problems': problems,
        })
    return status
