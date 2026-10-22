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
    Module('wordpress', 'WordPress Manager Pro', 'fa-wordpress',
           'Clone, stage, push to production, safe auto-updates and hardening.',
           None, 'building'),
    Module('htaccess', '.htaccess for OpenLiteSpeed', 'fa-file-code',
           'Apache .htaccess directives translated into OpenLiteSpeed configuration.',
           None, 'building'),
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
