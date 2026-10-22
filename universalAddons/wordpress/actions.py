"""Root-side WordPress Manager Pro actions (dispatched by universalAddons/runner.py)."""
import os
import re
import secrets
import subprocess

from universalAddons import jobs
from universalAddons.wordpress import service as wp
from universalAddons.wordpress.service import WPError


def _django():
    from universalAddons import django_env
    django_env.setup()


def _docroots():
    """(domain, user, docroot, vhost_domain) for every site and child domain."""
    _django()
    from websiteFunctions.models import ChildDomains, Websites
    rows = []
    for site in Websites.objects.all():
        rows.append((site.domain.lower(), site.externalApp, '/home/%s/public_html' % site.domain, site.domain))
    for child in ChildDomains.objects.select_related('master'):
        rows.append((child.domain.lower(), child.master.externalApp, child.path.rstrip('/'), child.domain))
    return [r for r in rows if wp.DOMAIN_RE.match(r[0]) and wp.USER_RE.match(r[1] or '')]


def _site(domain):
    for name, user, docroot, vhost in _docroots():
        if name == (domain or '').lower():
            return wp.Site(name, user, docroot, wp.php_for_vhost(vhost))
    raise WPError('Unknown site %r.' % domain)


def _quick_version(docroot):
    try:
        with open(os.path.join(docroot, 'wp-includes', 'version.php')) as handle:
            match = re.search(r"\$wp_version\s*=\s*'([^']+)'", handle.read())
        return match.group(1) if match else ''
    except OSError:
        return ''


def list_sites():
    rows = _docroots()
    installs = wp.find_installs(rows)
    for item in installs:
        item['version'] = _quick_version(item['docroot'])
    wordpress = {i['domain'] for i in installs}
    empty = [r[0] for r in rows if r[0] not in wordpress and os.path.isdir(r[2])]
    return {'installs': sorted(installs, key=lambda i: i['domain']), 'other_sites': sorted(empty),
            'wp_cli': _wp_cli_version()}


def _wp_cli_version():
    try:
        out = subprocess.run(['/usr/bin/php', wp.WP_CLI, '--version', '--allow-root'], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, universal_newlines=True, timeout=30)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ''


def _create_database_for(domain):
    """Create an empty DB + user for a site and register it in the panel. Returns (name, user, password)."""
    _django()
    from databases.models import Databases
    from websiteFunctions.models import ChildDomains, Websites
    from universalAddons.backupv2.service import mysql_defaults_file
    try:
        website = Websites.objects.get(domain=domain)
    except Websites.DoesNotExist:
        website = ChildDomains.objects.get(domain=domain).master
    prefix = re.sub(r'[^a-z0-9]', '', website.externalApp.lower())[:8] or 'wp'
    name = '%s_stg%s' % (prefix, secrets.token_hex(3))
    password = secrets.token_urlsafe(24)
    sql = ("CREATE DATABASE `{0}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
           "CREATE USER '{0}'@'localhost' IDENTIFIED BY '{1}';\n"
           "GRANT ALL PRIVILEGES ON `{0}`.* TO '{0}'@'localhost';\nFLUSH PRIVILEGES;\n").format(name, password)
    defaults = mysql_defaults_file()
    try:
        out = subprocess.run(['mysql', '--defaults-extra-file=' + defaults], input=sql, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, universal_newlines=True, timeout=120)
    finally:
        os.unlink(defaults)
    if out.returncode != 0:
        raise WPError('Could not create the database: ' + out.stdout.strip()[-300:])
    Databases(website=website, dbName=name, dbUser=name).save()
    return name, name, password


def _job(action):
    """An action that starts `action` as a background job and returns its id."""
    def start(**args):
        return jobs.spawn('wordpress', action, args)
    return start


def update_run(job_id, domain, scope):
    site = _site(domain)
    return jobs.run_job(job_id, [('Safe update (%s) of %s' % (scope, domain),
                                  lambda job: wp.safe_update(site, scope, log=job.log))])


def snapshot_run(job_id, domain):
    site = _site(domain)
    return jobs.run_job(job_id, [('Snapshot %s' % domain, lambda job: {'snapshot': wp.snapshot(site, 'manual')})])


def rollback_run(job_id, domain, snap_id):
    site = _site(domain)
    return jobs.run_job(job_id, [('Roll %s back to %s' % (domain, snap_id), lambda job: wp.rollback(site, snap_id))])


def clone_run(job_id, source, target):
    src, dst = _site(source), _site(target)
    return jobs.run_job(job_id, [('Clone %s to %s' % (source, target),
                                  lambda job: wp.clone(src, dst, lambda: _create_database_for(target), log=job.log))])


def push_run(job_id, staging, production):
    stg, prod = _site(staging), _site(production)
    return jobs.run_job(job_id, [('Push %s to %s' % (staging, production),
                                  lambda job: wp.push(stg, prod, log=job.log))])


def install_run(job_id, domain, title, admin_user, admin_email, locale='en_US'):
    site = _site(domain)
    wp.validate_install(title, admin_user, admin_email, locale)
    return jobs.run_job(job_id, [('Install WordPress on %s' % domain, lambda job: wp.install_wordpress(
        site, title, admin_user, admin_email, lambda: _create_database_for(domain), locale, log=job.log))])


def wpcli_run(job_id):
    return jobs.run_job(job_id, [('Update WP-CLI', lambda job: wp.update_wp_cli())])


ACTIONS = {
    'list': list_sites,
    'info': lambda domain: wp.info(_site(domain)),
    'item': lambda domain, kind, action, slug: {'output': wp.manage_item(_site(domain), kind, action, slug)},
    'flag': lambda domain, flag, enable: {'output': wp.set_flag(_site(domain), flag, bool(enable))},
    'autoupdates': lambda domain, kind, enable: {'output': wp.set_auto_updates(_site(domain), kind, bool(enable))},
    'hardening': lambda domain: {'checks': wp.hardening_report(_site(domain))},
    'fix': lambda domain, fix: {'output': wp.apply_fix(_site(domain), fix)},
    'lscache': lambda domain: {'output': wp.enable_lscache(_site(domain))},
    'objectcache': lambda domain: {'output': wp.enable_object_cache(_site(domain))},
    'login': lambda domain: wp.one_time_login(_site(domain)),
    'snapshots': lambda domain: {'snapshots': wp.list_snapshots(_site(domain))},
    'update': _job('update_run'),
    'update_run': update_run,
    'snapshot': _job('snapshot_run'),
    'snapshot_run': snapshot_run,
    'rollback': _job('rollback_run'),
    'rollback_run': rollback_run,
    'clone': _job('clone_run'),
    'clone_run': clone_run,
    'push': _job('push_run'),
    'push_run': push_run,
    'install': _job('install_run'),
    'install_run': install_run,
    'wpcli_update': _job('wpcli_run'),
    'wpcli_run': wpcli_run,
    'job': lambda job_id: jobs.status(job_id),
}
