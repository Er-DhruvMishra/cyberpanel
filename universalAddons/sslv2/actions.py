"""Root-side SSL V2 actions (dispatched by universalAddons/runner.py)."""
import os
import subprocess

from universalAddons import jobs
from universalAddons.emaildebug.service import DigResolver
from universalAddons.sslv2 import service
from universalAddons.sslv2.service import SSLError

CRON_FILE = '/etc/cron.d/cyberpanel-universal-ssl'


def _server_ips():
    try:
        with open('/etc/cyberpanel/machineIP') as handle:
            return [handle.read().split('\n', 1)[0].strip()]
    except OSError:
        return []


def _panel_domains():
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import ChildDomains, Websites
    names = list(Websites.objects.values_list('domain', flat=True)) + \
        list(ChildDomains.objects.values_list('domain', flat=True))
    return [n.lower() for n in names if service.valid_domain(n.lower())]


def inventory(domains=None):
    """Every panel domain, or (for a site owner) only the given ones."""
    names = _panel_domains()
    if domains is not None:
        wanted = {str(d).lower() for d in domains}
        names = [n for n in names if n in wanted]
    return {'certificates': service.inventory(names),
            'saved_cloudflare_token': _saved_cf_token()}


def _saved_cf_token():
    try:
        with open(os.path.join(service.ACME_HOME, 'account.conf')) as handle:
            return any(line.startswith('SAVED_CF_Token=') for line in handle)
    except OSError:
        return False


def check(domain, provider):
    domain = (domain or '').strip().lower()
    if not service.valid_domain(domain) or provider not in service.PROVIDERS:
        raise SSLError('Invalid domain or provider.')
    return service.nameserver_check(DigResolver(), domain, provider, _server_ips())


def issue(**request):
    clean = service.validate_request(**request)
    if clean['provider'] == 'cloudflare' and not clean['cf_token'] and not _saved_cf_token():
        raise SSLError('Enter a Cloudflare API token (Zone:DNS:Edit).')
    return jobs.spawn('sslv2', 'issue_run', clean)


def issue_run(job_id, domain, names, provider, ca, key, email, cf_token):
    request = {'domain': domain, 'names': names, 'provider': provider, 'ca': ca, 'key': key, 'email': email,
               'cf_token': cf_token}

    def do_issue(job):
        return service.issue(request, log=job.log)

    def do_install(job):
        code = subprocess.call([service.RELOAD_COMMAND.split()[0], service.RELOAD_COMMAND.split()[1], domain])
        if code != 0:
            raise SSLError('Installing the certificate into the web server failed (exit %d).' % code)
        return service.inventory([domain])[0]

    return jobs.run_job(job_id, [('Issue %s' % ', '.join(names), do_issue), ('Install and reload', do_install)])


def monitor():
    """Daily: e-mail administrators about expired, expiring or untrusted certificates."""
    rows, untrusted = service.alert_rows(service.inventory(_panel_domains()))
    if not rows:
        return {'alerts': 0, 'untrusted': untrusted}
    hostname = subprocess.run(['hostname', '-f'], stdout=subprocess.PIPE, universal_newlines=True).stdout.strip()
    text = service.alert_body(rows, hostname, untrusted)
    sent = {'recipients': 0}

    def legacy(recipients):
        # Administrators without notification settings: the same e-mail as before.
        body = 'To: %s\nSubject: [IndiansCloud] %d certificate(s) need attention on %s\n\n%s\n' % (
            ', '.join(recipients), len(rows), hostname, text)
        subprocess.run(['sendmail', '--'] + recipients, input=body, universal_newlines=True, timeout=60)
        sent['recipients'] = len(recipients)

    from universalAddons import notify
    notify.notify_admins('ssl_expiry', '%d certificate(s) need attention on %s' % (len(rows), hostname), text,
                         'warning', key='ssl:server', state=','.join(sorted(r['domain'] for r in rows)),
                         fallback=legacy)
    _notify_site_owners(rows)
    return {'alerts': len(rows), 'recipients': sent['recipients']}


def _notify_site_owners(rows):
    """Site owners who saved notification settings (and subscribe to SSL expiry) hear about their own
    domains. Nobody else gets anything new."""
    try:
        from universalAddons.notify import service as notify_service
        from websiteFunctions.models import ChildDomains, Websites
        owners = dict(Websites.objects.values_list('domain', 'admin_id'))
        owners.update({d: m for d, m in ChildDomains.objects.values_list('domain', 'master__admin_id')})
        admins = {pk for pk, _ in notify_service.admin_accounts()}
        by_owner = {}
        for row in rows:
            owner = owners.get(row['domain'])
            if owner and owner not in admins and notify_service.has_settings(owner):
                by_owner.setdefault(owner, []).append(row)
        for owner, own_rows in by_owner.items():
            notify_service.send(owner, 'ssl_expiry', '%d certificate(s) of your sites need attention' % len(own_rows),
                                service.alert_body(own_rows, 'your sites'), 'warning', key='ssl:sites',
                                state=','.join(sorted(r['domain'] for r in own_rows)), window=86400)
    except Exception:
        pass


def monitor_cron(enable=True):
    if enable:
        with open(CRON_FILE, 'w') as handle:
            handle.write('# CyberPanel Universal: daily certificate expiry check\n'
                         '17 6 * * * root /usr/local/CyberCP/bin/python /usr/local/CyberCP/universalAddons/runner.py '
                         'sslv2 monitor e30= >/dev/null 2>&1\n')
        os.chmod(CRON_FILE, 0o644)
    elif os.path.exists(CRON_FILE):
        os.unlink(CRON_FILE)
    return {'enabled': os.path.exists(CRON_FILE)}


ACTIONS = {
    'inventory': inventory,
    'check': check,
    'issue': issue,
    'issue_run': issue_run,
    'job': lambda job_id: jobs.status(job_id),
    'monitor': monitor,
    'monitor_cron': lambda enable=True: monitor_cron(bool(enable)),
    'monitor_status': lambda: {'enabled': os.path.exists(CRON_FILE)},
}
