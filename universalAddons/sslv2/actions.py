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


def inventory():
    return {'certificates': service.inventory(_panel_domains()),
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
    from loginSystem.models import Administrator
    recipients = [a.email for a in Administrator.objects.filter(acl__adminStatus=1) if a.email] or ['root']
    hostname = subprocess.run(['hostname', '-f'], stdout=subprocess.PIPE, universal_newlines=True).stdout.strip()
    body = 'To: %s\nSubject: [CyberPanel] %d certificate(s) need attention on %s\n\n%s\n' % (
        ', '.join(recipients), len(rows), hostname, service.alert_body(rows, hostname, untrusted))
    subprocess.run(['sendmail', '--'] + recipients, input=body, universal_newlines=True, timeout=60)
    return {'alerts': len(rows), 'recipients': len(recipients)}


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
