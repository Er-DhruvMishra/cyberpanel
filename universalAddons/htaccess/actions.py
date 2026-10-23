"""Root-side .htaccess module actions (dispatched by universalAddons/runner.py)."""
import os
import time

from universalAddons.htaccess import service as hs
from universalAddons.htaccess.service import HtaccessError

CRON_FILE = '/etc/cron.d/cyberpanel-universal-htaccess'


def _sites():
    """{domain: (docroot, home)} for every website and child domain."""
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import ChildDomains, Websites
    sites = {}
    for site in Websites.objects.all():
        sites[site.domain.lower()] = ('/home/%s/public_html' % site.domain, '/home/%s' % site.domain)
    for child in ChildDomains.objects.select_related('master'):
        sites[child.domain.lower()] = (child.path.rstrip('/'), '/home/%s' % child.master.domain)
    return sites


def _site(domain):
    sites = _sites()
    if domain not in sites:
        raise HtaccessError('Unknown site.')
    return sites[domain]


def _public(plan):
    return {k: v for k, v in plan.items() if k not in ('vhost_before', 'htaccess_before')}


def overview():
    state = hs.load_state()
    sites = _sites()
    now = time.time()
    return {
        'sites': [{'domain': d, 'enabled': d in state['sites'], 'applied': state['sites'].get(d, {}).get('applied'),
                   'bruteforce': bool((state['sites'].get(d, {}).get('bruteforce') or {}).get('enabled'))}
                  for d in sorted(sites)],
        'blocks': [b for b in state['blocks'] if b.get('until', 0) > now or now - b.get('at', 0) < 86400][-100:],
        'cron': os.path.exists(CRON_FILE),
    }


def preview(domain):
    docroot, home = _site(domain)
    return _public(hs.plan(domain, docroot, home))


def _apply(domains, state):
    sites = _sites()
    plans = [hs.plan(d, sites[d][0], sites[d][1]) for d in domains if d in sites]
    result = hs.apply_plans(plans)
    for plan in plans:
        state['sites'][plan['domain']] = {'fingerprint': plan['fingerprint'], 'applied': int(time.time()),
                                          'bruteforce': plan['bruteforce']}
    hs.save_state(state)
    return result


def enable(domain):
    _site(domain)
    state = hs.load_state()
    result = _apply([domain], state)
    _ensure_cron()
    return result


def disable(domain):
    docroot, home = _site(domain)
    state = hs.load_state()
    plan = hs.plan(domain, docroot, home)
    # Translate nothing: removes our vhost section and the managed redirect block.
    with open(plan['vhost_path']) as handle:
        current = handle.read()
    empty = hs.tr.translate({}, home, docroot)
    plan['vhost_after'] = hs.tr.apply_to_vhost(current, empty)
    plan['htaccess_after'] = hs.tr.apply_redirects(plan['htaccess_before'], [])
    plan['changed'] = plan['vhost_after'] != current or plan['htaccess_after'] != plan['htaccess_before']
    result = hs.apply_plans([plan])
    state['sites'].pop(domain, None)
    hs.save_state(state)
    return result


def watch():
    """Cron (every minute): re-apply sites whose .htaccess translation changed; run the guard."""
    state = hs.load_state()
    sites = _sites()
    changed = []
    for domain, info in state['sites'].items():
        if domain not in sites:
            continue
        files = hs.collect(sites[domain][0])
        if hs.fingerprint(files) != info.get('fingerprint'):
            changed.append(domain)
    applied = {}
    if changed:
        try:
            applied = _apply(changed, state)
        except HtaccessError as exc:
            for domain in changed:
                state['sites'][domain]['error'] = str(exc)[:500]
            hs.save_state(state)
    events = hs.guard({d: i.get('bruteforce') for d, i in state['sites'].items()}, state)
    hs.save_state(state)
    return {'reapplied': applied.get('applied', []), 'blocked': len(events)}


def _ensure_cron():
    if not os.path.exists(CRON_FILE):
        with open(CRON_FILE, 'w') as handle:
            handle.write('# CyberPanel Universal: re-apply changed .htaccess translations, brute-force guard\n'
                         '* * * * * root /usr/local/CyberCP/bin/python /usr/local/CyberCP/universalAddons/runner.py '
                         'htaccess watch e30= >/dev/null 2>&1\n')
        os.chmod(CRON_FILE, 0o644)


ACTIONS = {
    'overview': overview,
    'preview': preview,
    'enable': enable,
    'disable': disable,
    'watch': watch,
}
