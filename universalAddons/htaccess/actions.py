"""Root-side .htaccess module actions (dispatched by universalAddons/runner.py)."""
import os
import time

from universalAddons.htaccess import service as hs
from universalAddons.htaccess.service import HtaccessError

CRON_FILE = '/etc/cron.d/cyberpanel-universal-htaccess'
USER_REAPPLY_INTERVAL = 600  # seconds between automatic re-applies of a site its owner enabled


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


def overview(domains=None):
    """Every site, or (for a site owner) only the given domains and their own blocks."""
    state = hs.load_state()
    sites = _sites()
    now = time.time()
    names = sorted(sites)
    if domains is not None:
        wanted = {str(d).lower() for d in domains}
        names = [d for d in names if d in wanted]
    shown = set(names)
    return {
        'sites': [{'domain': d, 'enabled': d in state['sites'], 'applied': state['sites'].get(d, {}).get('applied'),
                   'bruteforce': bool((state['sites'].get(d, {}).get('bruteforce') or {}).get('enabled')),
                   'by_user': bool(state['sites'].get(d, {}).get('by_user'))}
                  for d in names],
        'blocks': [b for b in state['blocks'] if (b.get('until', 0) > now or now - b.get('at', 0) < 86400)
                   and (domains is None or b.get('domain') in shown)][-100:],
        'cron': os.path.exists(CRON_FILE),
    }


def preview(domain):
    docroot, home = _site(domain)
    return _public(hs.plan(domain, docroot, home))


def _apply(domains, state, by_user=None):
    """by_user: True/False sets who enabled the sites; None keeps what the state says."""
    sites = _sites()
    plans = [hs.plan(d, sites[d][0], sites[d][1]) for d in domains if d in sites]
    result = hs.apply_plans(plans)
    for plan in plans:
        owner_enabled = state['sites'].get(plan['domain'], {}).get('by_user', False) if by_user is None else by_user
        state['sites'][plan['domain']] = {'fingerprint': plan['fingerprint'], 'applied': int(time.time()),
                                          'bruteforce': plan['bruteforce'], 'by_user': bool(owner_enabled)}
    hs.save_state(state)
    return result


def _throttle(state, domain, min_interval):
    """Site owners: one apply per site every min_interval seconds (each apply restarts OpenLiteSpeed)."""
    if not min_interval:
        return
    last = state.setdefault('changed', {}).get(domain, 0)
    wait = int(last + min_interval - time.time())
    if wait > 0:
        raise HtaccessError('This site was changed a moment ago; try again in %d seconds.' % wait)


def _mark_changed(state, domain):
    now = time.time()
    changed = {d: t for d, t in state.get('changed', {}).items() if isinstance(t, (int, float)) and t > now - 86400}
    changed[domain] = int(now)
    state['changed'] = changed


def enable(domain, by_user=False, min_interval=0):
    _site(domain)
    state = hs.load_state()
    _throttle(state, domain, min_interval)
    _mark_changed(state, domain)
    hs.save_state(state)
    # An administrator enabling a site takes it over (and turns on firewall blocking for it).
    result = _apply([domain], state, by_user=bool(by_user))
    _ensure_cron()
    return result


def _guard_configs(state):
    """Brute-force settings per site; sites an owner enabled only log (their .htaccess and access
    log are under the owner's control, so they must not be able to block arbitrary IPs)."""
    configs = {}
    for domain, info in state['sites'].items():
        config = info.get('bruteforce')
        if config and info.get('by_user'):
            config = dict(config, action='log')
        configs[domain] = config
    return configs


def disable(domain, min_interval=0):
    docroot, home = _site(domain)
    state = hs.load_state()
    _throttle(state, domain, min_interval)
    _mark_changed(state, domain)
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
    now = time.time()
    for domain, info in state['sites'].items():
        if domain not in sites:
            continue
        if info.get('by_user') and now - (info.get('applied') or 0) < USER_REAPPLY_INTERVAL:
            continue  # owner-enabled sites restart OpenLiteSpeed at most every few minutes
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
    events = hs.guard(_guard_configs(state), state)
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
