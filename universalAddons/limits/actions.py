"""Root-side Resource Limits actions (dispatched by universalAddons/runner.py).

Root is needed to read vhost.conf (root-only), /proc of other users (hidepid=2) and repquota, and to
write vhost.conf and restart OpenLiteSpeed. The web layer is admin-only; every action re-validates.
"""
import fcntl
import os
import time

from universalAddons import jobs
from universalAddons.limits import service as sv
from universalAddons.limits.service import LimitsError


def _sites():
    """[{domain, user, package, state}] of every website (not child domains) from the panel database."""
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import Websites
    rows = Websites.objects.select_related('package').order_by('domain')
    return [{'domain': w.domain, 'user': w.externalApp or '', 'package': w.package.packageName, 'state': w.state}
            for w in rows]


def _packages():
    from universalAddons import django_env
    django_env.setup()
    from packages.models import Package
    return sorted(Package.objects.values_list('packageName', flat=True))


def _defaults():
    host = sv.host_resources()
    return host, sv.default_limits(host['total_mb'], host['cores'])


def _targets(scope, name, sites=None):
    sites = _sites() if sites is None else sites
    if scope == 'site':
        chosen = [s for s in sites if s['domain'] == name]
        if not chosen:
            raise LimitsError('Unknown site.')
    elif scope == 'package':
        chosen = [s for s in sites if s['package'] == name]
        if not chosen:
            raise LimitsError('No sites use this package.')
    else:
        raise LimitsError('Invalid scope.')
    active = [s for s in chosen if s['state'] == 1]
    if not active:
        raise LimitsError('Every selected site is suspended; nothing to apply.')
    return active


# ----------------------------------------------------------------------------- read

def overview():
    sites, packages = _sites(), _packages()
    store = sv.load_store()
    host, defaults = _defaults()
    usage = sv.usage_by_user(sorted({s['user'] for s in sites if s['user']}))
    quota = sv.quota_report()
    du_cache = sv.load_du_cache()
    rows = []
    for site in sites:
        limits, source = sv.effective(site['package'], site['domain'], store, defaults)
        row = dict(site, effective=limits, source=source, override=store['overrides'].get(site['domain'], {}),
                   usage=usage.get(site['user']), quota=quota['users'].get(site['user']),
                   du=du_cache.get(site['domain']), current=None, drift=[], error='')
        try:
            with open(sv.vhost_path(site['domain'])) as handle:
                current = sv.parse_extprocessor(handle.read(), site['user'])
            row['current'] = current['limits']
            row['php'] = os.path.basename(os.path.dirname(os.path.dirname(current['path']))) if current['path'] else ''
            row['drift'] = sorted(k for k, v in limits.items() if current['limits'].get(k) != v)
        except FileNotFoundError:
            row['error'] = 'No vhost.conf' + (' (suspended)' if site['state'] != 1 else '')
        except (OSError, LimitsError) as exc:
            row['error'] = str(exc)
        rows.append(row)
    counts = {}
    for site in sites:
        counts[site['package']] = counts.get(site['package'], 0) + 1
    return {
        'host': host, 'defaults': defaults, 'fields': [{'key': k, 'ols': v[0], 'min': v[1], 'max': v[2], 'label': v[3]}
                                                        for k, v in sv.FIELDS.items()],
        'packages': [{'name': p, 'sites': counts.get(p, 0), 'profile': store['packages'].get(p, {})} for p in packages],
        'sites': rows, 'quota': {k: v for k, v in quota.items() if k != 'users'}, 'cgroup': sv.cgroup_facts(),
        'du_scanned': max([d.get('at', 0) for d in du_cache.values() if isinstance(d, dict)] or [0]),
    }


def site_usage(domains):
    """Read-only view for a site owner: effective limits and current usage of the given websites."""
    wanted = {str(d).lower() for d in domains or ()}
    sites = [s for s in _sites() if s['domain'].lower() in wanted]
    store = sv.load_store()
    host, defaults = _defaults()
    usage = sv.usage_by_user(sorted({s['user'] for s in sites if s['user']}))
    quota = sv.quota_report()
    du_cache = sv.load_du_cache()
    rows = []
    for site in sites:
        limits, _ = sv.effective(site['package'], site['domain'], store, defaults)
        rows.append({'domain': site['domain'], 'package': site['package'], 'state': site['state'],
                     'effective': limits, 'usage': usage.get(site['user']), 'quota': quota['users'].get(site['user']),
                     'du': du_cache.get(site['domain'])})
    return {'fields': [{'key': k, 'label': v[3]} for k, v in sv.FIELDS.items()], 'sites': rows}


# ----------------------------------------------------------------------------- write profile

def save(scope, name, limits):
    if scope == 'package' and name not in _packages():
        raise LimitsError('Unknown package.')
    if scope == 'site' and name not in {s['domain'] for s in _sites()}:
        raise LimitsError('Unknown site.')
    store = sv.load_store()
    clean = sv.set_profile(store, scope, name, limits)
    host, defaults = _defaults()
    # The merged result for every affected site must still be consistent (soft <= hard, conns <= workers).
    for site in _sites():
        if (scope == 'package' and site['package'] == name) or (scope == 'site' and site['domain'] == name):
            sv.check_consistency(sv.effective(site['package'], site['domain'], store, defaults)[0])
    sv.save_store(store)
    return {'scope': scope, 'name': name, 'limits': clean}


# ----------------------------------------------------------------------------- preview / apply

def _plans(scope, name):
    store = sv.load_store()
    host, defaults = _defaults()
    targets = _targets(scope, name)
    usage = sv.usage_by_user([s['user'] for s in targets if s['user']])
    plans = []
    for site in targets:
        limits, source = sv.effective(site['package'], site['domain'], store, defaults)
        plans.append(sv.plan_site(site, limits, usage=usage.get(site['user'])))
    return plans


def preview(scope, name):
    plans = _plans(scope, name)
    return {'scope': scope, 'name': name, 'token': sv.plan_token(plans), 'plans': [sv.public_plan(p) for p in plans],
            'changed': sum(1 for p in plans if p['changed'] and not p['error'])}


def apply(scope, name, token):
    if not isinstance(token, str) or len(token) != 32:
        raise LimitsError('Preview the change first.')
    plans = _plans(scope, name)
    if sv.plan_token(plans) != token:
        raise LimitsError('The configuration changed since the preview; preview again.')
    if not any(p['changed'] and not p['error'] for p in plans):
        raise LimitsError('Nothing to change.')
    return jobs.spawn('limits', 'apply_run', {'scope': scope, 'name': name, 'token': token})


def apply_run(job_id, scope, name, token):
    def body(job):
        os.makedirs(sv.STATE_DIR, mode=0o700, exist_ok=True)
        with open(sv.LOCK_FILE, 'w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise LimitsError('Another limits change is being applied; try again in a minute.')
            plans = _plans(scope, name)
            if sv.plan_token(plans) != token:
                raise LimitsError('The configuration changed since the preview; preview again.')
            for plan in plans:
                if plan['error']:
                    job.log('%s skipped: %s' % (plan['domain'], plan['error']))
            return sv.apply_plans(plans, log=job.log)

    return jobs.run_job(job_id, [('Apply limits to %s %s' % (scope, name), body)])


# ----------------------------------------------------------------------------- disk usage job

def du_scan():
    return jobs.spawn('limits', 'du_run', {})


def du_run(job_id):
    def body(job):
        cache = sv.load_du_cache()
        sites = _sites()
        for index, site in enumerate(sites, 1):
            home = os.path.join('/home', site['domain'])
            if not os.path.isdir(home) or os.path.islink(home):
                continue
            started = time.time()
            try:
                kb = sv.du_kb(home)
            except LimitsError as exc:
                job.log(str(exc))
                continue
            cache[site['domain']] = {'kb': kb, 'at': int(time.time())}
            sv.save_du_cache(cache)
            job.log('[%d/%d] %-40s %8d MB  (%.1fs)' % (index, len(sites), site['domain'], kb // 1024, time.time() - started))
        known = {s['domain'] for s in sites}
        for domain in [d for d in cache if d not in known]:
            cache.pop(domain)
        sv.save_du_cache(cache)
        return {'sites': len(cache)}

    return jobs.run_job(job_id, [('Measure disk usage of every site', body)])


ACTIONS = {
    'overview': overview,
    'site_usage': site_usage,
    'save': save,
    'preview': preview,
    'apply': apply,
    'apply_run': apply_run,
    'du_scan': du_scan,
    'du_run': du_run,
    'job': lambda job_id: jobs.status(job_id),
}
