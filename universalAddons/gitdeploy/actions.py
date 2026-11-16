"""Root-side Git deploy actions (dispatched by universalAddons/runner.py).

The web layer has checked that the caller manages `domain`. The webhook action takes no domain:
it finds the site by its random hook id and trusts nothing before the signature checks out.
"""
import base64
import binascii
import os
import shutil
import time

from universalAddons import jobs, siteinfo
from universalAddons.gitdeploy import service as svc
from universalAddons.gitdeploy.service import DeployError
from universalAddons.laravel import service as lv


def _site(domain):
    return siteinfo.resolve(domain)


def _app_ids(domain):
    try:
        from universalAddons.apps import service as apps
        return sorted(a['id'] for a in apps.load_apps().values() if a.get('domain') == domain)
    except Exception:
        return []


def _find_npm():
    try:
        from universalAddons.apps import runtimes as rt
        root = os.path.join(rt.RUNTIME_ROOT, 'node')
        for version in sorted(os.listdir(root), reverse=True):
            candidate = os.path.join(root, version, 'bin', 'npm')
            if os.path.exists(candidate):
                return candidate
    except Exception:
        pass
    return shutil.which('npm', path=siteinfo.USER_PATH) or ''


def _restart_app(app_id, domain):
    from universalAddons.apps import actions as apps_actions
    apps_actions.control(app_id, domain, 'restart')


def _deployer(site, config, log=None):
    return svc.Deployer(site, config, svc.load_token(config), log=log, find_composer=lv.find_composer,
                        find_npm=_find_npm, restart_app=_restart_app)


# ----------------------------------------------------------------------------- settings

def status(domain):
    site = _site(domain)
    configs = svc.load_configs()
    config = configs.get(site.domain)
    result = {'domain': site.domain, 'connected': bool(config), 'apps': _app_ids(site.domain),
              'default_target': os.path.relpath(site.docroot, site.home), 'composer': bool(lv.find_composer()),
              'steps': [{'key': k, 'title': svc.STEP_TITLES[k]} for k in svc.STEPS]}
    if not config:
        return result
    deployer = _deployer(site, config)
    result.update({
        'config': svc.public_config(config), 'hook_path': '/addons/git-deploy/hook/%s/' % config['id'],
        'has_token': bool(svc.load_token(config)), 'public_key': svc.public_key(site, config),
        'history': svc.load_history(config), 'deploying': svc.SiteLock(config).held_elsewhere(),
    })
    if config['mode'] == 'releases':
        result['releases'] = deployer.releases()[::-1]
        result['current'] = deployer.current_release()
    return result


def save(domain, spec, token=None):
    site = _site(domain)
    configs = svc.load_configs()
    config = svc.validate_config(spec, site, configs.get(site.domain), _app_ids(site.domain))
    if config['auth'] == 'token':
        if token:
            svc.save_token(config, token)
        elif not svc.load_token(config):
            raise DeployError('Enter the access token for this private repository.')
    else:
        try:
            os.unlink(svc.token_path(config))
        except OSError:
            pass
    configs[site.domain] = config
    svc.save_configs(configs)
    if config['auth'] == 'key':
        svc.generate_key(site, config)
    return status(domain)


def key(domain, replace=False):
    site = _site(domain)
    config = svc.config_for(site.domain)
    if config['auth'] != 'key':
        raise DeployError('This repository does not use a deploy key.')
    return {'public_key': svc.generate_key(site, config, replace=replace is True)}


def secret(domain, regenerate=False):
    """The webhook secret, for the site owner to paste into the Git host (optionally a new one)."""
    configs = svc.load_configs()
    config = svc.config_for(domain)
    if regenerate is True:
        config['secret'] = svc.secrets.token_hex(20)
        configs[config['domain']] = config
        svc.save_configs(configs)
    return {'secret': config['secret'], 'regenerated': regenerate is True}


def disconnect(domain):
    """Forget the repository, its token and webhook. Deployed files and the deploy key stay."""
    configs = svc.load_configs()
    config = configs.pop((domain or '').lower(), None)
    if not config:
        raise DeployError('No repository is connected.')
    try:
        os.unlink(svc.token_path(config))
    except OSError:
        pass
    svc.save_configs(configs)
    return {'disconnected': True}


def log(domain, n):
    return {'lines': svc.history_log(svc.config_for(domain), n)}


# ----------------------------------------------------------------------------- deploys (background jobs)

def deploy(domain, trigger='manual'):
    config = svc.config_for(domain)
    _site(domain)
    return jobs.spawn('gitdeploy', 'deploy_run', {'domain': config['domain'], 'trigger': trigger})


def rollback(domain):
    config = svc.config_for(domain)
    if config['mode'] != 'releases':
        raise DeployError('Rollback needs the "releases" deploy mode.')
    return jobs.spawn('gitdeploy', 'deploy_run', {'domain': config['domain'], 'trigger': 'rollback'})


def deploy_run(job_id, domain, trigger='manual'):
    config = svc.config_for(domain)
    site = _site(domain)
    lock = svc.SiteLock(config)
    pending = svc.pending_path(config)
    try:
        lock.acquire()
    except svc.Busy:
        if trigger != 'rollback':
            open(pending, 'w').close()
        job = jobs.Job(job_id)
        job.log('Another deploy of this site is running.' + (' This push deploys right after it.'
                                                            if trigger != 'rollback' else ''))
        job.done({'queued': trigger != 'rollback'})
        return job.data
    data = {}
    try:
        if os.path.exists(pending):
            os.unlink(pending)
        started = time.time()
        outcome = {}

        def body(job):
            deployer = _deployer(site, config, job.log)
            outcome.update(deployer.rollback() if trigger == 'rollback' else deployer.deploy())
            return dict(outcome)

        title = ('Roll %s back' if trigger == 'rollback' else 'Deploy %s') % domain
        data = jobs.run_job(job_id, [(title, body)])
        svc.add_history(config, {'ts': int(started), 'trigger': trigger, 'job_id': job_id,
                                 'state': 'ok' if data.get('state') == 'done' else 'failed',
                                 'commit': outcome.get('commit', ''), 'release': outcome.get('release', ''),
                                 'seconds': int(time.time() - started), 'error': str(data.get('error', ''))[:300]},
                        data.get('log', []))
    finally:
        lock.release()
    if os.path.exists(pending):  # a push arrived while this deploy ran
        os.unlink(pending)
        jobs.spawn('gitdeploy', 'deploy_run', {'domain': config['domain'], 'trigger': 'queued push'})
    return data


# ----------------------------------------------------------------------------- webhook

def hook(hook_id, headers, body):
    """Verify and act on one webhook delivery. Failures say nothing: {'http': 404}."""
    try:
        raw = base64.b64decode(str(body or '').encode('ascii'), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return {'http': 404}
    if len(raw) > svc.MAX_BODY or not isinstance(headers, dict):
        return {'http': 404}
    config = svc.config_by_hook(str(hook_id or ''))
    code, outcome = svc.check_delivery(config, headers, raw)
    if outcome is None:
        return {'http': 404}
    if outcome['status'] != 'deploy':
        return dict(outcome, http=code)
    if not svc.rate_allowed(config):
        return {'http': 429, 'status': 'rate limited'}
    jobs.spawn('gitdeploy', 'deploy_run', {'domain': config['domain'], 'trigger': 'webhook:' + outcome['provider']})
    return {'http': 202, 'status': 'deploying'}


ACTIONS = {
    'status': status,
    'save': save,
    'key': key,
    'secret': secret,
    'disconnect': disconnect,
    'log': log,
    'deploy': lambda domain: deploy(domain, 'manual'),
    'rollback': rollback,
    'deploy_run': deploy_run,
    'hook': hook,
    'job': lambda job_id: jobs.status(job_id),
}
