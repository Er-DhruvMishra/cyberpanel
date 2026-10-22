"""Root-side Rspamd Manager actions (dispatched by universalAddons/runner.py)."""
from universalAddons import jobs
from universalAddons.rspamd import service
from universalAddons.rspamd.service import RspamdError


def _os():
    from cyberpanel_os_profile import detect
    profile = detect()
    if profile is None:
        raise RspamdError('Unsupported operating system.')
    codename = ''
    try:
        with open('/etc/os-release') as handle:
            for line in handle:
                if line.startswith('VERSION_CODENAME='):
                    codename = line.split('=', 1)[1].strip().strip('"')
    except OSError:
        pass
    return profile.family, profile.version, codename


def install_run(job_id):
    family, version, codename = _os()
    if family == 'debian' and not codename:
        raise RspamdError('Could not determine the distribution codename.')

    def command(argv):
        def step(job):
            code, out = service.run(argv, timeout=1800)
            job.log(out[-4000:])
            if code != 0:
                raise RspamdError('%s exited with %d' % (' '.join(argv[:3]), code))
        return step

    steps = [('Run: %s' % ' '.join(argv[:4]), command(argv)) for argv in
             service.install_commands(family, version if family == 'rhel' else 0, codename)]
    steps.append(('Write managed configuration', lambda job: service.apply_settings(service.read_settings())))
    steps.append(('Detect', lambda job: service.detect()))
    return jobs.run_job(job_id, steps)


def learn_run(job_id, kind, domain, user, folder):
    return jobs.run_job(job_id, [('Learn %s from %s@%s/%s' % (kind, user, domain, folder),
                                  lambda job: service.learn(kind, domain, user, folder))])


ACTIONS = {
    'detect': lambda: service.detect(),
    'plan': lambda enable=True, replace_spamassassin=False:
        service.set_filtering(bool(enable), bool(replace_spamassassin), dry_run=True),
    'filtering': lambda enable, replace_spamassassin=False:
        service.set_filtering(bool(enable), bool(replace_spamassassin)),
    'apply': lambda settings: service.apply_settings(settings),
    'migrate_dkim': lambda: service.migrate_dkim_keys(),
    'stats': lambda: service.stats(),
    'log': lambda lines=200: service.tail_log(lines),
    'install': lambda: jobs.spawn('rspamd', 'install_run', {}),
    'install_run': install_run,
    'learn': lambda kind, domain, user, folder: jobs.spawn('rspamd', 'learn_run', {
        'kind': kind, 'domain': domain, 'user': user, 'folder': folder}),
    'learn_run': learn_run,
    'job': lambda job_id: jobs.status(job_id),
}
