import re

from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok

SETTING_KEYS = ('reject', 'add_header', 'greylist', 'greylisting', 'bayes_autolearn', 'dkim_signing',
                'arc_signing', 'allow_list', 'deny_list')


def _call(action, **args):
    try:
        return ok(result=privileged.call('rspamd', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def page(request):
    return httpProc(request, 'universalAddons/rspamd.html', {}, 'admin').render()


@admin_api
def detect(request, data):
    return _call('detect')


@admin_api
def plan(request, data):
    return _call('plan', enable=data.get('enable') is not False, replace_spamassassin=data.get('replaceSpamAssassin') is True)


@admin_api
def filtering(request, data):
    enable = data.get('enable')
    if enable not in (True, False):
        return error('Specify enable true or false.', status=400)
    return _call('filtering', enable=enable, replace_spamassassin=data.get('replaceSpamAssassin') is True)


@admin_api
def apply(request, data):
    settings = {key: data[key] for key in SETTING_KEYS if key in data}
    return _call('apply', settings=settings)


@admin_api
def install(request, data):
    return _call('install')


@admin_api
def migrate_dkim(request, data):
    return _call('migrate_dkim')


@admin_api
def stats(request, data):
    return _call('stats')


@admin_api
def log(request, data):
    try:
        lines = int(data.get('lines', 200))
    except (TypeError, ValueError):
        return error('Invalid line count.', status=400)
    return _call('log', lines=lines)


@admin_api
def learn(request, data):
    kind, folder = data.get('kind'), data.get('folder')
    mailbox = str(data.get('mailbox', '')).strip().lower()
    if kind not in ('spam', 'ham') or folder not in ('Junk', 'Spam', 'INBOX', 'Archive'):
        return error('Choose spam or ham and a folder.', status=400)
    if not re.match(r'^[a-z0-9._%+=-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$', mailbox):
        return error('Enter a mailbox address on this server.', status=400)
    user, domain = mailbox.split('@')
    return _call('learn', kind=kind, domain=domain, user=user, folder=folder)


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)
