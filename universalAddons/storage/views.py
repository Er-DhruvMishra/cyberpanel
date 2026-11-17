import re


from universalAddons import privileged
from universalAddons.access import admin_api, admin_page, error, ok
from universalAddons.storage.service import CATEGORY_IDS, day_choices

_ITEM = re.compile(r'^[A-Za-z0-9_./ $@+=,:-]{1,1024}$')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('storage', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def page(request):
    return admin_page(request, 'universalAddons/storage.html')


@admin_api
def scan(request, data):
    return _call('scan')


@admin_api
def clean(request, data):
    """Selection: {category: true} or {category: [item paths]}. Items are re-checked on the server."""
    selection = {}
    for key, value in data.items():
        if not key.startswith('sel_'):
            continue
        category = key[4:]
        if category not in CATEGORY_IDS:
            return error('Unknown category %s.' % category, status=400)
        if value is True:
            selection[category] = True
        elif isinstance(value, list) and all(isinstance(v, str) and _ITEM.match(v) for v in value):
            selection[category] = value
        else:
            return error('Invalid selection for %s.' % category, status=400)
    if not selection:
        return error('Choose at least one category.', status=400)
    options = {}
    for key, value in data.items():  # days_<category>: age filter of the trash categories
        if not key.startswith('days_'):
            continue
        category = key[5:]
        choices = day_choices(category)
        if not choices or isinstance(value, bool) or value not in choices:
            return error('Invalid age for %s.' % category, status=400)
        if category in selection:
            options[category] = {'days': int(value)}
    extra = {'options': options} if options else {}
    return _call('clean', selection=selection, dry_run=data.get('dryRun') is True, **extra)


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)
