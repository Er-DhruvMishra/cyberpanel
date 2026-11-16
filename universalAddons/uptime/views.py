"""Uptime monitoring pages and endpoints for every account (unless the administrator turns the add-on
off for users). Users see and change only their own monitors, at most `uptime_max_monitors` of them;
administrators see every monitor. The store belongs to the panel user, so no root action is needed."""
import time

from universalAddons import access
from universalAddons.access import error, ok, owned_sites, site_api, site_page
from universalAddons.siteinfo import DOMAIN_RE
from universalAddons.uptime import service

FEATURE = 'uptime_for_users'
CHECK_NOW_INTERVAL = 30


def _limit():
    value = access.load_policy().get('uptime_max_monitors', service.DEFAULT_LIMIT)
    return value if isinstance(value, int) and value >= 0 else service.DEFAULT_LIMIT


def _id(data):
    value = data.get('id')
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError('Invalid monitor.')
    return value


def _guard(func):
    try:
        with service.opened() as db:
            return ok(result=func(db))
    except service.UptimeError as exc:
        return error(str(exc), status=400)
    except PermissionError as exc:
        return error(str(exc), status=403)
    except OSError as exc:
        return error('The uptime database could not be opened (%s).' % (exc.strerror or exc))


def _owner_names(ids):
    try:
        from loginSystem.models import Administrator
        return dict(Administrator.objects.filter(pk__in=list(ids)).values_list('pk', 'userName'))
    except Exception:
        return {}


def _site_choices(context):
    sites = owned_sites(context)
    if sites is None:
        try:
            from websiteFunctions.models import Websites
            sites = sorted(Websites.objects.values_list('domain', flat=True))[:500]
        except Exception:
            sites = []
    return sites


def page(request):
    def values(is_admin):
        wanted = str(request.GET.get('site', '')).strip().lower()
        return {'site': wanted if DOMAIN_RE.match(wanted) else '', 'limit': _limit()}
    return site_page(request, 'universalAddons/uptime.html', FEATURE, values)


@site_api(FEATURE)
def overview(request, data, context):
    user_id = int(context.user_id)

    def run(db):
        monitors = service.list_monitors(db, None if context.is_admin else user_id)
        now = time.time()
        rows = [service.summary(db, m, now) for m in monitors]
        names = _owner_names({m['owner_id'] for m in monitors}) if context.is_admin else {}
        for row in rows:
            row['owner'] = names.get(row['owner_id'], '') if context.is_admin else ''
            row['mine'] = row['owner_id'] == user_id
        return {'monitors': rows, 'limit': None if context.is_admin else _limit(),
                'count': service.count(db, user_id), 'sites': _site_choices(context)}
    return _guard(run)


@site_api(FEATURE)
def save(request, data, context):
    user_id = int(context.user_id)
    monitor_id = data.get('id')

    def run(db):
        if monitor_id is not None:
            current = service.owned(db, _id(data), user_id, context.is_admin)
            # An administrator editing a user's monitor keeps it in the user's name; local targets
            # stay possible only for monitors that administrators own.
            is_admin_owned = context.is_admin and current['owner_id'] == user_id
            return service.save(db, current['owner_id'], data.get('monitor'), is_admin_owned, monitor_id=current['id'])
        return service.save(db, user_id, data.get('monitor'), context.is_admin, _limit())
    return _guard(run)


@site_api(FEATURE)
def delete(request, data, context):
    def run(db):
        monitor = service.owned(db, _id(data), int(context.user_id), context.is_admin)
        service.delete(db, monitor['id'])
        return {'deleted': monitor['id']}
    return _guard(run)


@site_api(FEATURE)
def detail(request, data, context):
    def run(db):
        monitor = service.owned(db, _id(data), int(context.user_id), context.is_admin)
        return dict(service.summary(db, monitor), incidents=service.incidents(db, monitor['id']),
                    recent=service.recent_results(db, monitor['id']))
    return _guard(run)


@site_api(FEATURE)
def check_now(request, data, context):
    def run(db):
        monitor = service.owned(db, _id(data), int(context.user_id), context.is_admin)
        now = time.time()
        if now - monitor['last_check'] < CHECK_NOW_INTERVAL:
            raise service.UptimeError('This monitor was checked less than %d seconds ago.' % CHECK_NOW_INTERVAL)
        result = service.run_check(monitor)
        service.apply_result(db, monitor, result, now)
        return dict(result, state=service.get(db, monitor['id'])['state'])
    return _guard(run)
