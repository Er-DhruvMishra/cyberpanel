"""Notification centre pages and endpoints, for every account (unless the administrator turns the
add-on off for users). The store belongs to the panel user, so no root action is needed; each
account only ever reads and changes its own settings (the session's account id)."""
from universalAddons.access import error, ok, site_api, site_page
from universalAddons.notify import service

FEATURE = 'notify_for_users'


def _guard(func):
    try:
        return ok(result=func())
    except service.NotifyError as exc:
        return error(str(exc), status=400)
    except OSError as exc:
        return error('The notification settings could not be read or saved (%s).' % exc.strerror)


def page(request):
    return site_page(request, 'universalAddons/notify.html', FEATURE)


@site_api(FEATURE)
def overview(request, data, context):
    return _guard(lambda: service.public_view(int(context.user_id), context.is_admin))


@site_api(FEATURE)
def channel_save(request, data, context):
    return _guard(lambda: service.save_channel(int(context.user_id), data.get('channel'), context.is_admin))


@site_api(FEATURE)
def channel_delete(request, data, context):
    return _guard(lambda: service.delete_channel(int(context.user_id), str(data.get('id', ''))))


@site_api(FEATURE)
def channel_test(request, data, context):
    return _guard(lambda: service.test_channel(int(context.user_id), str(data.get('id', ''))))


@site_api(FEATURE)
def preferences(request, data, context):
    return _guard(lambda: service.save_preferences(int(context.user_id), data.get('events') or {},
                                                   data.get('thresholds'), context.is_admin))
