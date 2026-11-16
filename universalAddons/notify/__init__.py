"""Notification centre. Other add-ons call:

    from universalAddons import notify
    notify.send(account_id, 'uptime', 'example.com is down', 'details...', 'error', key=..., state='down')

See service.send for de-duplication and rate limiting.
"""


def send(account_id, event, title, body, severity='warning', **options):
    from universalAddons.notify import service
    return service.send(account_id, event, title, body, severity, **options)


def notify_admins(event, title, body, severity='warning', **options):
    from universalAddons.notify import service
    return service.notify_admins(event, title, body, severity, **options)
