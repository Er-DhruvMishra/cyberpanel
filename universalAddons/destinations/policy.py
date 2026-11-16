"""Who may use whose backup destination for which site.

Accounts form the panel's owner chain: ``Websites.admin`` is the site owner; a user's
``Administrator.owner`` is the pk of the account that created it (its reseller, or an
administrator). Rules, enforced server-side for every backup, restore and snapshot listing:

* Administrator: any site; destinations of the administrator itself, of the site owner, or of
  the site owner's reseller (the site owner's ``owner``).
* Reseller (ACL with resellerCenter): sites it owns or that belong to its users; its own
  destinations or the site owner's.
* User: only its own sites, and only its own destinations.

Only the owner of a destination can see its settings, change, test, rename or delete it; other
accounts that may use it see its name, provider and owner, never its settings or credentials.
"""
import json

from universalAddons.destinations import providers


class Actor:
    def __init__(self, admin_obj, acl):
        self.obj = admin_obj
        self.pk = admin_obj.pk
        self.is_admin = acl.get('admin') == 1
        self.is_reseller = not self.is_admin and acl.get('resellerCenter') == 1

    @property
    def role(self):
        return 'admin' if self.is_admin else ('reseller' if self.is_reseller else 'user')


def load_actor(user_id):
    from loginSystem.models import Administrator
    from plogical.acl import ACLManager
    if type(user_id) is not int:
        raise PermissionError('Not logged in.')
    try:
        return Actor(Administrator.objects.get(pk=user_id), ACLManager.loadedACL(user_id))
    except Exception:
        raise PermissionError('Could not load your account.') from None


def website(domain):
    from websiteFunctions.models import Websites
    domain = str(domain or '').strip().lower()
    try:
        return Websites.objects.select_related('admin').get(domain=domain)
    except Exception:
        raise PermissionError('Unknown site.') from None


def may_manage_site(actor, site):
    if actor.is_admin:
        return True
    if site.admin_id == actor.pk:
        return True
    return actor.is_reseller and site.admin.owner == actor.pk


def require_site(actor, site):
    if not may_manage_site(actor, site):
        raise PermissionError('You do not manage %s.' % site.domain)
    return site


def sites_for(actor):
    """Websites the actor may back up (queryset)."""
    from websiteFunctions.models import Websites
    query = Websites.objects.select_related('admin').order_by('domain')
    if actor.is_admin:
        return query
    if actor.is_reseller:
        from django.db.models import Q
        return query.filter(Q(admin_id=actor.pk) | Q(admin__owner=actor.pk))
    return query.filter(admin_id=actor.pk)


def allowed_owner_ids(actor, site):
    """Owners whose destinations the actor may use for this site (empty: none)."""
    if not may_manage_site(actor, site):
        return []
    owner = site.admin
    if actor.is_admin:
        ids = [actor.pk, owner.pk]
        if owner.owner and owner.owner != owner.pk:
            ids.append(owner.owner)
    elif actor.is_reseller:
        ids = [actor.pk, owner.pk]
    else:
        ids = [actor.pk]
    return list(dict.fromkeys(ids))


def allowed_destinations(actor, site):
    from universalAddons.models import BackupDestination
    ids = allowed_owner_ids(actor, site)
    return list(BackupDestination.objects.filter(owner_id__in=ids, connected=True)
                .order_by('owner_id', 'name'))


def require_use(actor, destination, site):
    """Raise PermissionError unless actor may back up `site` to / restore it from `destination`."""
    require_site(actor, site)
    if destination.owner_id not in allowed_owner_ids(actor, site):
        raise PermissionError('You cannot use this destination for %s.' % site.domain)
    if not destination.connected:
        raise PermissionError('This destination is not connected. Its owner must reconnect it.')
    return destination


def require_owner(actor, destination):
    if destination.owner_id != actor.pk:
        raise PermissionError('Only the owner of this destination can change it.')
    return destination


def get_destination(dest_id):
    from universalAddons.models import BackupDestination
    try:
        return BackupDestination.objects.get(pk=int(dest_id))
    except Exception:
        raise PermissionError('Unknown destination.') from None


def owner_name(destination):
    owner = destination.owner
    return owner.userName if owner else '(deleted account)'


def label(actor, destination, site):
    if destination.owner_id == actor.pk:
        return 'Mine'
    if destination.owner_id == site.admin_id:
        return 'Site owner: %s' % owner_name(destination)
    return 'Reseller: %s' % owner_name(destination)


def public_config(destination):
    try:
        data = json.loads(destination.public_config or '{}')
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def for_owner(destination):
    """Everything the owner may see: settings without any credential."""
    spec = providers.PROVIDERS.get(destination.provider, {})
    return {'id': destination.pk, 'name': destination.name, 'provider': destination.provider,
            'provider_title': spec.get('title', destination.provider), 'kind': spec.get('kind', ''),
            'settings': public_config(destination), 'connected': destination.connected,
            'last_test': destination.last_test.isoformat() if destination.last_test else '',
            'last_test_ok': destination.last_test_ok, 'last_test_message': destination.last_test_message,
            'owner': owner_name(destination)}


def for_others(actor, destination, site):
    """What another account that may use the destination sees: name, provider and owner only."""
    spec = providers.PROVIDERS.get(destination.provider, {})
    return {'id': destination.pk, 'name': destination.name, 'provider': destination.provider,
            'provider_title': spec.get('title', destination.provider), 'owner': owner_name(destination),
            'label': label(actor, destination, site)}
