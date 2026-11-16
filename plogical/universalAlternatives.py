"""Free Universal Add-ons that stand in for upstream pages.

IndiansCloud no longer checks a vendor licence: every upstream page whose code
runs locally is simply available. A page is sent to its free add-on only when

* the upstream page still depends on vendor-hosted services (VENDOR_DEPENDENT), or
* the administrator prefers the free add-on for that feature: one add-on key per
  line in /etc/cyberpanel/prefer_free_addons.

This decision does not depend on licensing (see `preferred_alternative`). ACL
and ownership checks in the upstream views are unaffected.
"""
import re

# (path pattern, add-on module key, add-on URL). First match wins.
ALTERNATIVES = (
    (r'^/websites/(ListWPSites|createWordpress|WPHome|RestoreBackups|RestoreHome|RemoteBackupConfig|'
     r'BackupfileConfig|AddRemoteBackupsite|AutoLogin|ConfigurePlugins|Addnewplugin|EidtPlugin)/?$',
     'wordpress', '/addons/wordpress/'),
    (r'^/websites/[^/]+/wordpressInstall/?$', 'wordpress', '/addons/wordpress/'),
    (r'^/emailPremium/EmailDebugger/?$', 'emaildebug', '/addons/email-debugger/'),
    (r'^/emailPremium/Rspamd/?$', 'rspamd', '/addons/rspamd/'),
    (r'^/filemanager/Filemanager/?$', 'rootfm', '/addons/root-file-manager/'),
    (r'^/dataBases/(MysqlManager|OptimizeMySQL|UpgradeMySQL)/?$', 'mysqlmgr', '/addons/mysql/'),
    (r'^/email/EmailLimits/?$', 'emaillimits', '/addons/email-limits/'),
    (r'^/webmail/roundcube/?$', 'roundcube', '/addons/roundcube/'),
    (r'^/websites/ApacheManager/(?P<domain>[A-Za-z0-9.-]+)/?$', 'apache', '/addons/apache/?site={domain}'),
)


def _available(key):
    try:
        from universalAddons.registry import MODULES, disabled_features
    except Exception:
        return False
    if key in disabled_features():
        return False
    return any(module.key == key and module.state == 'ready' for module in MODULES)


# Add-on keys whose upstream page still needs vendor-hosted services or closed
# vendor downloads. Every page listed in ALTERNATIVES was reviewed: all of them
# now run from code in this repository, so none is forced to its add-on.
# (Vendor-only services outside this table already redirect in their own views:
# emailDelivery -> SMTP Relay, one-click backups -> backup home.)
VENDOR_DEPENDENT = frozenset()

PREFERENCE_FILE = '/etc/cyberpanel/prefer_free_addons'


def preferred_keys(path=PREFERENCE_FILE):
    """Add-on keys the administrator wants shown instead of the upstream page."""
    try:
        with open(path) as handle:
            return {line.strip() for line in handle if line.strip() and not line.startswith('#')}
    except OSError:
        return set()


def _key_for(path):
    for pattern, key, url in ALTERNATIVES:
        match = re.match(pattern, path or '')
        if match:
            return key
    return None


def preferred_alternative(path, available=_available, preferred=None, vendor_dependent=None):
    """Add-on URL to show instead of the upstream page at `path`, or None.

    Licence-independent: fires for vendor-dependent pages and for features the
    administrator chose to replace; otherwise the upstream page is shown.
    """
    key = _key_for(path)
    if key is None:
        return None
    vendor_dependent = VENDOR_DEPENDENT if vendor_dependent is None else vendor_dependent
    if key not in vendor_dependent:
        chosen = preferred_keys() if preferred is None else preferred
        if key not in chosen:
            return None
    return alternative_for(path, available)


def alternative_for(path, available=_available):
    """URL of the free add-on matching the upstream page at `path`, or None."""
    from urllib.parse import quote
    for pattern, key, url in ALTERNATIVES:
        match = re.match(pattern, path or '')
        if match and available(key):
            return url.format(**{k: quote(v, safe='') for k, v in match.groupdict().items()})
    return None


def request_from(args, kwargs):
    """The HttpRequest among a view's (or a manager method's) arguments."""
    def is_request(value):
        return hasattr(value, 'path') and hasattr(value, 'method') and hasattr(value, 'session')
    values = list(args) + list(kwargs.values())
    for value in values:
        if is_request(value):
            return value
    for value in values:  # manager objects keep the request as an attribute
        if is_request(getattr(value, 'request', None)):
            return value.request
    return None
