"""Free Universal Add-ons that stand in for unlicensed paid pages.

The licence checks are left exactly as they are. When a paid page is not
licensed, the user is sent to the matching free add-on (if this install has it)
instead of a sales page. Licensed servers never reach this code.
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
)


def _available(key):
    try:
        from universalAddons.registry import MODULES, disabled_features
    except Exception:
        return False
    if key in disabled_features():
        return False
    return any(module.key == key and module.state == 'ready' for module in MODULES)


def alternative_for(path, available=_available):
    """URL of the free add-on that replaces the paid page at `path`, or None."""
    for pattern, key, url in ALTERNATIVES:
        if re.match(pattern, path or '') and available(key):
            return url
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
