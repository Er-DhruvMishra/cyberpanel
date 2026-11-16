"""IndiansCloud AI Scanner - page and JSON endpoints.

Access (unchanged from the original design):
* any logged-in panel user may open the scanner, unless their ACL carries
  ``aiScannerAccess = 0``;
* a user may scan only websites they own (ACLManager.checkOwnership: admins all
  sites, resellers their own and their users' sites, users their own);
* scan history: admins see all scans, others their own and their direct
  sub-users' scans;
* the provider/key/budget settings are administrator-only.  Non-admin users may
  store their own key only when the key policy allows it.
"""
import json
import os
import subprocess
import sys
import uuid

from django.http import JsonResponse
from django.shortcuts import render

from loginSystem.models import Administrator
from plogical.acl import ACLManager
from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging

from . import budget, pipeline, providers, settings_store
from .models import ScanHistory

MAX_ACTIVE_SCANS = 2
MAX_BODY = 64 * 1024


class AccessDenied(Exception):
    pass


def _error(message, status=200):
    return JsonResponse({'success': False, 'error': message}, status=status)


def load_actor(user_id):
    """(admin, acl, is_admin) for a session user; raises AccessDenied."""
    admin = Administrator.objects.get(pk=user_id)
    acl = ACLManager.loadedACL(user_id)
    try:
        if acl.get('aiScannerAccess', 1) == 0:
            raise AccessDenied('Access denied')
    except AttributeError:
        pass
    return admin, acl, acl.get('admin') == 1


def visible_admins(admin, is_admin):
    """Whose scans this user may see: everyone (admin) or self + direct sub-users."""
    if is_admin:
        return None
    return [admin] + list(Administrator.objects.filter(owner=admin.pk))


def scans_for(admin, is_admin):
    owners = visible_admins(admin, is_admin)
    query = ScanHistory.objects.all() if owners is None else ScanHistory.objects.filter(admin__in=owners)
    return query.order_by('-started_at')


def can_see_scan(scan, admin, is_admin):
    owners = visible_admins(admin, is_admin)
    return owners is None or scan.admin_id in {a.pk for a in owners}


def _json_body(request):
    if len(request.body or b'') > MAX_BODY:
        raise ValueError('Request too large.')
    data = json.loads(request.body or b'{}')
    if not isinstance(data, dict):
        raise ValueError('Invalid request.')
    return data


def launch_background(scan_id):
    """Run the scan in a detached low-priority process so it survives worker recycling."""
    from django.conf import settings
    manage = os.path.join(str(settings.BASE_DIR), 'manage.py')
    python = pipeline.PANEL_PYTHON if os.path.exists(pipeline.PANEL_PYTHON) else sys.executable
    subprocess.Popen(['nice', '-n', '10', python, manage, 'aiscanner_scan', '--scan-id', scan_id],
                     cwd=str(settings.BASE_DIR), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)


class AIScannerManager:

    def __init__(self):
        self.logger = logging

    # ------------------------------------------------------------------ page
    def scannerHome(self, request, userID):
        try:
            admin, acl, is_admin = load_actor(userID)
        except AccessDenied:
            return ACLManager.loadError()
        config = settings_store.load_config()
        try:
            websites = ACLManager.findWebsiteObjects(acl, userID)
        except Exception as exc:
            self.logger.writeToFile('[AI Scanner] could not list websites: %s' % exc.__class__.__name__)
            websites = []
        own_allowed = (not is_admin) and config['key_policy'] in ('admin_or_own', 'own')
        context = {
            'websites': websites,
            'recent_scans': scans_for(admin, is_admin)[:10],
            'is_admin': is_admin,
            'own_key_allowed': own_allowed,
            'ai_mode': config['mode'] == 'ai',
            'key_policy': config['key_policy'],
            'boot_json': {
                'settings': settings_store.public_view(config, user_id=userID, is_admin=is_admin),
                'presets': settings_store.presets_view(include_custom=is_admin),
                'is_admin': is_admin,
                'own_key_allowed': own_allowed,
            },
        }
        return render(request, 'aiScanner/scanner.html', context)

    # ------------------------------------------------------------ settings
    def getSettings(self, request, userID):
        try:
            admin, acl, is_admin = load_actor(userID)
        except AccessDenied:
            return _error('Access denied', 403)
        config = settings_store.load_config()
        data = {'success': True, 'settings': settings_store.public_view(config, user_id=userID, is_admin=is_admin),
                'presets': settings_store.presets_view(include_custom=is_admin)}
        if is_admin:
            data['usage'] = budget.snapshot()
        return JsonResponse(data)

    def saveSettings(self, request, userID):
        if request.method != 'POST':
            return _error('Invalid request method', 405)
        try:
            admin, acl, is_admin = load_actor(userID)
            data = _json_body(request).get('settings')
            if not isinstance(data, dict):
                return _error('Invalid request.')
            config = settings_store.load_config()
            keys = data.get('keys') if isinstance(data.get('keys'), dict) else {}
            if is_admin:
                new = settings_store.apply_admin_settings(config, data)
                pending = {}
                for slot in settings_store.SLOTS:
                    entry = keys.get(slot) if isinstance(keys.get(slot), dict) else {}
                    if entry.get('clear'):
                        pending[settings_store.key_owner(slot)] = ''
                    elif entry.get('value'):
                        pending[settings_store.key_owner(slot)] = providers.validate_key(str(entry['value']).strip())
                if new['mode'] == 'ai':
                    owner = settings_store.key_owner('primary')
                    has = pending.get(owner) if owner in pending else settings_store.has_key(owner)
                    if not has and not providers.PRESETS[new['primary']['provider']].get('key_optional'):
                        return _error('Add an API key for the primary provider before turning on AI analysis.')
                settings_store.save_config(new)
                for owner, value in pending.items():
                    settings_store.set_key(owner, value)
            else:
                if config['key_policy'] not in ('admin_or_own', 'own'):
                    return _error('The administrator manages the AI provider for this server.', 403)
                own = data.get('own')
                users = dict(config.get('users') or {})
                owner = settings_store.key_owner('primary', userID)
                entry = keys.get('own') if isinstance(keys.get('own'), dict) else {}
                if isinstance(own, dict) and own.get('provider'):
                    users[str(int(userID))] = {'primary': settings_store.clean_slot(own, allow_custom=False)}
                elif isinstance(own, dict):
                    users.pop(str(int(userID)), None)
                    entry = {'clear': True}
                config['users'] = users
                value = providers.validate_key(str(entry['value']).strip()) if entry.get('value') else None
                settings_store.save_config(config)
                if entry.get('clear'):
                    settings_store.set_key(owner, '')
                elif value:
                    settings_store.set_key(owner, value)
            config = settings_store.load_config()
            return JsonResponse({'success': True,
                                 'settings': settings_store.public_view(config, user_id=userID, is_admin=is_admin)})
        except AccessDenied:
            return _error('Access denied', 403)
        except (settings_store.StoreError, providers.ConfigError, ValueError) as exc:
            return _error(str(exc))
        except OSError as exc:
            self.logger.writeToFile('[AI Scanner] could not save settings: %s' % exc.__class__.__name__)
            return _error('Could not write the settings file (%s).' % settings_store.base_dir())

    def testKey(self, request, userID, http=None):
        if request.method != 'POST':
            return _error('Invalid request method', 405)
        try:
            admin, acl, is_admin = load_actor(userID)
            data = _json_body(request).get('settings')
            if not isinstance(data, dict):
                return _error('Invalid request.')
            config = settings_store.load_config()
            slot_name = data.get('slot', 'primary')
            if is_admin and slot_name in settings_store.SLOTS:
                slot = settings_store.clean_slot(data.get('provider') or config[slot_name])
                owner = settings_store.key_owner(slot_name)
            elif not is_admin and slot_name == 'own' and config['key_policy'] in ('admin_or_own', 'own'):
                slot = settings_store.clean_slot(data.get('provider') or {}, allow_custom=False)
                owner = settings_store.key_owner('primary', userID)
            else:
                return _error('Access denied', 403)
            key = str(data.get('key') or '').strip()
            key = providers.validate_key(key) if key else settings_store.get_key(owner)
            cfg = providers.resolve(slot)
            # the test request counts against the same daily budget
            budget.reserve(owner, 600, config['budget'])
            kwargs = {'http': http} if http is not None else {}
            result = providers.test_key(cfg, key, **kwargs)
            return JsonResponse({'success': True, 'message': 'The provider answered (%d tokens).' % result['tokens']})
        except AccessDenied:
            return _error('Access denied', 403)
        except budget.BudgetExceeded as exc:
            return _error(str(exc))
        except providers.ProviderError as exc:
            return _error(exc.message)
        except (settings_store.StoreError, providers.ConfigError, ValueError) as exc:
            return _error(str(exc))

    # ---------------------------------------------------------------- scans
    def startScan(self, request, userID, launcher=None):
        if request.method != 'POST':
            return _error('Invalid request method', 405)
        try:
            admin, acl, is_admin = load_actor(userID)
            data = _json_body(request)
        except AccessDenied:
            return _error('Access denied', 403)
        except ValueError as exc:
            return _error(str(exc))
        domain = str(data.get('domain') or '').strip().lower()
        scan_type = data.get('scan_type') if data.get('scan_type') in ('full', 'quick') else 'full'
        if not domain:
            return _error('Domain is required')
        from websiteFunctions.models import Websites
        try:
            website = Websites.objects.get(domain=domain)
        except Websites.DoesNotExist:
            return _error('Domain not found')
        try:
            if not ACLManager.checkOwnership(domain, admin, acl):
                return _error('Access denied to this domain', 403)
        except Exception:
            return _error('Access denied to this domain', 403)
        active = ScanHistory.objects.filter(status__in=['pending', 'running'])
        if active.filter(domain=domain).exists():
            return _error('A scan of this site is already running.')
        if active.count() >= MAX_ACTIVE_SCANS:
            return _error('Other scans are running; try again in a few minutes.')
        scan = ScanHistory.objects.create(admin=admin, scan_id='ic_%s' % uuid.uuid4().hex[:16], domain=domain,
                                          scan_type=scan_type, status='pending')
        try:
            (launcher or launch_background)(scan.scan_id)
        except Exception as exc:
            scan.status = 'failed'
            scan.error_message = 'Could not start the scanner process.'
            scan.save()
            self.logger.writeToFile('[AI Scanner] launch failed: %s' % exc.__class__.__name__)
            return _error('Could not start the scan.')
        return JsonResponse({'success': True, 'scan_id': scan.scan_id, 'message': 'Scan started'})


def run_scan_by_id(scan_id, runner=None, http=None):
    """Entry point for the background process and the scheduler."""
    from websiteFunctions.models import Websites
    scan = ScanHistory.objects.select_related('admin').get(scan_id=scan_id)
    if scan.status not in ('pending', 'running'):
        return scan
    acl = ACLManager.loadedACL(scan.admin.pk)
    is_admin = acl.get('admin') == 1
    try:
        website = Websites.objects.get(domain=scan.domain)
        allowed = ACLManager.checkOwnership(scan.domain, scan.admin, acl)
    except Exception:
        website, allowed = None, 0
    if not website or not allowed:
        scan.status = 'failed'
        scan.error_message = 'The website no longer exists or is not accessible to this user.'
        scan.save()
        return scan
    kwargs = {'runner': runner}
    if http is not None:
        kwargs['http'] = http
    return pipeline.run_scan(scan, website, scan.admin.pk, is_admin, **kwargs)
