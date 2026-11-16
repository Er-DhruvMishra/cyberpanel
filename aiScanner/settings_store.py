"""Settings and API-key storage for the IndiansCloud AI Scanner.

Files live in ``AISCANNER_DIR`` (default /var/lib/cyberpanel-universal/aiscanner),
owned by the panel's own user, directory 0700 and files 0600:

* ``config.json``  provider choices, models, budgets and policy (no secrets)
* ``secrets.json`` API keys, keyed by owner ("admin" or "user:<id>")
* ``usage.json``   daily request/token counters (see budget.py)

API keys are write-only: nothing here returns a key to a caller except
``get_key`` which the scan pipeline uses server-side.
"""
import copy
import json
import os
import stat
import tempfile

from . import providers

DEFAULT_DIR = '/var/lib/cyberpanel-universal/aiscanner'

KEY_POLICIES = ('admin', 'admin_or_own', 'own')
SLOTS = ('primary', 'fallback')

DEFAULTS = {
    'mode': 'local',                 # 'local' (no network) or 'ai'
    'privacy_ack': False,            # admin confirmed what is sent to the provider
    'primary': {'provider': 'cloudflare', 'model': '', 'account_id': '', 'base_url': '', 'json_mode': None},
    'fallback': {'provider': '', 'model': '', 'account_id': '', 'base_url': '', 'json_mode': None},
    'budget': {
        'max_requests_per_day': 200,     # stays under every free tier we support
        'max_tokens_per_day': 400000,
        'requests_per_minute': 10,
    },
    'limits': {
        'max_ai_files_per_scan': 25,
        'max_chars_per_request': 20000,
        'max_output_tokens': 2048,
    },
    'key_policy': 'admin',           # admin | admin_or_own | own
    'user_daily_ai_scans': 5,        # per non-admin user, when they use the admin's key
    'users': {},                     # str(user id) -> {'primary': slot}
}


class StoreError(Exception):
    pass


def base_dir():
    return os.environ.get('AISCANNER_DIR', DEFAULT_DIR)


def _ensure_dir(directory=None):
    directory = directory or base_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise StoreError('The AI Scanner settings directory has unsafe ownership.')
    if info.st_mode & 0o077:
        os.chmod(directory, 0o700)
    return directory


def _path(name):
    return os.path.join(base_dir(), name)


def read_json(name, default):
    path = _path(name)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        return copy.deepcopy(default)
    except OSError as exc:
        raise StoreError('Cannot read %s: %s' % (name, exc.strerror))
    with os.fdopen(fd, 'r', encoding='utf-8') as handle:
        try:
            data = json.load(handle)
        except ValueError:
            return copy.deepcopy(default)
    return data if isinstance(data, type(default)) else copy.deepcopy(default)


def write_json(name, data):
    directory = _ensure_dir()
    fd, temporary = tempfile.mkstemp(prefix='.%s.' % name, dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=1, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, _path(name))
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _merge(defaults, stored):
    out = copy.deepcopy(defaults)
    for key, value in (stored or {}).items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict) and key != 'users':
            out[key].update(value)
        else:
            out[key] = value
    return out


def load_config():
    return _merge(DEFAULTS, read_json('config.json', {}))


def save_config(config):
    write_json('config.json', config)


def _secrets():
    return read_json('secrets.json', {})


def key_owner(slot, user_id=None):
    return ('user:%d:%s' % (int(user_id), slot)) if user_id is not None else 'admin:%s' % slot


def get_key(owner):
    """Server-side only: the stored key for an owner, or ''."""
    value = _secrets().get(owner)
    return value if isinstance(value, str) else ''


def has_key(owner):
    return bool(get_key(owner))


def set_key(owner, key):
    secrets = _secrets()
    if key:
        secrets[owner] = providers.validate_key(key)
    else:
        secrets.pop(owner, None)
    write_json('secrets.json', secrets)


# ---------------------------------------------------------------------------
# Validation of submitted settings
# ---------------------------------------------------------------------------

def _int(value, low, high, name):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise StoreError('%s must be a whole number.' % name)
    if not low <= number <= high:
        raise StoreError('%s must be between %d and %d.' % (name, low, high))
    return number


def clean_slot(raw, allow_custom=True, allow_empty=False):
    raw = raw if isinstance(raw, dict) else {}
    provider = str(raw.get('provider') or '').strip()
    if not provider and allow_empty:
        return {'provider': '', 'model': '', 'account_id': '', 'base_url': '', 'json_mode': None}
    preset = providers.PRESETS.get(provider)
    if not preset:
        raise StoreError('Choose a provider.')
    if preset.get('admin_only') and not allow_custom:
        raise StoreError('Only the administrator can use a custom endpoint.')
    slot = {
        'provider': provider,
        'model': str(raw.get('model') or '').strip()[:128],
        'account_id': str(raw.get('account_id') or '').strip()[:64],
        'base_url': str(raw.get('base_url') or '').strip()[:300] if provider == 'custom' else '',
        'json_mode': None if raw.get('json_mode') in (None, '') else bool(raw.get('json_mode')),
    }
    try:
        providers.resolve(slot)
    except providers.ConfigError as exc:
        raise StoreError(str(exc))
    return slot


def apply_admin_settings(config, data):
    """Validate an admin's settings form into a new config dict (keys handled separately)."""
    new = copy.deepcopy(config)
    mode = data.get('mode', new['mode'])
    if mode not in ('local', 'ai'):
        raise StoreError('Mode must be "local" or "ai".')
    new['mode'] = mode
    new['privacy_ack'] = bool(data.get('privacy_ack', new.get('privacy_ack')))
    if 'primary' in data:
        new['primary'] = clean_slot(data['primary'])
    if 'fallback' in data:
        new['fallback'] = clean_slot(data['fallback'], allow_empty=True)
    budget = data.get('budget') or {}
    if budget:
        new['budget'] = {
            'max_requests_per_day': _int(budget.get('max_requests_per_day', new['budget']['max_requests_per_day']), 0, 100000, 'Requests per day'),
            'max_tokens_per_day': _int(budget.get('max_tokens_per_day', new['budget']['max_tokens_per_day']), 0, 100000000, 'Tokens per day'),
            'requests_per_minute': _int(budget.get('requests_per_minute', new['budget']['requests_per_minute']), 1, 1000, 'Requests per minute'),
        }
    limits = data.get('limits') or {}
    if limits:
        new['limits'] = {
            'max_ai_files_per_scan': _int(limits.get('max_ai_files_per_scan', new['limits']['max_ai_files_per_scan']), 0, 500, 'Files per scan'),
            'max_chars_per_request': _int(limits.get('max_chars_per_request', new['limits']['max_chars_per_request']), 2000, 200000, 'Characters per request'),
            'max_output_tokens': _int(limits.get('max_output_tokens', new['limits']['max_output_tokens']), 256, 16000, 'Output tokens'),
        }
    if 'key_policy' in data:
        if data['key_policy'] not in KEY_POLICIES:
            raise StoreError('Unknown key policy.')
        new['key_policy'] = data['key_policy']
    if 'user_daily_ai_scans' in data:
        new['user_daily_ai_scans'] = _int(data['user_daily_ai_scans'], 0, 1000, 'AI scans per user per day')
    if new['mode'] == 'ai' and not new['privacy_ack']:
        raise StoreError('Confirm the privacy notice before turning on AI analysis.')
    return new


def public_view(config, user_id=None, is_admin=True):
    """Settings as shown to the browser: keys reduced to set / not set."""
    def slot_view(slot, owner):
        view = {k: slot.get(k) for k in ('provider', 'model', 'account_id', 'base_url', 'json_mode')}
        view['key_set'] = has_key(owner) if slot.get('provider') else False
        return view

    out = {
        'mode': config['mode'],
        'privacy_ack': bool(config.get('privacy_ack')),
        'key_policy': config['key_policy'],
        'user_daily_ai_scans': config['user_daily_ai_scans'],
    }
    if is_admin:
        out.update({
            'primary': slot_view(config['primary'], key_owner('primary')),
            'fallback': slot_view(config['fallback'], key_owner('fallback')),
            'budget': dict(config['budget']),
            'limits': dict(config['limits']),
        })
    if user_id is not None and not is_admin:
        mine = (config.get('users') or {}).get(str(int(user_id))) or {}
        slot = mine.get('primary') or {'provider': '', 'model': '', 'account_id': '', 'base_url': '', 'json_mode': None}
        out['own'] = slot_view(slot, key_owner('primary', user_id))
    return out


def presets_view(include_custom=True):
    items = []
    for name, preset in providers.PRESETS.items():
        if preset.get('admin_only') and not include_custom:
            continue
        items.append({
            'id': name, 'label': preset['label'], 'default_model': preset['default_model'],
            'models': list(preset.get('models') or []), 'needs_account_id': bool(preset.get('needs_account_id')),
            'key_url': preset.get('key_url', ''), 'key_optional': bool(preset.get('key_optional')),
            'custom_url': name == 'custom', 'trains_on_free_tier': preset.get('trains_on_free_tier'),
        })
    return items
