"""Notification centre: per-account channels, subscriptions, de-duplication and delivery.

Storage (owned by the panel user, directory 0700, files 0600; root-side callers hand files back
to the panel user after writing):
  accounts/<id>.json  channels (public settings and secrets), subscribed events, thresholds
  state/<id>.json     de-duplication keys, send times (rate limit), recent deliveries, known login IPs
  outbox/*.json       messages queued by fast paths (the login view) for the minute cron to send

Secrets (bot tokens, webhook URLs, signing secrets) never leave this module: public_view() drops
them and reports only that one is set.
"""
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from email.message import EmailMessage

from universalAddons.notify import netguard

NOTIFY_DIR = os.environ.get('UA_NOTIFY_DIR', '/home/cyberpanel/ua-notify')
PANEL_USER = 'cyberpanel'

DEDUP_SECONDS = 30 * 60      # the same event at most once per 30 minutes, unless its state changes
RATE_PER_HOUR = 30           # at most this many messages per account per hour
TEST_INTERVAL = 20           # seconds between two test messages on one channel
MAX_CHANNELS = 10
LOG_KEEP = 50
KNOWN_IPS = 20

EVENTS = (
    ('uptime', 'Uptime monitors: a check goes down or comes back up'),
    ('backup_failure', 'Backups that fail'),
    ('ssl_expiry', 'SSL certificates that expire soon'),
    ('disk_quota', 'Websites near their disk quota'),
    ('login_new_ip', 'A sign-in to your account from a new IP address'),
)
ADMIN_EVENTS = (
    ('server_disk', 'Server: a disk is over the usage threshold'),
    ('server_service', 'Server: a service on the Services page is down'),
    ('server_swap', 'Server: swap usage is high'),
)
EVENT_KEYS = {key for key, _ in EVENTS + ADMIN_EVENTS}
SEVERITIES = ('info', 'warning', 'error', 'critical')
DEFAULT_THRESHOLDS = {'disk': 90, 'swap': 80}

CHANNEL_TYPES = ('email', 'telegram', 'slack', 'discord', 'webhook')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+=-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$')
TELEGRAM_TOKEN_RE = re.compile(r'^\d{5,12}:[A-Za-z0-9_-]{30,60}$')
TELEGRAM_CHAT_RE = re.compile(r'^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$')
SLACK_RE = re.compile(r'^https://hooks\.slack\.com/services/[A-Za-z0-9_/-]{10,200}$')
DISCORD_RE = re.compile(r'^https://(discord|discordapp)\.com/api/webhooks/\d{5,25}/[A-Za-z0-9_-]{20,120}$')
NAME_RE = re.compile(r'^[\w .,()@&+-]{1,60}$')
CHANNEL_ID_RE = re.compile(r'^[0-9a-f]{8}$')
SIGNATURE_HEADER = 'X-IndiansCloud-Signature'
TIMESTAMP_HEADER = 'X-IndiansCloud-Timestamp'


class NotifyError(ValueError):
    pass


# ----------------------------------------------------------------------------- files

def _panel_ids():
    try:
        import pwd
        entry = pwd.getpwnam(PANEL_USER)
        return entry.pw_uid, entry.pw_gid
    except (KeyError, ImportError):
        return None


def _hand_back(path):
    """Files written by root-side callers go back to the panel user, who owns this store."""
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        ids = _panel_ids()
        if ids:
            os.chown(path, *ids)


def _dir(name):
    os.makedirs(NOTIFY_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(NOTIFY_DIR, name)
    if not os.path.isdir(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        _hand_back(path)
        _hand_back(NOTIFY_DIR)
    return path


def _account_id(account_id):
    if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id <= 0:
        raise NotifyError('Invalid account.')
    return account_id


def _read(path, default):
    try:
        with open(path) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else default
    except (OSError, ValueError):
        return default


def _write_private(path, data):
    temporary = '%s.%d.tmp' % (path, os.getpid())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, sort_keys=True)
    os.chmod(temporary, 0o600)
    _hand_back(temporary)
    os.replace(temporary, path)


@contextlib.contextmanager
def _locked(account_id):
    import fcntl
    path = os.path.join(_dir('state'), '%d.lock' % account_id)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    _hand_back(path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def account_path(account_id):
    return os.path.join(_dir('accounts'), '%d.json' % _account_id(account_id))


def state_path(account_id):
    return os.path.join(_dir('state'), '%d.json' % _account_id(account_id))


def has_settings(account_id):
    """Has this account saved notification settings (channels or subscriptions)?"""
    try:
        return os.path.exists(os.path.join(NOTIFY_DIR, 'accounts', '%d.json' % _account_id(account_id)))
    except NotifyError:
        return False


def load_account(account_id):
    data = _read(account_path(account_id), {})
    for key in ('events', 'thresholds'):
        if not isinstance(data.get(key), dict):
            data[key] = {}
    if not isinstance(data.get('channels'), list):
        data['channels'] = []
    channels = [c for c in data.get('channels', []) if isinstance(c, dict) and c.get('type') in CHANNEL_TYPES]
    events = {key: data['events'].get(key, True) is not False for key in EVENT_KEYS}
    thresholds = dict(DEFAULT_THRESHOLDS)
    for key in thresholds:
        value = data['thresholds'].get(key)
        if isinstance(value, int) and 50 <= value <= 99:
            thresholds[key] = value
    return {'channels': channels, 'events': events, 'thresholds': thresholds}


def save_account(account_id, data):
    _write_private(account_path(account_id), data)


def load_state(account_id):
    data = _read(state_path(account_id), {})
    for key, default in (('keys', {}), ('sent', []), ('log', []), ('ips', []), ('tests', {})):
        if not isinstance(data.get(key), type(default)):
            data[key] = default
    return data


def save_state(account_id, data):
    _write_private(state_path(account_id), data)


# ----------------------------------------------------------------------------- channels

def public_channel(channel):
    """What a browser may see of a channel: never a secret, only whether it is set."""
    return {'id': channel['id'], 'type': channel['type'], 'name': channel.get('name', ''),
            'enabled': channel.get('enabled', True) is not False, 'public': dict(channel.get('public') or {}),
            'secret_set': bool(channel.get('secret'))}


def public_view(account_id, is_admin=False):
    account = load_account(account_id)
    state = load_state(account_id)
    events = [{'key': key, 'label': label, 'enabled': account['events'][key]}
              for key, label in EVENTS + (ADMIN_EVENTS if is_admin else ())]
    return {'channels': [public_channel(c) for c in account['channels']], 'events': events,
            'thresholds': account['thresholds'] if is_admin else None,
            'log': list(reversed(state['log']))[:LOG_KEEP], 'configured': has_settings(account_id)}


def _text(spec, key, limit=200):
    value = spec.get(key, '')
    if value is None:
        value = ''
    if not isinstance(value, str) or len(value) > limit:
        raise NotifyError('Invalid %s.' % key)
    return value.strip()


def validate_channel(spec, existing=None, is_admin=False):
    """Return a clean channel from the browser's spec. Empty secret fields keep the stored secret."""
    if not isinstance(spec, dict):
        raise NotifyError('Invalid channel.')
    kind = spec.get('type')
    if kind not in CHANNEL_TYPES:
        raise NotifyError('Choose e-mail, Telegram, Slack, Discord or webhook.')
    if existing and existing['type'] != kind:
        raise NotifyError('The type of a channel cannot change; add a new one instead.')
    name = _text(spec, 'name', 60) or kind.capitalize()
    if not NAME_RE.match(name):
        raise NotifyError('Use letters, digits and spaces in the channel name.')
    old_secret = dict((existing or {}).get('secret') or {})
    public, secret = {}, {}

    def keep(field, value, pattern, message):
        value = value or old_secret.get(field, '')
        if not value or not pattern.match(value):
            raise NotifyError(message)
        secret[field] = value

    if kind == 'email':
        address = _text(spec, 'address', 254)
        if not EMAIL_RE.match(address):
            raise NotifyError('Enter a valid e-mail address.')
        public['address'] = address
    elif kind == 'telegram':
        chat = _text(spec, 'chat_id', 40)
        if not TELEGRAM_CHAT_RE.match(chat):
            raise NotifyError('Enter the Telegram chat id (a number, or @channelname).')
        public['chat_id'] = chat
        keep('token', _text(spec, 'token', 100), TELEGRAM_TOKEN_RE, 'Enter the bot token from @BotFather.')
    elif kind == 'slack':
        keep('url', _text(spec, 'url', 300), SLACK_RE, 'Enter a Slack incoming webhook URL (https://hooks.slack.com/services/...).')
    elif kind == 'discord':
        keep('url', _text(spec, 'url', 300), DISCORD_RE, 'Enter a Discord webhook URL (https://discord.com/api/webhooks/...).')
    elif kind == 'webhook':
        url = _text(spec, 'url', 500)
        try:
            netguard.split_url(url)
        except netguard.GuardError as exc:
            raise NotifyError(str(exc))
        public['url'] = url
        keep('signing_secret', _text(spec, 'signing_secret', 200), re.compile(r'^[\x21-\x7e]{16,200}$'),
             'Enter a signing secret of at least 16 characters (used for the HMAC-SHA256 signature).')
    channel = {'id': (existing or {}).get('id') or os.urandom(4).hex(), 'type': kind, 'name': name,
               'enabled': spec.get('enabled', True) is not False, 'public': public, 'secret': secret}
    if kind == 'webhook':
        channel['allow_local'] = bool(is_admin)   # administrators may post to this server itself
    return channel


def save_channel(account_id, spec, is_admin=False):
    with _locked(_account_id(account_id)):
        account = load_account(account_id)
        channel_id = spec.get('id') if isinstance(spec, dict) else None
        existing = None
        if channel_id:
            if not isinstance(channel_id, str) or not CHANNEL_ID_RE.match(channel_id):
                raise NotifyError('Unknown channel.')
            existing = next((c for c in account['channels'] if c['id'] == channel_id), None)
            if existing is None:
                raise NotifyError('Unknown channel.')
        elif len(account['channels']) >= MAX_CHANNELS:
            raise NotifyError('At most %d channels per account.' % MAX_CHANNELS)
        channel = validate_channel(spec, existing, is_admin)
        if existing:
            account['channels'] = [channel if c['id'] == channel['id'] else c for c in account['channels']]
        else:
            account['channels'].append(channel)
        save_account(account_id, account)
    return public_channel(channel)


def delete_channel(account_id, channel_id):
    with _locked(_account_id(account_id)):
        account = load_account(account_id)
        kept = [c for c in account['channels'] if c['id'] != channel_id]
        if len(kept) == len(account['channels']):
            raise NotifyError('Unknown channel.')
        account['channels'] = kept
        save_account(account_id, account)
    return {'deleted': channel_id}


def save_preferences(account_id, events, thresholds=None, is_admin=False):
    if not isinstance(events, dict):
        raise NotifyError('Invalid subscriptions.')
    allowed = {key for key, _ in EVENTS + (ADMIN_EVENTS if is_admin else ())}
    with _locked(_account_id(account_id)):
        account = load_account(account_id)
        for key, value in events.items():
            if key not in allowed or not isinstance(value, bool):
                raise NotifyError('Unknown event %r.' % key)
            account['events'][key] = value
        if thresholds is not None:
            if not is_admin or not isinstance(thresholds, dict):
                raise NotifyError('Invalid thresholds.')
            for key, value in thresholds.items():
                if key not in DEFAULT_THRESHOLDS or isinstance(value, bool) or not isinstance(value, int) \
                        or not 50 <= value <= 99:
                    raise NotifyError('Thresholds are percentages from 50 to 99.')
                account['thresholds'][key] = value
        save_account(account_id, account)
    return public_view(account_id, is_admin)


# ----------------------------------------------------------------------------- delivery

def sign(secret, timestamp, body):
    """HMAC-SHA256 over "<timestamp>.<body>", as sent in the X-IndiansCloud-Signature header."""
    if isinstance(body, str):
        body = body.encode('utf-8')
    digest = hmac.new(secret.encode('utf-8'), str(timestamp).encode('ascii') + b'.' + body, hashlib.sha256)
    return 'sha256=' + digest.hexdigest()


def verify(secret, timestamp, body, signature):
    return hmac.compare_digest(sign(secret, timestamp, body), signature or '')


def hostname():
    try:
        return socket.getfqdn() or 'localhost'
    except OSError:
        return 'localhost'


def _subject(message):
    return '[IndiansCloud] %s' % message['title']


def _plain_text(message):
    return '%s\n\n%s\n\n-- IndiansCloud on %s (%s)' % (_subject(message), message['body'], message['host'],
                                                        message['severity'])


def send_email(address, message, runner=subprocess.run):
    mail = EmailMessage()
    mail['To'] = address
    mail['Subject'] = _subject(message)
    mail.set_content('%s\n\n-- IndiansCloud on %s\n' % (message['body'], message['host']))
    result = runner(['sendmail', '-i', '--', address], input=mail.as_bytes(), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=60)
    if result.returncode != 0:
        raise NotifyError('sendmail failed: %s' % (result.stderr or b'').decode('utf-8', 'replace')[-200:])


def _post_json(url, payload, http, headers=None, allow_local=False):
    body = json.dumps(payload).encode('utf-8')
    all_headers = {'Content-Type': 'application/json'}
    all_headers.update(headers or {})
    response = http(url, method='POST', body=body, headers=all_headers, timeout=10, allow_local=allow_local,
                    read_limit=4096)
    if not 200 <= response['status'] < 300:
        raise NotifyError('HTTP %d from the receiver.' % response['status'])
    return body


def deliver(channel, message, email_runner=subprocess.run, http=netguard.request, now=None):
    """Send one message on one channel; raises on failure."""
    kind, public, secret = channel['type'], channel.get('public') or {}, channel.get('secret') or {}
    text = _plain_text(message)
    if kind == 'email':
        send_email(public['address'], message, email_runner)
    elif kind == 'telegram':
        _post_json('https://api.telegram.org/bot%s/sendMessage' % secret['token'],
                   {'chat_id': public['chat_id'], 'text': text[:4000], 'disable_web_page_preview': True}, http)
    elif kind == 'slack':
        _post_json(secret['url'], {'text': text[:3500]}, http)
    elif kind == 'discord':
        _post_json(secret['url'], {'content': text[:1900]}, http)
    elif kind == 'webhook':
        timestamp = int(now or time.time())
        payload = dict(message, time=timestamp)
        body = json.dumps(payload, sort_keys=True).encode('utf-8')
        headers = {'Content-Type': 'application/json', 'X-IndiansCloud-Event': message['event'],
                   TIMESTAMP_HEADER: str(timestamp), SIGNATURE_HEADER: sign(secret['signing_secret'], timestamp, body)}
        response = http(public['url'], method='POST', body=body, headers=headers, timeout=10,
                        allow_local=channel.get('allow_local') is True, read_limit=4096)
        if not 200 <= response['status'] < 300:
            raise NotifyError('HTTP %d from the webhook.' % response['status'])
    else:
        raise NotifyError('Unknown channel type.')


def account_email(account_id):
    """The e-mail address on the panel account (the default channel)."""
    from universalAddons import django_env
    django_env.setup()
    from loginSystem.models import Administrator
    admin = Administrator.objects.filter(pk=account_id).first()
    email = (getattr(admin, 'email', '') or '').strip()
    return email if EMAIL_RE.match(email) else ''


def channels_for(account_id, account=None, email_lookup=account_email):
    """Enabled channels; with none configured, e-mail to the account's address (the default)."""
    account = account or load_account(account_id)
    if account['channels']:
        return [c for c in account['channels'] if c.get('enabled', True) is not False]
    address = email_lookup(account_id)
    return [{'id': 'default', 'type': 'email', 'name': 'Account e-mail', 'public': {'address': address}}] \
        if address else []


def _message(event, title, body, severity, state=None, account_id=None):
    return {'event': event, 'title': str(title)[:200], 'body': str(body)[:8000], 'severity': severity,
            'state': state, 'host': hostname(), 'account_id': account_id}


def send(account_id, event, title, body, severity='warning', key=None, state=None, recovery=False,
         now=None, deliverer=deliver, email_lookup=account_email, window=DEDUP_SECONDS):
    """Notify one account about an event.

    key: what counts as "the same event" (default: event and title). state: the condition being
    reported ('down', 'up', 'high'...). The same key and state go out at most once per 30 minutes
    (`window` seconds; callers may pass a longer window for conditions that last, never a shorter one);
    a changed state goes out at once. recovery=True sends only when an earlier, different state was
    reported (a "back to normal" message nobody needs if no alert went out). At most RATE_PER_HOUR
    messages per account per hour. Returns {'sent': n, 'skipped': reason, 'errors': [...]}.
    """
    account_id = _account_id(account_id)
    if event not in EVENT_KEYS:
        raise NotifyError('Unknown event.')
    if severity not in SEVERITIES:
        severity = 'warning'
    now = time.time() if now is None else now
    key = str(key or '%s:%s' % (event, title))[:300]
    account = load_account(account_id)
    if not account['events'].get(event, True):
        return {'sent': 0, 'skipped': 'unsubscribed', 'errors': []}
    with _locked(account_id):
        state_data = load_state(account_id)
        previous = state_data['keys'].get(key)
        if recovery and (not previous or previous.get('state') == state):
            return {'sent': 0, 'skipped': 'no change', 'errors': []}
        if previous and previous.get('state') == state and now - previous.get('sent', 0) < max(window, DEDUP_SECONDS):
            return {'sent': 0, 'skipped': 'duplicate', 'errors': []}
        recent = [t for t in state_data['sent'] if isinstance(t, (int, float)) and now - t < 3600]
        if len(recent) >= RATE_PER_HOUR:
            _log(state_data, now, event, title, severity, 'rate limited')
            save_state(account_id, state_data)
            return {'sent': 0, 'skipped': 'rate limit', 'errors': []}
        # Reserve the key before delivering, so a parallel caller does not send it twice, and so the
        # lock is not held while channels answer (up to 10 seconds each).
        state_data['keys'][key] = {'state': state, 'sent': now}
        state_data['keys'] = {k: v for k, v in state_data['keys'].items()
                              if isinstance(v, dict) and now - v.get('sent', 0) < 14 * 86400}
        state_data['sent'] = recent + [now]
        save_state(account_id, state_data)
    message = _message(event, title, body, severity, state, account_id)
    sent, errors = 0, []
    try:
        channels = channels_for(account_id, account, email_lookup)
    except Exception as exc:
        channels, errors = [], ['account e-mail lookup: %s' % str(exc)[:200]]
    for channel in channels:
        try:
            deliverer(channel, message)
            sent += 1
        except Exception as exc:   # one failing channel must not stop the others
            errors.append('%s: %s' % (channel.get('name') or channel['type'], str(exc)[:200]))
    with _locked(account_id):
        state_data = load_state(account_id)
        _log(state_data, now, event, title, severity,
             'sent to %d channel(s)' % sent + ('; ' + '; '.join(errors) if errors else '') if sent or errors
             else 'no channel (no e-mail address on the account)')
        save_state(account_id, state_data)
    return {'sent': sent, 'skipped': '', 'errors': errors}


def _log(state_data, now, event, title, severity, result):
    state_data['log'] = (state_data['log'] + [{'time': int(now), 'event': event, 'title': str(title)[:200],
                                               'severity': severity, 'result': result[:400]}])[-LOG_KEEP:]


def test_channel(account_id, channel_id, now=None, deliverer=deliver):
    """Send a test message on one channel (at most one per TEST_INTERVAL seconds)."""
    now = time.time() if now is None else now
    account = load_account(_account_id(account_id))
    channel = next((c for c in account['channels'] if c['id'] == channel_id), None)
    if channel is None:
        raise NotifyError('Unknown channel.')
    with _locked(account_id):
        state_data = load_state(account_id)
        if now - state_data['tests'].get(channel_id, 0) < TEST_INTERVAL:
            raise NotifyError('Wait a few seconds before sending another test message.')
        state_data['tests'] = {k: v for k, v in state_data['tests'].items() if now - v < 86400}
        state_data['tests'][channel_id] = now
        save_state(account_id, state_data)
    message = _message('uptime', 'Test message', 'This is a test notification from IndiansCloud. If you can read '
                       'it, the channel "%s" works.' % channel.get('name', ''), 'info', None, account_id)
    try:
        deliverer(channel, message)
    except Exception as exc:
        raise NotifyError('The test message failed: %s' % str(exc)[:300])
    return {'sent': True}


# ----------------------------------------------------------------------------- outbox and helpers

def queue(account_id, event, title, body, severity='warning', key=None, state=None):
    """Queue a message for the minute cron (for request paths that must not wait on the network)."""
    record = {'account_id': _account_id(account_id), 'event': event, 'title': str(title)[:200],
              'body': str(body)[:4000], 'severity': severity, 'key': key, 'state': state, 'queued': int(time.time())}
    if event not in EVENT_KEYS:
        raise NotifyError('Unknown event.')
    _write_private(os.path.join(_dir('outbox'), '%020d-%s.json' % (time.time_ns(), os.urandom(4).hex())), record)


def flush_outbox(sender=None, limit=200):
    sender = sender or send
    directory = _dir('outbox')
    done = 0
    for name in sorted(os.listdir(directory))[:limit]:
        if not name.endswith('.json'):
            continue
        path = os.path.join(directory, name)
        record = _read(path, None)
        try:
            os.unlink(path)
        except OSError:
            continue
        if not record or time.time() - record.get('queued', 0) > 86400:
            continue
        try:
            sender(record['account_id'], record['event'], record['title'], record['body'], record.get('severity'),
                   key=record.get('key'), state=record.get('state'))
            done += 1
        except Exception:
            pass
    return done


def login_seen(account_id, ip, now=None):
    """Remember the sign-in address; queue an alert when it is new (not for the very first sign-in)."""
    try:
        parsed = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if parsed.version == 6 and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    # IPv6 clients rotate their interface id: one /64 counts as one address.
    address = str(ipaddress.ip_network('%s/64' % parsed, strict=False)) if parsed.version == 6 else str(parsed)
    account_id = _account_id(account_id)
    with _locked(account_id):
        state_data = load_state(account_id)
        known = [a for a in state_data['ips'] if isinstance(a, str)]
        if address in known:
            state_data['ips'] = [a for a in known if a != address] + [address]
            save_state(account_id, state_data)
            return False
        first = not known
        state_data['ips'] = (known + [address])[-KNOWN_IPS:]
        save_state(account_id, state_data)
    if first:
        return False
    queue(account_id, 'login_new_ip', 'New sign-in from %s' % address,
          'Your IndiansCloud account was signed in to from %s, an address not seen before (%s). If this was '
          'not you, change your password now.' % (address, time.strftime('%Y-%m-%d %H:%M %Z',
                                                                         time.localtime(now or time.time()))),
          'warning', key='login:%s' % address, state='new')
    return True


def admin_accounts():
    """(pk, email) of every administrator account."""
    from universalAddons import django_env
    django_env.setup()
    from loginSystem.models import Administrator
    return [(a.pk, (a.email or '').strip()) for a in Administrator.objects.filter(acl__adminStatus=1)]


def notify_admins(event, title, body, severity='warning', key=None, state=None, fallback=None, admins=None,
                  sender=None):
    """Tell every administrator. Administrators who saved notification settings get them through their
    channels; the others get the plain e-mail they always got, through `fallback(recipients)`
    (recipients: their addresses, or ['root'] when no administrator has one)."""
    sender = sender or send
    try:
        admins = admin_accounts() if admins is None else admins
        configured = [pk for pk, _ in admins if has_settings(pk)]
    except Exception:
        admins, configured = [], []
    legacy = [email for pk, email in admins if pk not in configured and email]
    for pk in configured:
        try:
            sender(pk, event, title, body, severity, key=key, state=state)
        except Exception:
            legacy.extend(email for p, email in admins if p == pk and email)
    if fallback is not None and (legacy or not configured):
        fallback(legacy or ['root'])
