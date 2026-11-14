"""Build Services requests: a form in the panel whose submissions are kept and emailed to the
administrator's chosen address through the local mail server (no third-party service).

Files (owned by the panel user, mode 0600):
  /home/cyberpanel/build-services.json      {"recipient": "..."} chosen by an administrator
  /home/cyberpanel/build-requests.jsonl     one JSON line per submission (kept even if mail fails)
"""
import json
import os
import re
import smtplib
import time
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

SETTINGS = '/home/cyberpanel/build-services.json'
LOG = '/home/cyberpanel/build-requests.jsonl'
SERVICES = ('Website', 'Android app', 'iOS app', 'Web application / SaaS', 'E-commerce store',
            'Custom software', 'Server setup / migration', 'Maintenance & support', 'Other')
BUDGETS = ('', 'Under ₹25,000', '₹25,000 – ₹1,00,000', '₹1,00,000 – ₹5,00,000', 'Above ₹5,00,000', 'Not sure yet')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$')
PHONE_RE = re.compile(r'^[0-9+()\- .]{6,25}$')
# Never mail customer requests to the vendor's default admin address left by the installer.
VENDOR_DOMAINS = ('cyberpersons.com', 'cyberpanel.net', 'cyberpanel.sh')
MAX_PER_HOUR = 5


class RequestError(ValueError):
    pass


def _clean(value, limit):
    text = str(value or '').replace('\r', '').strip()
    text = ''.join(ch for ch in text if ch == '\n' or ch >= ' ')
    return text[:limit]


def validate(data):
    req = {
        'name': _clean(data.get('name'), 100),
        'email': _clean(data.get('email'), 254).lower(),
        'phone': _clean(data.get('phone'), 25),
        'company': _clean(data.get('company'), 120),
        'service': _clean(data.get('service'), 60),
        'budget': _clean(data.get('budget'), 60),
        'deadline': _clean(data.get('deadline'), 60),
        'details': _clean(data.get('details'), 5000),
    }
    if len(req['name']) < 2 or '\n' in req['name']:
        raise RequestError('Please enter your name.')
    if not EMAIL_RE.match(req['email']):
        raise RequestError('Please enter a valid email address.')
    if req['phone'] and not PHONE_RE.match(req['phone']):
        raise RequestError('Please enter a valid phone number or leave it empty.')
    if req['service'] not in SERVICES:
        raise RequestError('Choose what you would like built.')
    if req['budget'] not in BUDGETS:
        raise RequestError('Choose a budget range.')
    if len(req['details']) < 20:
        raise RequestError('Please describe the project in a few sentences (20 characters or more).')
    for key in ('company', 'deadline'):
        if '\n' in req[key]:
            raise RequestError('Line breaks are only allowed in the project details.')
    return req


def _private_write(path, text, append=False):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC) | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a' if append else 'w') as handle:
        handle.write(text)


def load_settings(path=SETTINGS):
    try:
        with open(path) as handle:
            data = json.load(handle)
        return {'recipient': data.get('recipient', '')} if isinstance(data, dict) else {'recipient': ''}
    except (OSError, ValueError):
        return {'recipient': ''}


def usable_recipient(address):
    address = (address or '').strip().lower()
    return bool(EMAIL_RE.match(address)) and address.split('@')[1] not in VENDOR_DOMAINS


def save_settings(recipient, path=SETTINGS):
    recipient = (recipient or '').strip().lower()
    if not usable_recipient(recipient):
        raise RequestError('Enter a valid address of your own (not a CyberPanel vendor address).')
    _private_write(path, json.dumps({'recipient': recipient}))
    return {'recipient': recipient}


def rate_limited(session, now=None):
    now = time.time() if now is None else now
    recent = [t for t in session.get('build_requests', []) if now - t < 3600]
    if len(recent) >= MAX_PER_HOUR:
        return True
    session['build_requests'] = recent + [now]
    return False


def render_message(req, meta, recipient, sender):
    msg = EmailMessage()
    msg['Subject'] = 'Build request: %s from %s' % (req['service'], req['name'])
    msg['From'] = formataddr(('CyberPanel Build Services', sender))
    msg['To'] = recipient
    msg['Reply-To'] = formataddr((req['name'], req['email']))
    msg['Message-ID'] = make_msgid(domain=sender.split('@')[1])
    lines = ['A new Build Services request was submitted in the panel.', '']
    for label, key in (('Name', 'name'), ('Email', 'email'), ('Phone', 'phone'), ('Company', 'company'),
                       ('Service', 'service'), ('Budget', 'budget'), ('Timeline', 'deadline')):
        lines.append('%-9s %s' % (label + ':', req[key] or '-'))
    lines += ['', 'Project details:', req['details'], '',
              'Submitted by panel user %s from %s at %s.' % (meta['panel_user'], meta['ip'], meta['time']),
              'Reply to this email to answer the requester directly.']
    msg.set_content('\n'.join(lines))
    return msg


def submit(req, meta, sender, settings=None, smtp=smtplib.SMTP, log_path=LOG):
    """Keep the request, then mail it. Returns (mailed, note)."""
    _private_write(log_path, json.dumps(dict(req, **meta)) + '\n', append=True)
    settings = settings if settings is not None else load_settings()
    recipient = settings.get('recipient', '')
    if not usable_recipient(recipient):
        return False, 'Saved. The administrator has not set where requests are emailed yet.'
    try:
        with smtp('127.0.0.1', 25, timeout=20) as server:
            server.send_message(render_message(req, meta, recipient, sender))
        return True, 'Thank you - your request was sent. We will get back to you soon.'
    except (OSError, smtplib.SMTPException):
        return False, 'Saved, but the email could not be sent right now; the administrator can still see it.'


def recent_requests(limit=20, log_path=LOG):
    try:
        with open(log_path) as handle:
            lines = handle.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
