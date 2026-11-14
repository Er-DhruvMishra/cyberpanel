"""Email Limits: per-domain and per-mailbox outbound sending limits, enforced by cpecs.

A free, independent replacement for the panel's licence-gated Email Limits page. It edits the same
tables the CyberPanel policy daemon (cpecs, postfixSenderPolicy/) reads, and never touches the
licence check or Postfix itself.

How cpecs enforces (postfixSenderPolicy/accept_traffic.py)
- Postfix asks cpecs at the DATA stage (smtpd_data_restrictions = check_policy_service
  unix:/var/log/policyServerSocket). A message is deferred only when BOTH the domain row
  (DomainLimits.limitStatus) and the mailbox row (EmailLimits.limitStatus) are 1 and one of
  domain monthly, mailbox monthly or mailbox hourly usage has reached its limit.
- cpecs keeps every domain/mailbox it has seen in memory and only reads the database the first
  time. Changes are pushed into that cache through a one-command file, /home/cyberpanel/purgeCache,
  which cpecs reads when a connection arrives on its socket (see actions.py). After each command
  cpecs writes its in-memory counters back to the database ("flush"), which is how the page gets
  live usage figures.
- Root cron runs `client.py hourlyCleanup` and `client.py monthlyCleanup` to reset counters.

Database work runs in the web process (the panel user can reach the cyberpanel database);
the cache push, health checks and cron repair need root and go through privileged.call.
"""
import re

MAX_LIMIT = 10000000          # IntegerField is a signed 32-bit int; keep well inside it
MAX_COMMANDS = 5000           # cache commands accepted in one sync call
DEFAULT_DOMAIN_MONTHLY = 10000
DEFAULT_MAILBOX_MONTHLY = 2000
DEFAULT_MAILBOX_HOURLY = 50

# \Z, not $: "$" also matches before a trailing newline.
DOMAIN_RE = re.compile(r'^(?=.{3,50}\Z)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\Z')
LOCAL_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9_+-])?\Z')

PURGE_FILE = '/home/cyberpanel/purgeCache'
POLICY_SOCKET = '/var/log/policyServerSocket'
CLIENT = '/usr/local/CyberCP/postfixSenderPolicy/client.py'
PYTHON = '/usr/local/CyberCP/bin/python'
CRON_JOBS = (
    ('hourlyCleanup', '0 * * * *'),
    ('monthlyCleanup', '0 0 1 * *'),
)
RESTRICTION_PARAMS = ('smtpd_data_restrictions', 'smtpd_recipient_restrictions', 'smtpd_end_of_data_restrictions')


class LimitError(ValueError):
    pass


# ----------------------------------------------------------------------------- input validation

def clean_domain(value):
    domain = value.lower() if isinstance(value, str) else ''
    if not DOMAIN_RE.match(domain) or '..' in domain:
        raise LimitError('Invalid domain.')
    return domain


def clean_email(value):
    if not isinstance(value, str) or len(value) > 80 or value.count('@') != 1:
        raise LimitError('Invalid mailbox.')
    local, domain = value.split('@')
    if not LOCAL_RE.match(local) or '..' in local:
        raise LimitError('Invalid mailbox.')
    return '%s@%s' % (local, clean_domain(domain))


def clean_limit(value, name):
    """A whole number 0..MAX_LIMIT. Booleans and fractions are refused (JSON true is an int in Python)."""
    if isinstance(value, bool):
        raise LimitError('%s must be a whole number.' % name)
    if isinstance(value, str) and re.match(r'^\d{1,9}\Z', value):
        value = int(value)
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if not isinstance(value, int) or not 0 <= value <= MAX_LIMIT:
        raise LimitError('%s must be a whole number between 0 and %d.' % (name, MAX_LIMIT))
    return value


def clean_status(value, name='Status'):
    if not isinstance(value, bool):
        raise LimitError('%s must be true or false.' % name)
    return 1 if value else 0


def check_mailbox_limits(monthly, hourly):
    if hourly > monthly:
        raise LimitError('The hourly limit cannot be higher than the monthly limit.')


# ----------------------------------------------------------------------------- cpecs cache commands

def cache_command(command):
    """Turn a structured command into the text cpecs' cacheManager.handlePurgeRequest expects.

    Rebuilt and re-validated on the root side: request data never reaches the file verbatim.
    """
    if not isinstance(command, (list, tuple)) or not command:
        raise LimitError('Invalid cache command.')
    op, args = command[0], list(command[1:])
    if op == 'domain_status' and len(args) == 2:
        return 'cyberpanelCleaner purgeLimitDomain %s %d' % (clean_domain(args[0]), _flag(args[1]))
    if op == 'domain_limit' and len(args) == 2:
        return 'cyberpanelCleaner updateDomainLimit %s %d' % (clean_domain(args[0]), clean_limit(args[1], 'Limit'))
    if op == 'mailbox_status' and len(args) == 2:
        return 'cyberpanelCleaner purgeLimit %s %d' % (clean_email(args[0]), _flag(args[1]))
    if op == 'mailbox_limits' and len(args) == 3:
        return 'cyberpanelCleaner purgeLimitEmail %s %d %d' % (
            clean_email(args[0]), clean_limit(args[1], 'Limit'), clean_limit(args[2], 'Limit'))
    if op == 'flush' and not args:
        # Not a cacheManager command: it is ignored, but cpecs flushes its counters afterwards.
        return 'cyberpanelCleaner refreshCounters'
    raise LimitError('Invalid cache command.')


def _flag(value):
    if value not in (0, 1) or isinstance(value, bool):
        raise LimitError('Invalid cache command.')
    return value


def domain_commands(domain, before, after):
    """Cache commands for the domain fields that changed. before/after: {'status','monthly'}."""
    out = []
    if before.get('status') != after['status']:
        out.append(['domain_status', domain, after['status']])
    if before.get('monthly') != after['monthly']:
        out.append(['domain_limit', domain, after['monthly']])
    return out


def mailbox_commands(email, before, after):
    out = []
    if before.get('status') != after['status']:
        out.append(['mailbox_status', email, after['status']])
    if (before.get('monthly'), before.get('hourly')) != (after['monthly'], after['hourly']):
        out.append(['mailbox_limits', email, after['monthly'], after['hourly']])
    return out


# ----------------------------------------------------------------------------- health checks (pure parsers)

def policy_hooks(postconf_values, socket_path=POLICY_SOCKET):
    """Which restriction lists call the cpecs socket. postconf_values: {param: value}."""
    needle = re.compile(r'check_policy_service\s+unix:%s(?=[\s,]|$)' % re.escape(socket_path))
    return [param for param in RESTRICTION_PARAMS if needle.search(postconf_values.get(param) or '')]


def cron_line(job, schedule):
    return '%s %s %s %s >/dev/null 2>&1' % (schedule, PYTHON, CLIENT, job)


def cron_present(crontab_text):
    """{job: True/False}: an uncommented line runs client.py <job>."""
    found = {job: False for job, _ in CRON_JOBS}
    for line in (crontab_text or '').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        for job, _ in CRON_JOBS:
            if re.search(r'postfixSenderPolicy/client\.py\s+%s(\s|$)' % job, stripped):
                found[job] = True
    return found


def cron_repaired(crontab_text):
    """The crontab with any missing cleanup line appended (unchanged text when nothing is missing)."""
    present = cron_present(crontab_text)
    missing = [cron_line(job, schedule) for job, schedule in CRON_JOBS if not present[job]]
    if not missing:
        return crontab_text or '', []
    text = crontab_text or ''
    if text and not text.endswith('\n'):
        text += '\n'
    return text + '\n'.join(missing) + '\n', missing


def health_report(service_state, socket_ok, postconf_values, crontab_text, purge_pending, default_action=''):
    """Results in the UA.resultRows shape: {status, title, detail, fix}."""
    rows = []
    if service_state == 'active':
        rows.append(_row('pass', 'cpecs service', 'cpecs.service is active.'))
    else:
        rows.append(_row('fail', 'cpecs service', 'cpecs.service is %s; no limit is enforced.' % (service_state or 'unknown'),
                         'Start it as root: systemctl enable --now cpecs'))
    if socket_ok:
        rows.append(_row('pass', 'Policy socket', '%s exists.' % POLICY_SOCKET))
    else:
        rows.append(_row('fail', 'Policy socket', '%s is missing or not a socket.' % POLICY_SOCKET,
                         'cpecs creates it when it starts; check journalctl -u cpecs.'))
    hooks = policy_hooks(postconf_values)
    if 'smtpd_data_restrictions' in hooks:
        rows.append(_row('pass', 'Postfix policy hook', 'smtpd_data_restrictions calls the cpecs socket.'))
    elif hooks:
        rows.append(_row('warn', 'Postfix policy hook', '%s calls cpecs, but not smtpd_data_restrictions. cpecs counts '
                         'one message per policy request; at the recipient stage that is once per recipient.' % ', '.join(hooks),
                         'Add "check_policy_service unix:%s" to smtpd_data_restrictions.' % POLICY_SOCKET))
    else:
        rows.append(_row('fail', 'Postfix policy hook', 'No smtpd restriction list calls cpecs; limits are not enforced.',
                         'As root: postconf -e "smtpd_data_restrictions = check_policy_service unix:%s" and reload '
                         'Postfix at a quiet time. This page never changes or restarts Postfix.' % POLICY_SOCKET))
    if default_action:
        rows.append(_row('info', 'When cpecs is down', 'smtpd_policy_service_default_action = %s' % default_action))
    present = cron_present(crontab_text)
    for job, schedule in CRON_JOBS:
        if present[job]:
            rows.append(_row('pass', 'Cron: %s' % job, 'Root crontab runs client.py %s.' % job))
        else:
            rows.append(_row('fail', 'Cron: %s' % job, 'Root crontab does not run client.py %s; counters are never reset.' % job,
                             'Use "Repair cron entries" to add: %s' % cron_line(job, schedule)))
    if purge_pending:
        rows.append(_row('info', 'Pending cache command', '%s is waiting for cpecs. This is normal after the '
                         'hourly cron when no mail has been sent since: cpecs runs it before it checks the next '
                         'message.' % PURGE_FILE, '"Refresh live counters" delivers it now.'))
    return rows


def _row(status, title, detail, fix=''):
    return {'status': status, 'title': title, 'detail': detail, 'fix': fix}


# ----------------------------------------------------------------------------- database (web process)

def _models():
    from emailPremium.models import DomainLimits, EmailLimits
    from mailServer.models import Domains, EUsers
    return Domains, EUsers, DomainLimits, EmailLimits


def owner_site(mail_domain):
    """The website (or child domain) a mail domain belongs to, for ownership checks."""
    if mail_domain.domainOwner_id:
        return mail_domain.domainOwner.domain
    if mail_domain.childOwner_id:
        return mail_domain.childOwner.domain
    return mail_domain.domain


def mail_domains(sites=None):
    """Mail domains, optionally only those whose website/child domain is in `sites`."""
    from django.db.models import Q
    Domains = _models()[0]
    query = Domains.objects.select_related('domainOwner', 'childOwner').order_by('domain')
    if sites is not None:
        query = query.filter(Q(domainOwner__domain__in=list(sites)) | Q(childOwner__domain__in=list(sites)))
    return query


def get_mail_domain(domain):
    Domains = _models()[0]
    try:
        return Domains.objects.select_related('domainOwner', 'childOwner').get(domain=clean_domain(domain))
    except Domains.DoesNotExist:
        return None


def _domain_values(row):
    if row is None:
        return {'status': 0, 'monthly': DEFAULT_DOMAIN_MONTHLY, 'used': 0, 'missing': True}
    return {'status': row.limitStatus, 'monthly': row.monthlyLimit, 'used': row.monthlyUsed, 'missing': False}


def _mailbox_values(email, row):
    if row is None:
        return {'email': email, 'status': 0, 'monthly': DEFAULT_MAILBOX_MONTHLY, 'hourly': DEFAULT_MAILBOX_HOURLY,
                'used_month': 0, 'used_hour': 0, 'missing': True}
    return {'email': email, 'status': row.limitStatus, 'monthly': row.monthlyLimits, 'hourly': row.hourlyLimit,
            'used_month': row.monthlyUsed, 'used_hour': row.hourlyUsed, 'missing': False}


def overview(sites=None):
    from django.db.models import Count
    Domains, EUsers, DomainLimits, EmailLimits = _models()
    domains = list(mail_domains(sites))
    names = [d.domain for d in domains]
    limits = {}
    for row in DomainLimits.objects.filter(domain_id__in=names).order_by('id'):
        limits.setdefault(row.domain_id, row)
    boxes = dict(EUsers.objects.filter(emailOwner_id__in=names).values_list('emailOwner_id').annotate(n=Count('email')))
    limited = dict(EmailLimits.objects.filter(email__emailOwner_id__in=names, limitStatus=1)
                   .values_list('email__emailOwner_id').annotate(n=Count('id')))
    out = []
    for domain in domains:
        values = _domain_values(limits.get(domain.domain))
        values.update(domain=domain.domain, site=owner_site(domain), mailboxes=boxes.get(domain.domain, 0),
                      limited_mailboxes=limited.get(domain.domain, 0))
        out.append(values)
    return out


def detail(mail_domain):
    Domains, EUsers, DomainLimits, EmailLimits = _models()
    row = DomainLimits.objects.filter(domain=mail_domain).order_by('id').first()
    emails = list(EUsers.objects.filter(emailOwner=mail_domain).order_by('email').values_list('email', flat=True))
    rows = {}
    for item in EmailLimits.objects.filter(email_id__in=emails).order_by('id'):
        rows.setdefault(item.email_id, item)
    mailboxes = [_mailbox_values(email, rows.get(email)) for email in emails]
    result = {'domain': mail_domain.domain, 'site': owner_site(mail_domain), 'limits': _domain_values(row),
              'mailboxes': mailboxes}
    result['warnings'] = warnings(result['limits'], mailboxes)
    return result


def warnings(domain_limits, mailboxes):
    out = []
    if not domain_limits['status']:
        out.append('The domain limit is off, so no mailbox limit of this domain is enforced (cpecs requires both).')
    else:
        unlimited = [m['email'] for m in mailboxes if not m['status']]
        if unlimited:
            out.append('%d mailbox(es) have their limit off and are not limited at all, not even by the domain limit.'
                       % len(unlimited))
    total = sum(m['monthly'] for m in mailboxes if m['status'])
    if domain_limits['status'] and total > domain_limits['monthly']:
        out.append('Mailbox monthly limits add up to %d, more than the domain limit of %d; the domain limit '
                   'stops all mailboxes once it is reached.' % (total, domain_limits['monthly']))
    if any(m['missing'] for m in mailboxes) or domain_limits.get('missing'):
        out.append('Some limit rows do not exist yet; they are created with the values you save.')
    return out


def save_domain(mail_domain, status, monthly):
    """Update (or create) the domain row. Returns the cpecs cache commands to send."""
    from django.db import transaction
    DomainLimits = _models()[2]
    with transaction.atomic():
        row = DomainLimits.objects.select_for_update().filter(domain=mail_domain).order_by('id').first()
        before = {} if row is None else {'status': row.limitStatus, 'monthly': row.monthlyLimit}
        if row is None:
            row = DomainLimits(domain=mail_domain)
        row.limitStatus, row.monthlyLimit = status, monthly
        row.save()
    return domain_commands(mail_domain.domain, before, {'status': status, 'monthly': monthly})


def mailbox_rule(is_admin, domain_status, before_status, status, monthly, domain_monthly):
    """Restrictions for site owners: they share out the domain's quota but cannot escape it.

    cpecs only limits a mailbox whose own limit is on, so switching it off would also lift the
    domain limit for that mailbox; non-administrators may not do that while the domain limit is on.
    """
    if is_admin:
        return
    if domain_status and before_status and not status:
        raise PermissionError('Only an administrator can switch off a mailbox limit while the domain limit is on.')
    if domain_status and monthly > domain_monthly:
        raise PermissionError('The monthly limit cannot exceed the domain limit of %d.' % domain_monthly)


def save_mailboxes(mail_domain, changes, is_admin):
    """changes: [(email, status, monthly, hourly)]. All mailboxes must belong to mail_domain.

    Returns the cpecs cache commands. All or nothing: one invalid mailbox rolls everything back.
    """
    from django.db import transaction
    Domains, EUsers, DomainLimits, EmailLimits = _models()
    domain_row = DomainLimits.objects.filter(domain=mail_domain).order_by('id').first()
    domain_values = _domain_values(domain_row)
    commands = []
    with transaction.atomic():
        users = {u.email: u for u in EUsers.objects.filter(emailOwner=mail_domain, email__in=[c[0] for c in changes])}
        rows = {}
        for item in EmailLimits.objects.select_for_update().filter(email_id__in=list(users)).order_by('id'):
            rows.setdefault(item.email_id, item)
        for email, status, monthly, hourly in changes:
            if email not in users:
                raise LimitError('%s is not a mailbox of %s.' % (email, mail_domain.domain))
            check_mailbox_limits(monthly, hourly)
            row = rows.get(email)
            before = {} if row is None else {'status': row.limitStatus, 'monthly': row.monthlyLimits,
                                             'hourly': row.hourlyLimit}
            mailbox_rule(is_admin, domain_values['status'], before.get('status', 0), status, monthly,
                         domain_values['monthly'])
            if row is None:
                row = EmailLimits(email=users[email])
            row.limitStatus, row.monthlyLimits, row.hourlyLimit = status, monthly, hourly
            row.save()
            commands.extend(mailbox_commands(email, before, {'status': status, 'monthly': monthly, 'hourly': hourly}))
    return commands


def domain_emails(mail_domain):
    EUsers = _models()[1]
    return list(EUsers.objects.filter(emailOwner=mail_domain).order_by('email').values_list('email', flat=True))
