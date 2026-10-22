"""SSL V2: DNS-01 / wildcard certificates with acme.sh, inventory and expiry monitoring.

Differences from the official module, by design:
- Local DNS-01 goes through our acme.sh hook (dns_cpuniversal.sh -> dnshook.py), which writes
  TXT records through the panel's DNS models. The PowerDNS HTTP API is never enabled.
- Cloudflare uses scoped API tokens (CF_Token), not the Global API Key.
- acme.sh keeps the DNS hook and a reload command in its renewal config, so wildcard
  certificates renew over DNS-01 and the web/mail servers reload afterwards.
- CA and key type are selectable. No probe records are left behind.
"""
import os
import re
import subprocess
import time

ACME_HOME = '/root/.acme.sh'
ACME = os.path.join(ACME_HOME, 'acme.sh')
LIVE_DIR = '/etc/letsencrypt/live'
HOOK_NAME = 'dns_cpuniversal'
HOOK_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dns_cpuniversal.sh')
RELOAD_COMMAND = '/usr/local/CyberCP/bin/python /usr/local/CyberCP/universalAddons/sslv2/reload.py'

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
CF_TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{30,80}$')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+=-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$')
CAS = {'letsencrypt': 'letsencrypt', 'zerossl': 'zerossl', 'letsencrypt_test': 'letsencrypt_test'}
KEYS = {'ec-256': True, 'ec-384': True, '2048': False, '4096': False}  # value: ECC
PROVIDERS = ('pdns', 'cloudflare')


class SSLError(ValueError):
    pass


def valid_domain(domain):
    return isinstance(domain, str) and bool(DOMAIN_RE.match(domain))


def run(argv, runner=subprocess.run, env=None, timeout=900):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=env)
    except FileNotFoundError:
        return 127, '%s is not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- certificates

def parse_certificate(pem_bytes, now=None):
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    cert = x509.load_pem_x509_certificate(pem_bytes)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value \
            .get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    not_after = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after
    expires = not_after.timestamp() if not_after.tzinfo else \
        (not_after - __import__('datetime').datetime(1970, 1, 1)).total_seconds()
    issuer = ', '.join(a.value for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)) or \
        cert.issuer.rfc4514_string()
    issuer_cn = ', '.join(a.value for a in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME))
    now = now or time.time()
    return {
        'sans': sans,
        'wildcard': any(name.startswith('*.') for name in sans),
        'issuer': issuer + (' (%s)' % issuer_cn if issuer_cn else ''),
        'expires': int(expires),
        'days_left': int((expires - now) // 86400),
        'self_signed': cert.issuer == cert.subject,
        'staging': 'STAGING' in (issuer + issuer_cn).upper() or '(STAGING)' in cert.issuer.rfc4514_string().upper(),
    }


def read_acme_config(domain, acme_home=ACME_HOME):
    """Return acme.sh's renewal settings for domain (ECC dir preferred), or {}."""
    for directory in (domain + '_ecc', domain):
        path = os.path.join(acme_home, directory, domain + '.conf')
        try:
            with open(path) as handle:
                values = {}
                for line in handle:
                    match = re.match(r"^(Le_\w+)='?(.*?)'?$", line.strip())
                    if match:
                        values[match.group(1)] = match.group(2)
                values['ecc'] = directory.endswith('_ecc')
                return values
        except OSError:
            continue
    return {}


def challenge_of(acme_config):
    webroot = acme_config.get('Le_Webroot', '')
    if webroot.startswith('dns_'):
        return 'dns-01 (%s)' % webroot
    if webroot:
        return 'http-01'
    return ''


def inventory(domains, live_dir=LIVE_DIR, acme_home=ACME_HOME, now=None):
    rows = []
    for domain in sorted(set(domains)):
        row = {'domain': domain, 'certificate': None, 'acme': {}}
        path = os.path.join(live_dir, domain, 'fullchain.pem')
        try:
            with open(path, 'rb') as handle:
                row['certificate'] = parse_certificate(handle.read(), now)
        except (OSError, ValueError):
            pass
        config = read_acme_config(domain, acme_home)
        if config:
            row['acme'] = {'challenge': challenge_of(config), 'ca': config.get('Le_API', ''),
                           'next_renewal': config.get('Le_NextRenewTimeStr', ''),
                           'key': config.get('Le_Keylength', ''), 'reload': bool(config.get('Le_ReloadCmd'))}
        cert = row['certificate']
        if not cert:
            row['state'] = 'missing'
        elif cert['days_left'] < 0:
            row['state'] = 'expired'
        elif cert['self_signed'] or cert['staging']:
            row['state'] = 'untrusted'
        elif cert['days_left'] < 14:
            row['state'] = 'expiring'
        else:
            row['state'] = 'ok'
        rows.append(row)
    return rows


# ----------------------------------------------------------------------------- DNS readiness

def nameserver_check(resolver, domain, provider, server_ips):
    """Is DNS-01 through this provider going to be visible to the CA?"""
    labels = domain.split('.')
    for start in range(len(labels) - 1):
        zone = '.'.join(labels[start:])
        ns = [n.rstrip('.').lower() for n in resolver.query(zone, 'NS')]
        if ns:
            break
    else:
        return {'ok': False, 'zone': domain, 'nameservers': [], 'detail': 'No NS records found.'}
    if provider == 'cloudflare':
        ok = all(n.endswith('.ns.cloudflare.com') for n in ns)
        detail = 'Zone is on Cloudflare.' if ok else 'Nameservers are not Cloudflare: ' + ', '.join(ns)
    else:
        addresses = set()
        for name in ns:
            addresses.update(resolver.query(name, 'A'))
        ok = bool(addresses & set(server_ips))
        detail = ('Nameservers resolve to this server.' if ok else
                  'Nameservers (%s) do not point to this server, so TXT records written here will not be seen. '
                  'Use Cloudflare, or delegate the zone to this server.' % ', '.join(ns))
    return {'ok': ok, 'zone': zone, 'nameservers': ns, 'detail': detail}


# ----------------------------------------------------------------------------- issuance

def validate_request(domain, provider, wildcard=True, aliases=(), ca='letsencrypt', key='ec-256', email='',
                     cf_token=''):
    domain = (domain or '').strip().lower()
    if not valid_domain(domain):
        raise SSLError('Invalid domain name.')
    if provider not in PROVIDERS:
        raise SSLError('Choose the local DNS server or Cloudflare.')
    if ca not in CAS:
        raise SSLError('Unknown certificate authority.')
    if key not in KEYS:
        raise SSLError('Unknown key type.')
    clean_aliases = []
    for alias in aliases or ():
        alias = str(alias).strip().lower()
        if not valid_domain(alias):
            raise SSLError('Invalid alias %r.' % alias)
        if alias != domain:
            clean_aliases.append(alias)
    if ca == 'zerossl' and not EMAIL_RE.match(email or ''):
        raise SSLError('ZeroSSL needs an account e-mail address.')
    if provider == 'cloudflare' and cf_token and not CF_TOKEN_RE.match(cf_token):
        raise SSLError('That does not look like a Cloudflare API token.')
    names = [domain] + (['*.' + domain] if wildcard else [])
    for alias in sorted(set(clean_aliases)):
        names.append(alias)
        if wildcard:
            names.append('*.' + alias)
    return {'domain': domain, 'names': names, 'provider': provider, 'ca': ca, 'key': key,
            'email': email, 'cf_token': cf_token}


def acme_commands(request, acme=ACME, live_dir=LIVE_DIR):
    """(argv, env_overrides) pairs to issue and install a certificate."""
    domain = request['domain']
    hook = HOOK_NAME if request['provider'] == 'pdns' else 'dns_cf'
    env = {}
    if request['provider'] == 'cloudflare' and request['cf_token']:
        env['CF_Token'] = request['cf_token']
    commands = []
    if request['ca'] == 'zerossl':
        commands.append((['bash', acme, '--register-account', '-m', request['email'], '--server', 'zerossl'], {}))
    issue = ['bash', acme, '--issue', '--server', CAS[request['ca']], '--dns', hook, '--keylength', request['key'],
             '--force']
    if request['provider'] == 'pdns':
        issue += ['--dnssleep', '10']
    for name in request['names']:
        issue += ['-d', name]
    commands.append((issue, env))
    target = os.path.join(live_dir, domain)
    install = ['bash', acme, '--install-cert', '-d', domain, '--key-file', os.path.join(target, 'privkey.pem'),
               '--fullchain-file', os.path.join(target, 'fullchain.pem'), '--reloadcmd', RELOAD_COMMAND + ' ' + domain]
    if KEYS[request['key']]:
        install.append('--ecc')
    commands.append((install, {}))
    return commands


def install_hook(acme_home=ACME_HOME, source=HOOK_SOURCE):
    directory = os.path.join(acme_home, 'dnsapi')
    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, HOOK_NAME + '.sh')
    with open(source) as handle:
        content = handle.read()
    with open(target, 'w') as handle:
        handle.write(content)
    os.chmod(target, 0o700)
    return target


def acme_error(output):
    """Turn common acme.sh/ACME failures into an actionable message."""
    text = output or ''
    hints = (
        ('rateLimited', 'The CA rate limit was hit (too many certificates for this domain). Wait, or use ZeroSSL.'),
        ('Incorrect TXT record', 'The CA did not see the TXT record. Check that the zone is served by the chosen DNS provider.'),
        ('NXDOMAIN', 'The CA could not resolve the domain or the _acme-challenge name.'),
        ('invalid domain', 'The domain is not valid for public certificates.'),
        ('Invalid API token', 'Cloudflare rejected the API token. It needs Zone:DNS:Edit for this zone.'),
        ('dns_cpuniversal', 'Our local DNS hook failed. See the output below.'),
        ('CAA', 'A CAA record forbids this certificate authority.'),
    )
    for needle, hint in hints:
        if needle.lower() in text.lower():
            return hint
    return 'Issuance failed. See the acme.sh output below.'


def issue(request, runner=subprocess.run, log=None, acme=ACME):
    if not os.path.exists(acme):
        raise SSLError('acme.sh is not installed at %s.' % acme)
    if request['provider'] == 'pdns':
        install_hook(os.path.dirname(acme))
    os.makedirs(os.path.join(LIVE_DIR, request['domain']), mode=0o700, exist_ok=True)
    for argv, overrides in acme_commands(request, acme):
        env = dict(os.environ, **overrides) if overrides else None
        code, out = run(argv, runner, env=env)
        if log:
            log(out[-6000:])
        if code != 0 and not ('--register-account' in argv and 'already' in out.lower()):
            raise SSLError('%s\n%s' % (acme_error(out), out[-3000:]))
    return {'domain': request['domain'], 'names': request['names']}


# ----------------------------------------------------------------------------- monitor

def expiring(rows):
    """Rows whose certificate is expired, expires within 14 days, or is untrusted."""
    return [row for row in rows if row['state'] in ('expired', 'expiring', 'untrusted')]


def alert_rows(rows):
    """What the daily e-mail lists one by one: trusted certificates that expired or expire soon.

    Self-signed/staging certificates are summarised as a count instead; servers often carry many
    of them (CyberPanel installs a self-signed fallback when issuance fails) and listing them
    every day would bury the urgent lines.
    """
    urgent = [row for row in rows if row['state'] in ('expired', 'expiring')
              and row['certificate'] and not row['certificate']['self_signed']]
    untrusted = sum(1 for row in rows if row['state'] == 'untrusted')
    return urgent, untrusted


def alert_body(rows, hostname, untrusted=0):
    lines = ['Certificates on %s that need attention:' % hostname, '']
    for row in rows:
        cert = row['certificate']
        lines.append('- %s: %s%s' % (row['domain'], row['state'],
                                     ', %d days left' % cert['days_left'] if cert else ''))
    if untrusted:
        lines += ['', '%d site(s) also serve a self-signed or test certificate.' % untrusted]
    lines += ['', 'Open Universal Add-ons > SSL V2 in CyberPanel to renew.']
    return '\n'.join(lines)
