"""Root-side Cloudflare actions (dispatched by universalAddons/runner.py).

Only one thing here needs root: installing a Cloudflare Origin CA certificate on a panel site,
with the panel's own SSL install code (virtualHostUtilities.saveSSL, as Websites > SSL > Upload
does). The web side has already checked that the caller manages the site.
"""
import os
import re
import tempfile

DOMAIN_RE = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
WORK_DIR = '/var/lib/cyberpanel-universal/cloudflare'


def _panel_site(domain):
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import ChildDomains, Websites
    return Websites.objects.filter(domain=domain).exists() or ChildDomains.objects.filter(domain=domain).exists()


def install_cert(domain, key_pem, cert_pem):
    domain = str(domain or '').strip().lower()
    if not DOMAIN_RE.match(domain):
        raise ValueError('Invalid domain.')
    if not re.match(r'^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\s*$', cert_pem or ''):
        raise ValueError('Cloudflare returned an unexpected certificate.')
    if not re.match(r'^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END PRIVATE KEY-----\s*$', key_pem or ''):
        raise ValueError('Invalid private key.')
    if not _panel_site(domain):
        raise ValueError('%s is not a website on this server.' % domain)
    os.makedirs(WORK_DIR, mode=0o700, exist_ok=True)
    os.chmod(WORK_DIR, 0o700)
    paths = []
    try:
        for text in (key_pem, cert_pem):
            fd, path = tempfile.mkstemp(dir=WORK_DIR)
            with os.fdopen(fd, 'w') as handle:
                handle.write(text.strip() + '\n')
            paths.append(path)
        import io
        from contextlib import redirect_stdout
        from plogical.virtualHostUtilities import virtualHostUtilities
        out = io.StringIO()
        with redirect_stdout(out):
            virtualHostUtilities.saveSSL(domain, paths[0], paths[1])   # removes both files
        if '1,None' not in out.getvalue():
            raise ValueError('The panel could not install the certificate: %s' % out.getvalue().strip()[-300:])
    finally:
        for path in paths:
            if os.path.exists(path):
                os.unlink(path)
    return {'installed': domain}


ACTIONS = {'install_cert': install_cert}
