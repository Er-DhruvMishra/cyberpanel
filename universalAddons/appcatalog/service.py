"""App catalogue: the panel's existing one-click installers plus new verified installers.

Every new installer downloads the official release over HTTPS, verifies it before anything is
extracted (checksum from the project's own feed, and an OpenPGP signature where the project
publishes one), creates the database through the panel's database code (package quota applies),
runs the app's own CLI installer where it has one, and does all file work as the site's Linux
user. Admin credentials are generated here and shown once.

This module is pure: parsing, checks and argument building. actions.py does the I/O.
"""
import base64
import binascii
import json
import re
import secrets
import string
import xml.etree.ElementTree as ElementTree

from universalAddons.siteinfo import DOMAIN_RE, SiteError, check_rel


class CatalogError(ValueError):
    pass


# ----------------------------------------------------------------------------- the catalogue

# Installers the panel already has: the catalogue links to them.
EXISTING = (
    {'key': 'wordpress', 'title': 'WordPress', 'icon': 'fab fa-wordpress', 'url': '/addons/wordpress/?site={domain}',
     'summary': 'The most used CMS, through the WordPress add-on (staging, updates, hardening).'},
    {'key': 'joomla', 'title': 'Joomla', 'icon': 'fab fa-joomla', 'url': '/websites/{domain}/joomlaInstall',
     'summary': 'CMS for sites, portals and communities.'},
    {'key': 'prestashop', 'title': 'PrestaShop', 'icon': 'fas fa-cart-shopping',
     'url': '/websites/{domain}/installPrestaShop', 'summary': 'E-commerce shop.'},
    {'key': 'magento', 'title': 'Magento', 'icon': 'fab fa-magento', 'url': '/websites/{domain}/installMagento',
     'summary': 'Large-scale e-commerce (Adobe Commerce open source).'},
    {'key': 'mautic', 'title': 'Mautic', 'icon': 'fas fa-bullhorn', 'url': '/websites/{domain}/installMautic',
     'summary': 'Marketing automation.'},
)

# Pinned OpenPGP release-signing keys (full fingerprints). A downloaded key is used only when its
# fingerprint matches; MediaWiki publishes a keyring of its release managers instead.
NEXTCLOUD_FINGERPRINT = '28806A878AE423A28372792ED75899B9A724937A'
MATOMO_FINGERPRINT = 'F529A27008477483777FC23D63BB30D0E5D2C749'

NEW = {
    'drupal': {
        'title': 'Drupal', 'icon': 'fab fa-drupal', 'db': 'mysql', 'kind': 'php', 'top': 'drupal-',
        'summary': 'Enterprise CMS. Installed with drush site:install.',
        'source': 'Release tarball from ftp.drupal.org; version, MD5 and size from updates.drupal.org '
                  '(release-history feed). Drush is added with Composer.',
        'feed': 'https://updates.drupal.org/release-history/drupal/current',
    },
    'nextcloud': {
        'title': 'Nextcloud', 'icon': 'fas fa-cloud', 'db': 'mysql', 'kind': 'php', 'top': 'nextcloud',
        'summary': 'Files, calendar and contacts. Installed with occ maintenance:install; data outside the web root.',
        'source': 'download.nextcloud.com latest.tar.bz2 with its .sha256 and .asc (signed by the Nextcloud '
                  'release key, fingerprint pinned).',
        'url': 'https://download.nextcloud.com/server/releases/latest.tar.bz2',
        'key_url': 'https://nextcloud.com/nextcloud.asc', 'fingerprint': NEXTCLOUD_FINGERPRINT,
    },
    'phpbb': {
        'title': 'phpBB', 'icon': 'fas fa-comments', 'db': 'mysql', 'kind': 'php', 'top': 'phpBB3',
        'summary': 'Forum. Installed with phpbbcli.php install.',
        'source': 'download.phpbb.com release zip with its .sha256; version from version.phpbb.com.',
        'feed': 'https://version.phpbb.com/phpbb/versions.json',
    },
    'mediawiki': {
        'title': 'MediaWiki', 'icon': 'fab fa-wikipedia-w', 'db': 'mysql', 'kind': 'php', 'top': 'mediawiki-',
        'summary': 'The wiki engine of Wikipedia. Installed with maintenance/install.php.',
        'source': 'releases.wikimedia.org tarball with its .sig, checked against the MediaWiki release keyring '
                  '(mediawiki.org/keys/keys.txt); version from mediawiki.org.',
        'feed': 'https://www.mediawiki.org/w/api.php?action=expandtemplates&format=json&prop=wikitext'
                '&text=%7B%7BMW+stable+release+number%7D%7D',
        'key_url': 'https://www.mediawiki.org/keys/keys.txt',
    },
    'matomo': {
        'title': 'Matomo', 'icon': 'fas fa-chart-pie', 'db': 'mysql', 'kind': 'php', 'top': 'matomo',
        'summary': 'Web analytics. Files and database are prepared; Matomo has no installer on the command line, '
                   'so finish its short setup in the browser right away.',
        'source': 'builds.matomo.org matomo-latest.zip with its .asc (signed by the Matomo release key, '
                  'fingerprint pinned).',
        'url': 'https://builds.matomo.org/matomo-latest.zip',
        'key_url': 'https://builds.matomo.org/signature.asc', 'fingerprint': MATOMO_FINGERPRINT,
    },
    'grav': {
        'title': 'Grav', 'icon': 'fas fa-feather', 'db': None, 'kind': 'php', 'top': 'grav-admin',
        'summary': 'Flat-file CMS with the admin panel. No database.',
        'source': 'grav-admin zip of the latest GitHub release of getgrav/grav, checked against the SHA-256 '
                  'digest GitHub publishes for the asset.',
        'feed': 'https://api.github.com/repos/getgrav/grav/releases/latest',
    },
    'ghost': {
        'title': 'Ghost', 'icon': 'fab fa-ghost', 'db': 'ghost', 'kind': 'node', 'top': 'package',
        'summary': 'Publishing platform (Node.js). Runs as a Universal App behind OpenLiteSpeed on the whole site.',
        'source': 'The ghost package from registry.npmjs.org, checked against its SHA-512 integrity value.',
        'feed': 'https://registry.npmjs.org/ghost/latest',
    },
}

MAX_DOWNLOAD = 600 * 1024 * 1024
ADMIN_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{2,31}\Z')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@([a-z0-9-]{1,63}\.)+[a-z]{2,63}\Z')
APP_ID_RE = re.compile(r'^[a-z][a-z0-9-]{1,30}\Z')
VERSION_RE = re.compile(r'^\d{1,3}(\.\d{1,4}){1,3}\Z')
IGNORED_ENTRIES = ('.well-known',)   # ACME challenges may sit in an otherwise empty web root


def catalogue(domain):
    existing = [dict(app, url=app['url'].format(domain=domain), new=False) for app in EXISTING]
    new = [{'key': key, 'title': app['title'], 'icon': app['icon'], 'summary': app['summary'],
            'source': app['source'], 'db': bool(app['db']), 'kind': app['kind'], 'new': True}
           for key, app in sorted(NEW.items(), key=lambda item: item[1]['title'].lower())]
    return existing + new


# ----------------------------------------------------------------------------- request validation

def clean_request(data, domain):
    """Validate an install request. Returns a dict actions.py can trust."""
    data = data if isinstance(data, dict) else {}
    app = data.get('app')
    if app not in NEW:
        raise CatalogError('Unknown app.')
    try:
        rel = check_rel(data.get('path') or '')
    except SiteError as exc:
        raise CatalogError(str(exc))
    if NEW[app]['kind'] == 'node':
        rel = rel or app
        if not APP_ID_RE.match(rel):
            raise CatalogError('App name: 2-31 lowercase letters, digits and dashes, starting with a letter.')
    overwrite = data.get('overwrite') is True
    if overwrite and str(data.get('confirm', '')).strip().lower() != domain:
        raise CatalogError('To install over existing files, type the domain name to confirm.')
    site_name = ''.join(c for c in str(data.get('site_name') or NEW[app]['title']) if ord(c) >= 32)[:80].strip()
    admin_user = str(data.get('admin_user') or 'admin').strip()
    if not ADMIN_RE.match(admin_user):
        raise CatalogError('Admin user: 3-32 letters, digits, . _ -, starting with a letter.')
    admin_email = str(data.get('admin_email') or '').strip()
    if not EMAIL_RE.match(admin_email):
        raise CatalogError('Enter the admin email address.')
    return {'app': app, 'path': rel, 'overwrite': overwrite, 'site_name': site_name or NEW[app]['title'],
            'admin_user': admin_user, 'admin_email': admin_email}


def blocking_entries(names):
    """Entries that make a target directory "not empty"."""
    return sorted(n for n in names if n not in IGNORED_ENTRIES)


def new_password(length=20):
    """Letters and digits only (no shell, YAML, URL or SQL quoting issues), with each class present."""
    alphabet = string.ascii_letters + string.digits
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def database_names(site_user, app, suffix=None):
    """A database name/user for the panel (at most 16 characters; the panel allows 32)."""
    prefix = re.sub(r'[^a-z0-9]', '', site_user.lower())[:6] or 'site'
    suffix = suffix or secrets.token_hex(2)
    name = '%s_%s%s' % (prefix, app[:4], suffix)
    return name, name


def redact(text, secrets_):
    for secret in secrets_:
        if secret:
            text = text.replace(secret, '********')
    return text


# ----------------------------------------------------------------------------- release feeds

def parse_drupal_feed(xml_text):
    """Latest stable, published release from updates.drupal.org: version, url, md5, size."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        raise CatalogError('The Drupal release feed could not be read.')
    for release in root.iter('release'):
        get = lambda tag: (release.findtext(tag) or '').strip()
        version = get('version')
        if get('status') != 'published' or get('version_extra') or not VERSION_RE.match(version):
            continue
        url = get('download_link')
        if not re.match(r'^https://ftp\.drupal\.org/files/projects/drupal-%s\.tar\.gz\Z' % re.escape(version), url):
            continue
        md5 = get('mdhash').lower()
        if not re.match(r'^[0-9a-f]{32}\Z', md5):
            continue
        size = get('filesize')
        return {'version': version, 'url': url, 'md5': md5, 'size': int(size) if size.isdigit() else None}
    raise CatalogError('No stable Drupal release in the feed.')


def parse_phpbb_feed(json_text):
    try:
        stable = json.loads(json_text)['stable']
        branch = max(stable, key=lambda b: tuple(int(p) for p in b.split('.')))
        version = stable[branch]['current']
    except (ValueError, KeyError, TypeError, AttributeError):
        raise CatalogError('The phpBB version feed could not be read.')
    if not VERSION_RE.match(version) or not version.startswith(branch + '.'):
        raise CatalogError('Unexpected phpBB version %r.' % str(version)[:20])
    url = 'https://download.phpbb.com/pub/release/%s/%s/phpBB-%s.zip' % (branch, version, version)
    return {'version': version, 'url': url, 'sha256_url': url + '.sha256', 'file': 'phpBB-%s.zip' % version}


def parse_mediawiki_feed(json_text):
    try:
        version = json.loads(json_text)['expandtemplates']['wikitext'].strip()
    except (ValueError, KeyError, TypeError, AttributeError):
        raise CatalogError('The MediaWiki version could not be read.')
    if not re.match(r'^1\.\d{2}\.\d{1,3}\Z', version):
        raise CatalogError('Unexpected MediaWiki version %r.' % version[:20])
    branch = version.rsplit('.', 1)[0]
    url = 'https://releases.wikimedia.org/mediawiki/%s/mediawiki-%s.tar.gz' % (branch, version)
    return {'version': version, 'url': url, 'sig_url': url + '.sig'}


def parse_github_release(json_text, pattern=r'^grav-admin-v(\d+\.\d+\.\d+)\.zip\Z'):
    """The grav-admin asset of a GitHub release, with the sha256 digest GitHub publishes for it."""
    try:
        release = json.loads(json_text)
        assets = release['assets']
    except (ValueError, KeyError, TypeError):
        raise CatalogError('The Grav release feed could not be read.')
    if release.get('draft') or release.get('prerelease'):
        raise CatalogError('The latest Grav release is not a stable release.')
    for asset in assets:
        match = re.match(pattern, str(asset.get('name', '')))
        if not match:
            continue
        digest = str(asset.get('digest') or '')
        if not re.match(r'^sha256:[0-9a-f]{64}\Z', digest):
            raise CatalogError('GitHub publishes no SHA-256 digest for %s; not installing an unverified file.'
                               % asset['name'])
        url = str(asset.get('browser_download_url', ''))
        if not url.startswith('https://github.com/getgrav/grav/releases/download/'):
            raise CatalogError('Unexpected Grav download location.')
        return {'version': match.group(1), 'url': url, 'sha256': digest.split(':', 1)[1]}
    raise CatalogError('The latest Grav release has no grav-admin package.')


def parse_npm_meta(json_text, name='ghost'):
    try:
        meta = json.loads(json_text)
        version, dist = meta['version'], meta['dist']
        tarball, integrity = dist['tarball'], dist['integrity']
    except (ValueError, KeyError, TypeError):
        raise CatalogError('The npm registry answer could not be read.')
    if meta.get('name') != name or not VERSION_RE.match(version):
        raise CatalogError('Unexpected package in the npm registry answer.')
    if tarball != 'https://registry.npmjs.org/%s/-/%s-%s.tgz' % (name, name, version):
        raise CatalogError('Unexpected npm download location.')
    if not str(integrity).startswith('sha512-'):
        raise CatalogError('The npm registry gives no SHA-512 integrity value.')
    engines = str((meta.get('engines') or {}).get('node', ''))
    return {'version': version, 'url': tarball, 'sha512': sri_to_hex(integrity), 'node': engines}


def sri_to_hex(integrity):
    """'sha512-<base64>' (Subresource Integrity, as npm uses it) to hex."""
    try:
        raw = base64.b64decode(integrity.split('-', 1)[1], validate=True)
    except (binascii.Error, IndexError, ValueError):
        raise CatalogError('Invalid integrity value.')
    if len(raw) != 64:
        raise CatalogError('Invalid integrity value.')
    return raw.hex()


def node_majors(engines):
    """Node.js major versions an engines range allows (^18.12.1 || ^20.11.1 -> {18, 20})."""
    return {int(m) for m in re.findall(r'(?:^|\|\||\s|\^|~|>=?)\s*v?(\d{1,2})(?:\.|\b)', engines or '')}


def pick_node(installed_versions, engines):
    majors = node_majors(engines)
    usable = [v for v in installed_versions if re.match(r'^\d+', v) and (not majors or int(v.split('.')[0]) in majors)]
    if not usable:
        return None
    return max(usable, key=lambda v: tuple(int(p) for p in re.findall(r'\d+', v)))


# ----------------------------------------------------------------------------- verification

def parse_checksum_file(text, filename=None):
    """The hex digest from a `sha256sum`-style file ("<hex>  <name>" or just "<hex>")."""
    for line in (text or '').splitlines():
        parts = line.strip().split()
        if not parts or not re.match(r'^[0-9a-fA-F]{32,128}\Z', parts[0]):
            continue
        if filename and len(parts) > 1 and parts[-1].lstrip('*') != filename:
            continue
        return parts[0].lower()
    raise CatalogError('The checksum file has no checksum%s.' % (' for %s' % filename if filename else ''))


def parse_digest_output(output):
    """The digest printed by sha256sum/sha512sum/md5sum."""
    match = re.match(r'^\s*([0-9a-f]{32,128})\s', output or '')
    if not match:
        raise CatalogError('Could not compute the checksum: %s' % (output or '').strip()[-200:])
    return match.group(1)


def check_digest(actual, expected, what):
    if not expected or not secrets.compare_digest(actual.lower(), expected.lower()):
        raise CatalogError('Checksum mismatch for %s: the download was not installed.' % what)
    return True


def parse_validsig(status_output):
    """Fingerprints from gpg --status-fd VALIDSIG lines (signing key and primary key)."""
    found = set()
    for line in (status_output or '').splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == '[GNUPG:]' and parts[1] == 'VALIDSIG':
            found.add(parts[2].upper())
            if len(parts) >= 12:
                found.add(parts[11].upper())
    return found


def check_signature(status_output, fingerprint=None):
    """A good signature (by `fingerprint` when one is pinned). Returns the signing fingerprints."""
    found = parse_validsig(status_output)
    bad = any(' BADSIG ' in ' %s ' % l or ' ERRSIG ' in ' %s ' % l for l in (status_output or '').splitlines())
    if bad or not found:
        raise CatalogError('The release signature did not verify: the download was not installed.')
    if fingerprint and fingerprint.upper() not in found:
        raise CatalogError('The release is signed, but not by the expected key %s.' % fingerprint)
    return sorted(found)


def check_archive_names(names, top):
    """Refuse archives with absolute paths or .. components; return the single top directory."""
    tops = set()
    for name in names:
        name = name.strip('\n')
        if not name:
            continue
        if name.startswith('/') or '\\' in name or '..' in name.split('/'):
            raise CatalogError('The archive contains an unsafe path: %s' % name[:100])
        tops.add(name.split('/', 1)[0])
    tops.discard('')
    wanted = [t for t in tops if t == top or (top.endswith('-') and t.startswith(top))]
    if len(wanted) != 1:
        raise CatalogError('Unexpected archive layout (top-level: %s).' % ', '.join(sorted(tops))[:200])
    return wanted[0]


# ----------------------------------------------------------------------------- CLI installers

def drush_settings(db_name, db_user, db_password):
    """Appended to sites/default/settings.php so drush site:install needs no password on its command line."""
    return ("\n$databases['default']['default'] = [\n  'database' => '%s',\n  'username' => '%s',\n"
            "  'password' => '%s',\n  'host' => 'localhost',\n  'port' => '3306',\n"
            "  'driver' => 'mysql',\n  'prefix' => '',\n  'collation' => 'utf8mb4_general_ci',\n];\n"
            % (db_name, db_user, db_password))


def drush_install_args(drush, site_name, admin_user, admin_email):
    return [drush, 'site:install', 'standard', '--yes', '--site-name=' + site_name, '--account-name=' + admin_user,
            '--account-mail=' + admin_email, '--site-mail=' + admin_email]


def parse_drush_password(output):
    match = re.search(r'User password:\s*(\S+)', output or '')
    return match.group(1) if match else None


def occ_install_args(php, occ, db_name, db_user, db_password, admin_user, admin_password, data_dir):
    return [php, occ, 'maintenance:install', '--no-interaction', '--database=mysql', '--database-host=localhost',
            '--database-name=' + db_name, '--database-user=' + db_user, '--database-pass=' + db_password,
            '--admin-user=' + admin_user, '--admin-pass=' + admin_password, '--data-dir=' + data_dir]


def occ_followup_args(php, occ, domain, url):
    return [[php, occ, 'config:system:set', 'trusted_domains', '1', '--value=' + domain],
            [php, occ, 'config:system:set', 'overwrite.cli.url', '--value=' + url]]


def mediawiki_install_args(php, root, db_name, db_user, db_pass_file, admin_pass_file, server, script_path,
                           site_name, admin_user):
    return [php, root + '/maintenance/install.php', '--dbtype=mysql', '--dbserver=localhost', '--dbname=' + db_name,
            '--dbuser=' + db_user, '--dbpassfile=' + db_pass_file, '--passfile=' + admin_pass_file,
            '--server=' + server, '--scriptpath=' + script_path, '--lang=en', '--confpath=' + root,
            site_name, admin_user]


def _yaml(value):
    return json.dumps(value, ensure_ascii=False)   # a JSON string is a valid YAML double-quoted scalar


def phpbb_config(site_name, admin_user, admin_password, admin_email, db_name, db_user, db_password, domain,
                 script_path):
    return '\n'.join([
        'installer:',
        '    admin:',
        '        name: %s' % _yaml(admin_user),
        '        password: %s' % _yaml(admin_password),
        '        email: %s' % _yaml(admin_email),
        '    board:',
        '        lang: en',
        '        name: %s' % _yaml(site_name),
        '        description: %s' % _yaml(site_name),
        '    database:',
        '        dbms: mysqli',
        '        dbhost: localhost',
        '        dbport: ~',
        '        dbuser: %s' % _yaml(db_user),
        '        dbpasswd: %s' % _yaml(db_password),
        '        dbname: %s' % _yaml(db_name),
        '        table_prefix: phpbb_',
        '    email:',
        '        enabled: false',
        '        smtp_delivery: ~',
        '        smtp_host: ~',
        '        smtp_port: ~',
        '        smtp_auth: ~',
        '        smtp_user: ~',
        '        smtp_pass: ~',
        '    server:',
        '        cookie_secure: true',
        '        server_protocol: https://',
        '        force_server_vars: false',
        '        server_name: %s' % _yaml(domain),
        '        server_port: 443',
        '        script_path: %s' % _yaml(script_path),
        '    extensions: []',
        ''])


def phpbb_install_args(php, root, config_path):
    return [php, root + '/install/phpbbcli.php', 'install', config_path]


def grav_account(admin_email, password_hash):
    """user/accounts/<admin>.yaml for a Grav super administrator."""
    return '\n'.join(['state: enabled', 'email: %s' % _yaml(admin_email), 'fullname: Administrator',
                      'title: Administrator', 'access:', '  admin:', '    login: true', '    super: true',
                      '  site:', '    login: true', 'hashed_password: %s' % _yaml(password_hash), ''])


def ghost_config(url, port, content_path, database):
    """config.production.json; database = {'client': 'sqlite3', ...} or the MySQL connection."""
    if database.get('client') == 'mysql':
        db = {'client': 'mysql', 'connection': {'host': 'localhost', 'user': database['user'],
                                                'password': database['password'], 'database': database['name']}}
    else:
        db = {'client': 'sqlite3', 'connection': {'filename': content_path + '/data/ghost.db'},
              'useNullAsDefault': True}
    return json.dumps({'url': url, 'server': {'host': '127.0.0.1', 'port': int(port)}, 'database': db,
                       'mail': {'transport': 'Direct'}, 'logging': {'transports': ['stdout']},
                       'process': 'local', 'paths': {'contentPath': content_path}}, indent=2) + '\n'


def ghost_setup_body(name, email, password, title):
    return json.dumps({'setup': [{'name': name, 'email': email, 'password': password, 'blogTitle': title}]})


def site_url(domain, rel):
    return 'https://%s/%s' % (domain, rel + '/' if rel else '')


def clean_domain(value):
    value = str(value or '').strip().lower()
    if not DOMAIN_RE.match(value):
        raise CatalogError('Invalid domain.')
    return value
