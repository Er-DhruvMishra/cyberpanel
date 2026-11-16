"""PostgreSQL databases for site owners: plain logic shared by actions.py, views.py and the tests.

PostgreSQL itself is installed and tuned by Applications (appsvc); this add-on only creates and
manages databases and roles for websites.

Rules
  * Names: the site's database prefix, as the panel's MySQL page builds it (first label of the
    domain without hyphens, cut to 4 characters when longer than 5), then "_" and the user's
    suffix: example.com -> exam_shop. Lowercase letters, digits and _ only, at most 32 characters.
  * Quota (combined): the package's database limit counts MySQL and PostgreSQL databases of the
    website together; 0 means unlimited. It is enforced when a PostgreSQL database is created.
    The panel's own MySQL page is unchanged and still counts only MySQL databases.
  * SQL: every psql script is constant text. Names and secrets reach it as environment variables,
    read with \\getenv and interpolated by psql itself as :"name" (quoted identifier, like
    format('%I')) or :'value' (quoted literal). Request data is never pasted into SQL, never on a
    command line. Names are also validated here (strict pattern) before they get that far.
  * Passwords: generated, shown once, never stored. The server receives a SCRAM-SHA-256 secret
    computed here, so the plain password never reaches PostgreSQL's logs.
  * Restores run as the site's Linux user with a temporary login role that is a member of the
    database owner (never as postgres/superuser), so an uploaded dump can do no more than the
    site's own role could.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import string

from universalAddons.appsvc.service import PG_MAJORS

STATE_DIR = '/var/lib/cyberpanel-universal/pgsql'
REGISTRY = os.path.join(STATE_DIR, 'registry.json')
BACKUP_DIR = 'pgsql-backups'                     # below the site's home, owned by the site user
MAX_NAME = 32
MAX_UPLOAD_BYTES = 512 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024
TEMP_PREFIX = 'ua_tmp_'
ADMINER_MINUTES = 30

SUFFIX_RE = re.compile(r'^[a-z0-9][a-z0-9_]{0,26}$')
NAME_RE = re.compile(r'^[a-z0-9][a-z0-9_]{1,31}$')
TEMP_RE = re.compile(r'^ua_tmp_[0-9a-f]{16}$')
BACKUP_RE = re.compile(r'^([a-z0-9][a-z0-9_]{1,31})-(\d{8}-\d{6})\.dump$')
RESERVED = {'postgres', 'template0', 'template1', 'public', 'root', 'admin', 'pg_signal_backend', 'none',
            'current_user', 'session_user', 'current_role', 'user'}
LEVELS = ('all', 'read')


class PGError(ValueError):
    pass


# ----------------------------------------------------------------------------- names

def db_prefix(domain):
    """The panel's MySQL prefix for a site (databases.js getTruncatedWebName), lower case."""
    first = (domain or '').lower().replace('-', '').split('.')[0]
    if len(first) > 5:
        first = first[:4]
    return re.sub(r'[^a-z0-9]', '', first)


def full_name(domain, suffix):
    """<prefix>_<suffix>, validated. Raises PGError."""
    suffix = str(suffix or '').strip().lower()
    if not SUFFIX_RE.match(suffix):
        raise PGError('Name: lowercase letters, digits and _ (1-27 characters, starting with a letter or digit).')
    prefix = db_prefix(domain)
    if not prefix:
        raise PGError('This site has no usable database prefix.')
    return check_name('%s_%s' % (prefix, suffix))


def check_name(name):
    """A database or role name this add-on may create or touch."""
    if not isinstance(name, str) or not NAME_RE.match(name) or len(name) > MAX_NAME:
        raise PGError('Invalid name: lowercase letters, digits and _ only, at most %d characters.' % MAX_NAME)
    if name in RESERVED or name.startswith('pg_') or name.startswith(TEMP_PREFIX):
        raise PGError('%s is reserved.' % name)
    return name


def owned_by_prefix(domain, name):
    return name.startswith(db_prefix(domain) + '_')


def quote_ident(name):
    """SQL identifier quoting, as format('%I') / quote_ident() do (used for display and tests;
    scripts let psql quote with :"var")."""
    if not isinstance(name, str) or '\x00' in name:
        raise PGError('Invalid identifier.')
    return '"%s"' % name.replace('"', '""')


def quote_literal(value):
    if not isinstance(value, str) or '\x00' in value:
        raise PGError('Invalid literal.')
    return "'%s'" % value.replace("'", "''")


# ----------------------------------------------------------------------------- quota

def quota_check(limit, mysql_count, pg_count):
    """Combined quota: MySQL + PostgreSQL databases of the website against the package limit.
    Returns a short usage text; raises PGError when the limit is reached (0 = unlimited)."""
    limit, used = int(limit or 0), int(mysql_count) + int(pg_count)
    if limit and used >= limit:
        raise PGError('The package allows %d database%s for this website (MySQL and PostgreSQL together) '
                      'and %d are in use.' % (limit, '' if limit == 1 else 's', used))
    return '%d of %s' % (used, limit or 'unlimited')


# ----------------------------------------------------------------------------- passwords

def new_password(length=24):
    alphabet = string.ascii_letters + string.digits
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def scram_secret(password, salt=None, iterations=4096):
    """The SCRAM-SHA-256 verifier PostgreSQL stores (RFC 5802/7677, as scram_build_secret builds it).
    Generated passwords are ASCII letters and digits, which SASLprep leaves unchanged."""
    if not re.match(r'^[A-Za-z0-9]{12,128}$', password or ''):
        raise PGError('Unexpected password format.')
    salt = salt or os.urandom(16)
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    client_key = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode('ascii')
    return 'SCRAM-SHA-256$%d:%s$%s:%s' % (iterations, b64(salt), b64(stored_key), b64(server_key))


# ----------------------------------------------------------------------------- psql scripts
# Constant text: values arrive through \getenv (UA_* variables) and psql quotes them.

_ROLE_OPTS = 'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'

SCRIPTS = {
    'create_role': '\\getenv role UA_ROLE\n\\getenv secret UA_SECRET\n'
                   'CREATE ROLE :"role" LOGIN PASSWORD :\'secret\' %s;\n' % _ROLE_OPTS,
    'create_db': '\\getenv db UA_DB\n\\getenv owner UA_OWNER\n'
                 'CREATE DATABASE :"db" OWNER :"owner" ENCODING \'UTF8\' TEMPLATE template0;\n'
                 'REVOKE ALL ON DATABASE :"db" FROM PUBLIC;\n'
                 'GRANT ALL ON DATABASE :"db" TO :"owner";\n',
    # Run inside the new database: the owner also owns the public schema (PostgreSQL 15+ default).
    'own_schema': '\\getenv owner UA_OWNER\nALTER SCHEMA public OWNER TO :"owner";\n',
    'drop_db': '\\getenv db UA_DB\nDROP DATABASE IF EXISTS :"db" WITH (FORCE);\n',
    # Run in every database the role has privileges in, before drop_role.
    'disown': '\\getenv role UA_ROLE\n\\getenv owner UA_OWNER\n'
              'REASSIGN OWNED BY :"role" TO :"owner";\nDROP OWNED BY :"role";\n',
    'drop_owned': '\\getenv role UA_ROLE\nDROP OWNED BY :"role";\n',
    'drop_role': '\\getenv role UA_ROLE\n'
                 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = :\'role\';\n'
                 'DROP ROLE IF EXISTS :"role";\n',
    'password': '\\getenv role UA_ROLE\n\\getenv secret UA_SECRET\nALTER ROLE :"role" PASSWORD :\'secret\';\n',
    'grant_connect': '\\getenv db UA_DB\n\\getenv role UA_ROLE\n'
                     'GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"role";\n',
    'grant_all': '\\getenv role UA_ROLE\n\\getenv owner UA_OWNER\n'
                 'GRANT USAGE, CREATE ON SCHEMA public TO :"role";\n'
                 'GRANT ALL ON ALL TABLES IN SCHEMA public TO :"role";\n'
                 'GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO :"role";\n'
                 'GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO :"role";\n'
                 'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT ALL ON TABLES TO :"role";\n'
                 'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT ALL ON SEQUENCES TO :"role";\n'
                 'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT ALL ON FUNCTIONS TO :"role";\n',
    'grant_read': '\\getenv role UA_ROLE\n\\getenv owner UA_OWNER\n'
                  'GRANT USAGE ON SCHEMA public TO :"role";\n'
                  'GRANT SELECT ON ALL TABLES IN SCHEMA public TO :"role";\n'
                  'GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO :"role";\n'
                  'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT SELECT ON TABLES TO :"role";\n'
                  'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public GRANT SELECT ON SEQUENCES TO :"role";\n',
    # Run inside the database: objects the role created go to the owner, then every grant goes.
    'revoke_in_db': '\\getenv role UA_ROLE\n\\getenv owner UA_OWNER\n'
                    'REASSIGN OWNED BY :"role" TO :"owner";\n'
                    'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public REVOKE ALL ON TABLES FROM :"role";\n'
                    'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public REVOKE ALL ON SEQUENCES FROM :"role";\n'
                    'ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM :"role";\n'
                    'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"role";\n'
                    'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"role";\n'
                    'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM :"role";\n'
                    'REVOKE ALL ON SCHEMA public FROM :"role";\n',
    'revoke_connect': '\\getenv db UA_DB\n\\getenv role UA_ROLE\nREVOKE ALL ON DATABASE :"db" FROM :"role";\n',
    # A short-lived login that acts as the owner (restore, Adminer). It logs in as itself, then
    # becomes the owner, so what it creates belongs to the owner.
    'temp_role': '\\getenv role UA_ROLE\n\\getenv secret UA_SECRET\n\\getenv owner UA_OWNER\n\\getenv until UA_UNTIL\n'
                 'CREATE ROLE :"role" LOGIN PASSWORD :\'secret\' VALID UNTIL :\'until\' CONNECTION LIMIT 5 %s;\n'
                 'GRANT :"owner" TO :"role";\n'
                 'ALTER ROLE :"role" SET role = :\'owner\';\n' % _ROLE_OPTS,
    'sizes': 'SELECT datname, pg_database_size(oid) FROM pg_database WHERE NOT datistemplate ORDER BY datname;\n',
    'exists': '\\getenv name UA_NAME\n'
              'SELECT (SELECT count(*) FROM pg_database WHERE datname = :\'name\') + '
              '(SELECT count(*) FROM pg_roles WHERE rolname = :\'name\');\n',
    'temp_roles': "SELECT rolname FROM pg_roles WHERE rolname LIKE 'ua\\_tmp\\_%' ORDER BY 1;\n",
}


def script(name, **values):
    """(constant psql script, environment with the values). Values are checked: names must be
    valid identifiers of this add-on, secrets and dates have fixed formats."""
    text = SCRIPTS[name]
    env = {}
    for key, value in values.items():
        if key in ('role', 'db', 'owner', 'name'):
            if not (isinstance(value, str) and TEMP_RE.match(value)):
                check_name(value)
        elif key == 'secret':
            if not isinstance(value, str) or not value.startswith('SCRAM-SHA-256$'):
                raise PGError('Passwords are sent as SCRAM secrets only.')
        elif key == 'until':
            if not re.match(r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\+00$', value or ''):
                raise PGError('Invalid expiry.')
        else:
            raise PGError('Unknown script value %s.' % key)
        if '\\getenv %s UA_%s' % (key, key.upper()) not in text:
            raise PGError('Script %s takes no %s.' % (name, key))
        env['UA_' + key.upper()] = value
    return text, env


def parse_sizes(text):
    sizes = {}
    for line in (text or '').splitlines():
        name, _, size = line.partition('|')
        if size.strip().isdigit():
            sizes[name.strip()] = int(size)
    return sizes


def psql_argv(major):
    return [os.path.join(pg_bin(major), 'psql'), '-X', '-q', '-At', '-F', '|', '-v', 'ON_ERROR_STOP=1', '-f', '-']


def pg_bin(major):
    if int(major) not in PG_MAJORS:
        raise PGError('Unsupported PostgreSQL version.')
    return '/usr/pgsql-%d/bin' % int(major)


def installed_major(exists=os.path.exists):
    """The newest PGDG major with its client installed here (readable by the web process too)."""
    for major in PG_MAJORS:
        if exists('/usr/pgsql-%d/bin/psql' % major) and exists('/usr/pgsql-%d/bin/postgres' % major):
            return major
    return None


# ----------------------------------------------------------------------------- registry (pure helpers)

def empty_registry():
    return {'version': 1, 'databases': {}, 'roles': {}, 'temps': {}}


def normalise_registry(data):
    reg = empty_registry()
    if isinstance(data, dict):
        for key in ('databases', 'roles', 'temps'):
            if isinstance(data.get(key), dict):
                reg[key] = {k: v for k, v in data[key].items() if isinstance(v, dict)}
    for entry in reg['databases'].values():
        if not isinstance(entry.get('grants'), dict):
            entry['grants'] = {}
    return reg


def site_view(reg, domains=None):
    """Databases and roles of the given sites (None = all), for listing."""
    def keep(entry):
        return domains is None or entry.get('domain') in domains
    dbs = [dict(e, name=n) for n, e in sorted(reg['databases'].items()) if keep(e)]
    roles = []
    for name, entry in sorted(reg['roles'].items()):
        if keep(entry):
            granted = sorted(d for d, e in reg['databases'].items() if name in e.get('grants', {}))
            owns = sorted(d for d, e in reg['databases'].items() if e.get('owner') == name)
            roles.append(dict(entry, name=name, databases=granted, owns=owns))
    return {'databases': dbs, 'roles': roles}


def count_for_site(reg, domain):
    return sum(1 for e in reg['databases'].values() if e.get('domain') == domain)


def require_db(reg, domain, name):
    entry = reg['databases'].get(name)
    if not entry or entry.get('domain') != domain:
        raise PGError('Unknown database.')
    return entry


def require_role(reg, domain, name):
    entry = reg['roles'].get(name)
    if not entry or entry.get('domain') != domain:
        raise PGError('Unknown role.')
    return entry


def backup_name(db, stamp):
    check_name(db)
    if not re.match(r'^\d{8}-\d{6}$', stamp):
        raise PGError('Invalid time stamp.')
    return '%s-%s.dump' % (db, stamp)


def dump_format(head):
    """'custom' for pg_dump -Fc archives, 'plain' for SQL text, else raises."""
    if head[:5] == b'PGDMP':
        return 'custom'
    if head[:2] == b'\x1f\x8b':
        raise PGError('Compressed files are not accepted: upload the .sql or .dump file itself.')
    sample = head[:4096]
    if b'\x00' in sample:
        raise PGError('This is neither a pg_dump custom archive nor a plain SQL file.')
    return 'plain'


def count_errors(output):
    return sum(1 for line in (output or '').splitlines() if 'ERROR:' in line)


# ----------------------------------------------------------------------------- Adminer

ADMINER_VERSION = '6.3.0'
ADMINER_FILE = 'adminer-%s-en.php' % ADMINER_VERSION
ADMINER_URL = 'https://github.com/vrana/adminer/releases/download/v%s/%s' % (ADMINER_VERSION, ADMINER_FILE)
# The author publishes no checksum file; this is the SHA-256 GitHub records for the release asset
# (api.github.com/repos/vrana/adminer/releases, "digest"), pinned here on 2026-11-16.
ADMINER_SHA256 = 'f467aac2419f3992e4bf450f8d88ee9d6ddd45243eb72fa224747019da33a8fa'
ADMINER_DIR = '/usr/local/CyberCP/public/adminer'
ADMINER_PATH = '/adminer/'

ADMINER_WRAPPER = r"""<?php
// Managed by IndiansCloud Add-ons > PostgreSQL databases; changes here are overwritten.
// Adminer for this server's PostgreSQL only: the server is fixed to 127.0.0.1:5432 (no other
// hosts can be reached from the login form) and only the PostgreSQL driver may log in.
function adminer_object() {
    if (!class_exists('IndiansCloudAdminerBase', false)) {
        class_alias(class_exists('Adminer\\Adminer') ? 'Adminer\\Adminer' : 'Adminer', 'IndiansCloudAdminerBase');
    }
    if (!class_exists('IndiansCloudAdminer', false)) {
        class IndiansCloudAdminer extends IndiansCloudAdminerBase {
            function name() {
                return 'IndiansCloud PostgreSQL';
            }
            function credentials() {
                $password = function_exists('Adminer\\get_password') ? call_user_func('Adminer\\get_password')
                    : call_user_func('get_password');
                return array('127.0.0.1:5432', isset($_GET['username']) ? $_GET['username'] : '', $password);
            }
            function login($login, $password) {
                $driver = defined('Adminer\\DRIVER') ? constant('Adminer\\DRIVER') : (defined('DRIVER') ? constant('DRIVER') : '');
                return $driver === 'pgsql' ? true : 'This Adminer is for PostgreSQL only.';
            }
        }
    }
    return new IndiansCloudAdminer;
}
include __DIR__ . '/%s';
""".replace('%s', ADMINER_FILE)


def adminer_installed(exists=os.path.exists):
    return exists(os.path.join(ADMINER_DIR, 'index.php')) and exists(os.path.join(ADMINER_DIR, ADMINER_FILE))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def connection_info(major):
    return {'host': '127.0.0.1', 'port': 5432, 'psql': '%s/psql -h 127.0.0.1 -U ROLE DBNAME' % pg_bin(major),
            'php': "new PDO('pgsql:host=127.0.0.1;port=5432;dbname=DBNAME', 'ROLE', 'PASSWORD');",
            'note': 'Applications connect over 127.0.0.1 with a role and its password (scram-sha-256).'}
