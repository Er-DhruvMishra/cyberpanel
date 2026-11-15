"""Microsoft SQL Server (Express edition) with per-site databases.

Footprint and safety choices
- Express edition (free; 10 GB per database, Microsoft's smallest server edition), with the
  memory cap set at install time (default 1 GB) so it cannot starve the web stack.
- Listens on 127.0.0.1 only. Apps on the server connect locally; nothing is exposed.
- Installation requires the administrator to accept Microsoft's licence terms explicitly.
- Preflight refuses hosts below Microsoft's minimums (2 GB RAM, 6 GB disk, x86-64).
- The sa password is random, stored root-only, and never shown in the panel.
- Each database gets its own login that owns only that database and cannot see other
  databases (DENY VIEW ANY DATABASE). Ownership is recorded per site and checked on every
  action.
- Passwords and SQL never appear on a command line: sqlcmd reads the password from the
  SQLCMDPASSWORD environment variable and SQL from a private temporary file.
"""
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import tempfile

STATE_DIR = '/etc/cyberpanel/mssql'
SQLCMD = '/opt/mssql-tools18/bin/sqlcmd'
MSSQL_CONF = '/opt/mssql/bin/mssql-conf'
DATA_DIR = '/var/opt/mssql'
MIN_RAM_MB = 2000
MIN_DISK_MB = 6144
EULA_URL = 'https://go.microsoft.com/fwlink/?LinkId=2104078'

NAME_RE = re.compile(r'^[a-z][a-z0-9_]{1,30}$')
DB_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{1,63}$')
OBJECT_RE = re.compile(r'^[A-Za-z_#@][A-Za-z0-9_#@$ -]{0,127}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


class SQLError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=600, env=None):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=env)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- platform

def repo_for(family, version):
    """(kind, url, product) of Microsoft's package repository for an OS profile."""
    version = int(version)
    if family == 'rhel':
        if version == 8:
            return 'rpm', 'https://packages.microsoft.com/config/rhel/8/mssql-server-2022.repo', '2022'
        if version in (9, 10):
            return 'rpm', 'https://packages.microsoft.com/config/rhel/%d/mssql-server-2025.repo' % version, '2025'
    if family == 'debian':
        if version in (20, 22):
            return 'deb', 'https://packages.microsoft.com/config/ubuntu/%d.04/mssql-server-2022.list' % version, '2022'
        if version == 24:
            return 'deb', 'https://packages.microsoft.com/config/ubuntu/24.04/mssql-server-2025.list', '2025'
    raise SQLError('Microsoft does not publish SQL Server for this operating system.')


def tools_repo_for(family, version):
    version = int(version)
    if family == 'rhel':
        return 'https://packages.microsoft.com/config/rhel/%d/prod.repo' % version
    return 'https://packages.microsoft.com/config/ubuntu/%d.04/prod.list' % version


TOOLS_REPO_ID = 'cp-microsoft-prod'
TOOLS_REPO_FILE = '/etc/yum.repos.d/cp-microsoft-prod.repo'


def tools_repo_text(version):
    return ('[%s]\nname=Microsoft production packages for RHEL %d (CyberPanel)\n'
            'baseurl=https://packages.microsoft.com/rhel/%d/prod/\nenabled=1\ngpgcheck=1\n'
            'gpgkey=https://packages.microsoft.com/keys/microsoft.asc\n' % (TOOLS_REPO_ID, int(version), int(version)))


def write_tools_repo(version, path=TOOLS_REPO_FILE):
    with open(path + '.tmp', 'w') as handle:
        handle.write(tools_repo_text(version))
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)


PROTECT_DROPIN = '/etc/systemd/system/mssql-server.service.d/cyberpanel-memory.conf'


def protect_dropin_text(memory_limit_mb, unified=None):
    """systemd drop-in so SQL Server, not MariaDB or the web stack, gives way when RAM runs out.

    OOMScoreAdjust makes the kernel pick sqlservr first; the cgroup ceiling (SQL Server's own
    memory limit plus room for its process overhead) keeps it from pushing everything into swap.
    """
    if unified is None:
        unified = os.path.exists('/sys/fs/cgroup/cgroup.controllers')
    ceiling = int(memory_limit_mb) + 512
    key = 'MemoryMax' if unified else 'MemoryLimit'
    return ('# Managed by CyberPanel Universal (SQL Server). Changes are overwritten.\n'
            '[Service]\nOOMScoreAdjust=500\n%s=%dM\n' % (key, ceiling))


def write_protect_dropin(memory_limit_mb, path=PROTECT_DROPIN):
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path + '.tmp', 'w') as handle:
        handle.write(protect_dropin_text(memory_limit_mb))
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)


def total_ram_mb(meminfo='/proc/meminfo'):
    with open(meminfo) as handle:
        for line in handle:
            if line.startswith('MemTotal:'):
                return int(line.split()[1]) // 1024
    return 0


def disk_free_mb(path=DATA_DIR):
    while not os.path.exists(path):
        path = os.path.dirname(path)
    return shutil.disk_usage(path).free // (1024 * 1024)


def preflight(profile, machine, ram_mb, disk_mb, installed):
    """List of {'id','ok','detail'} checks; installation is allowed only if all are ok."""
    checks = []
    try:
        kind, url, product = repo_for(profile['family'], profile['version'])
        checks.append({'id': 'os', 'ok': True, 'detail': 'SQL Server %s packages are available for this OS.' % product})
    except SQLError as exc:
        checks.append({'id': 'os', 'ok': False, 'detail': str(exc)})
    checks.append({'id': 'arch', 'ok': machine in ('x86_64', 'amd64'),
                   'detail': 'SQL Server on Linux requires x86-64 (this server: %s).' % machine})
    checks.append({'id': 'ram', 'ok': ram_mb >= MIN_RAM_MB,
                   'detail': '%d MB of RAM (Microsoft requires at least 2 GB).' % ram_mb})
    checks.append({'id': 'disk', 'ok': disk_mb >= MIN_DISK_MB,
                   'detail': '%.1f GB free for %s (Microsoft requires at least 6 GB).' % (disk_mb / 1024.0, DATA_DIR)})
    checks.append({'id': 'installed', 'ok': not installed, 'detail': 'SQL Server is already installed.' if installed
                   else 'SQL Server is not installed yet.'})
    return checks


def default_memory_limit_mb(ram_mb):
    """Leave most of the RAM to the web stack: 1/3 of RAM, between 512 MB and 4 GB."""
    return max(512, min(4096, ram_mb // 3))


# ----------------------------------------------------------------------------- secrets

def strong_password(length=24):
    """Meets SQL Server's complexity policy (upper, lower, digit, symbol) and avoids quoting issues."""
    symbols = '!#%*+-=?@^_'
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password) and any(c in symbols for c in password)):
            return password


def validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise SQLError('Passwords must be 12-128 characters.')
    if any(ord(c) < 32 for c in password) or "'" in password or ']' in password:
        raise SQLError('Passwords cannot contain quotes, ] or control characters.')
    classes = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                   any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
    if classes < 3:
        raise SQLError('Use at least three of: lowercase, uppercase, digits, symbols.')
    return password


def _private_write(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(path + '.tmp', path)


def _load(path, default):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def sa_password(state_dir=None):
    data = _load(os.path.join(state_dir or STATE_DIR, 'sa.json'), {})
    if not data.get('password'):
        raise SQLError('SQL Server is not set up by the panel.')
    return data['password']


def registry(state_dir=None):
    return _load(os.path.join(state_dir or STATE_DIR, 'databases.json'), {})


def save_registry(data, state_dir=None):
    _private_write(os.path.join(state_dir or STATE_DIR, 'databases.json'), data)


# ----------------------------------------------------------------------------- SQL

def quote_ident(name, kind='database'):
    """[name] with QUOTENAME semantics, after validating the name.

    kind='database' (and logins): the panel's own names. kind='object': schema, table and view
    names, which may also start with _ (e.g. __EFMigrationsHistory) and contain # @ $ - or spaces.
    """
    pattern = OBJECT_RE if kind == 'object' else DB_RE
    if not isinstance(name, str) or not pattern.match(name):
        raise SQLError('Invalid name %r.' % (name,))
    return '[%s]' % name.replace(']', ']]')


def quote_string(value):
    return "N'%s'" % value.replace("'", "''")


TABLE_FORMAT = ['-h', '-1', '-W', '-s', '|']


def sqlcmd(sql, password, runner=subprocess.run, sqlcmd_path=SQLCMD, database='master', options=None, timeout=300):
    """Run SQL as sa through a private file; the password travels in SQLCMDPASSWORD."""
    fd, path = tempfile.mkstemp(prefix='cp-mssql-', suffix='.sql')
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(sql)
        env = dict(os.environ, SQLCMDPASSWORD=password)
        code, out = run([sqlcmd_path, '-S', '127.0.0.1', '-U', 'sa', '-d', database, '-C', '-b']
                        + list(TABLE_FORMAT if options is None else options) + ['-i', path],
                        runner, timeout=timeout, env=env)
    finally:
        os.unlink(path)
    if code != 0:
        raise SQLError('SQL Server reported an error: %s' % out.strip()[-500:])
    return out


def create_sql(db, password):
    q = quote_ident(db)
    return '\n'.join([
        'SET NOCOUNT ON;',
        'CREATE DATABASE %s;' % q,
        'CREATE LOGIN %s WITH PASSWORD = %s, CHECK_POLICY = ON, DEFAULT_DATABASE = %s;' % (q, quote_string(password), q),
        'DENY VIEW ANY DATABASE TO %s;' % q,
        'ALTER AUTHORIZATION ON DATABASE::%s TO %s;' % (q, q),
        'GO',
    ]) + '\n'


def drop_sql(db):
    q = quote_ident(db)
    return '\n'.join([
        'SET NOCOUNT ON;',
        "IF DB_ID(%s) IS NOT NULL BEGIN ALTER DATABASE %s SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
        "DROP DATABASE %s; END;" % (quote_string(db), q, q),
        "IF SUSER_ID(%s) IS NOT NULL DROP LOGIN %s;" % (quote_string(db), q),
        'GO',
    ]) + '\n'


def password_sql(db, password):
    return 'ALTER LOGIN %s WITH PASSWORD = %s;\nGO\n' % (quote_ident(db), quote_string(password))


def database_name(site_user, name):
    """Site-prefixed name, as CyberPanel does for MySQL: <siteuser>_<name>."""
    name = (name or '').strip().lower()
    if not NAME_RE.match(name):
        raise SQLError('Database name: 2-31 lowercase letters, digits or _, starting with a letter.')
    prefix = re.sub(r'[^a-z0-9]', '', (site_user or '').lower())[:16] or 'site'
    return '%s_%s' % (prefix, name)


def connection_string(db, password):
    return ('Server=127.0.0.1,1433;Database=%s;User Id=%s;Password=%s;Encrypt=True;'
            'TrustServerCertificate=True;' % (db, db, password))


def sizes(password, runner=subprocess.run):
    out = sqlcmd('SET NOCOUNT ON; SELECT DB_NAME(database_id), CAST(SUM(size) * 8 / 1024 AS int) '
                 'FROM sys.master_files GROUP BY database_id;\nGO\n', password, runner)
    result = {}
    for line in out.splitlines():
        parts = [p.strip() for p in line.split('|')]
        if len(parts) == 2 and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
    return result


# ----------------------------------------------------------------------------- database viewer
#
# Every viewer batch runs in the database (sqlcmd -d), inside BEGIN TRANSACTION ... ROLLBACK, and
# as the database's own login (EXECUTE AS LOGIN), so even a query that slipped past the read-only
# filter could neither keep a change nor see another database or server-level data.

PAGE_SIZE = 50
ROW_CAP = 500
QUERY_TIMEOUT = 30
MAX_QUERY_CHARS = 20000
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_TEXT = 1000
MAX_BINARY = 32
DOC_MARK = '@@UA-DOC@@'
END_MARK = '@@UA-END@@'
# Unlimited width for (n)varchar(max) so a JSON document prints whole, no trimming (trailing
# spaces can be part of the data), no $(var) substitution, 30 s query timeout. sqlcmd refuses
# -h -1 together with -y 0, so documents() skips the header lines instead.
VIEWER_FORMAT = ['-y', '0', '-x', '-t', str(QUERY_TIMEOUT)]
FOR_JSON_HEADER = 'JSON_F52E2B61-18A1-11d1-B105-00805F49916B'
_HEADER_RE = re.compile(r'^(-+|%s)$' % FOR_JSON_HEADER)

FORBIDDEN = ('EXEC', 'EXECUTE', 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'DROP', 'ALTER', 'CREATE', 'GRANT', 'DENY',
             'REVOKE', 'TRUNCATE', 'BACKUP', 'RESTORE', 'SHUTDOWN', 'DBCC', 'OPENROWSET', 'OPENQUERY',
             'OPENDATASOURCE',
             # T-SQL needs no ';' between statements, so also refuse every reserved word that starts a
             # statement other than SELECT/WITH, and SELECT ... INTO (creates a table).
             'INTO', 'REVERT', 'SETUSER', 'USE', 'SET', 'DECLARE', 'WAITFOR', 'KILL', 'RECONFIGURE',
             'CHECKPOINT', 'BEGIN', 'COMMIT', 'ROLLBACK', 'SAVE', 'RAISERROR', 'THROW', 'PRINT', 'BULK',
             'WRITETEXT', 'UPDATETEXT', 'READTEXT', 'IF', 'WHILE', 'GOTO', 'RETURN')
_FORBIDDEN_RE = re.compile(r'\b(%s)\b|\bxp_' % '|'.join(FORBIDDEN), re.IGNORECASE)
_GO_RE = re.compile(r'\bGO\b', re.IGNORECASE)
# sqlcmd acts on these at the start of a line wherever they are (e.g. ':!! cmd' runs a shell command).
_SQLCMD_LINE_RE = re.compile(r'^[ \t]*(:|!!|GO\b)', re.IGNORECASE | re.MULTILINE)
_START_RE = re.compile(r'^\s*(SELECT|WITH)\b', re.IGNORECASE)
BINARY_TYPES = ('binary', 'varbinary', 'image', 'timestamp', 'rowversion')
LONG_TYPES = ('text', 'ntext', 'xml')


def strip_sql(sql):
    """`sql` with comments blanked and literal/identifier contents blanked, same length.

    Handles 'strings' (with ''), "identifiers" and [identifiers] (with ]]), -- line comments and
    nested /* block comments */ the way SQL Server does. Unterminated ones are refused.
    """
    out, i, n = list(sql), 0, len(sql)

    def blank(start, end):
        for k in range(start, end):
            out[k] = ' '

    while i < n:
        c, nxt = sql[i], sql[i + 1:i + 2]
        if c == '-' and nxt == '-':
            end = sql.find('\n', i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
        elif c == '/' and nxt == '*':
            depth, j = 1, i + 2
            while j < n and depth:
                pair = sql[j:j + 2]
                if pair == '/*':
                    depth, j = depth + 1, j + 2
                elif pair == '*/':
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            if depth:
                raise SQLError('Unterminated comment.')
            blank(i, j)
            i = j
        elif c in '\'"[':
            close = ']' if c == '[' else c
            j = i + 1
            while True:
                j = sql.find(close, j)
                if j < 0:
                    raise SQLError('Unterminated string or quoted name.')
                if sql[j + 1:j + 2] == close:  # doubled = escaped
                    j += 2
                    continue
                break
            blank(i + 1, j)
            i = j + 1
        else:
            i += 1
    return ''.join(out)


def readonly_query(sql):
    """Validate a read-only query; return it without its optional trailing ';'."""
    if not isinstance(sql, str) or not sql.strip():
        raise SQLError('Enter a query.')
    if len(sql) > MAX_QUERY_CHARS:
        raise SQLError('The query is longer than %d characters.' % MAX_QUERY_CHARS)
    if '\x00' in sql:
        raise SQLError('Invalid characters in the query.')
    if _SQLCMD_LINE_RE.search(sql):
        raise SQLError('GO and sqlcmd commands (lines starting with : or !!) are not allowed.')
    bare = strip_sql(sql)
    if not _START_RE.match(bare):
        raise SQLError('Only a single SELECT (or WITH ... SELECT) query is allowed.')
    trimmed = bare.rstrip()
    if trimmed.endswith(';'):
        cut = len(trimmed) - 1
        sql, bare = sql[:cut] + sql[cut + 1:], bare[:cut] + bare[cut + 1:]
    if ';' in bare:
        raise SQLError('Only a single statement is allowed.')
    if _GO_RE.search(bare):
        raise SQLError('GO is not allowed.')
    found = _FORBIDDEN_RE.search(bare)
    if found:
        raise SQLError('Read-only queries cannot use %s.' % found.group(0).upper())
    return sql


def viewer_sql(login, documents):
    """Batch printing each document (a statement producing JSON) after a marker line."""
    lines = ['SET NOCOUNT ON;', 'SET LOCK_TIMEOUT 5000;', 'BEGIN TRANSACTION;',
             'EXECUTE AS LOGIN = %s;' % quote_string(quote_ident(login)[1:-1])]
    for document in documents:
        lines += ["SELECT N'%s';" % DOC_MARK, document]
    lines += ["SELECT N'%s';" % END_MARK, 'REVERT;', 'ROLLBACK;', 'GO']
    return '\n'.join(lines) + '\n'


def _json_doc(select):
    """A SELECT ... FOR JSON wrapped as one scalar, so sqlcmd prints it as a single value."""
    return 'SELECT (%s FOR JSON PATH, INCLUDE_NULL_VALUES);' % select


def tables_sql(login):
    return viewer_sql(login, [_json_doc(
        "SELECT s.name AS [schema], o.name AS name, o.kind AS kind, "
        "(SELECT SUM(p.row_count) FROM sys.dm_db_partition_stats p WHERE p.object_id = o.object_id "
        "AND p.index_id IN (0, 1)) AS [rows], "
        "(SELECT SUM(p.reserved_page_count) * 8 FROM sys.dm_db_partition_stats p "
        "WHERE p.object_id = o.object_id) AS size_kb "
        "FROM (SELECT object_id, schema_id, name, 'table' AS kind FROM sys.tables WHERE is_ms_shipped = 0 "
        "UNION ALL SELECT object_id, schema_id, name, 'view' FROM sys.views WHERE is_ms_shipped = 0) o "
        "JOIN sys.schemas s ON s.schema_id = o.schema_id ORDER BY s.name, o.name")])


def object_name(schema, table):
    return '%s.%s' % (quote_ident(schema, 'object'), quote_ident(table, 'object'))


def columns_sql(login, schema, table):
    target = quote_string(object_name(schema, table))
    return viewer_sql(login, [_json_doc(
        "SELECT c.name AS name, TYPE_NAME(c.user_type_id) AS type, TYPE_NAME(c.system_type_id) AS base, "
        "CAST(CASE WHEN c.system_type_id = 240 THEN 1 ELSE 0 END AS bit) AS clr, "
        "c.max_length, c.precision, c.scale, c.is_nullable AS nullable, ic.key_ordinal AS pk "
        "FROM sys.columns c JOIN sys.objects o ON o.object_id = c.object_id AND o.type IN ('U', 'V') "
        "LEFT JOIN sys.indexes i ON i.object_id = c.object_id AND i.is_primary_key = 1 "
        "LEFT JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
        "AND ic.column_id = c.column_id "
        "WHERE c.object_id = OBJECT_ID(%s) ORDER BY c.column_id" % target)])


def quote_column(name):
    """QUOTENAME of a column name read from sys.columns (any characters, so only escaped)."""
    if not isinstance(name, str) or not name or len(name) > 128 or '\x00' in name:
        raise SQLError('Invalid column name.')
    return '[%s]' % name.replace(']', ']]')


def display_type(column):
    name, length = column.get('type') or '?', column.get('max_length')
    base = column.get('base') or name
    if base in ('varchar', 'char', 'varbinary', 'binary', 'nvarchar', 'nchar'):
        if length == -1:
            return '%s(max)' % name
        return '%s(%d)' % (name, length // 2 if base in ('nvarchar', 'nchar') else length)
    if base in ('decimal', 'numeric'):
        return '%s(%s,%s)' % (name, column.get('precision'), column.get('scale'))
    return name


def _browse_expr(column, alias):
    q = quote_column(column['name'])
    base = column.get('base')
    if column.get('clr'):
        expr = 'LEFT(%s.ToString(), %d)' % (q, MAX_TEXT + 1)
    elif base in BINARY_TYPES:
        expr = ("CASE WHEN DATALENGTH(%s) > %d THEN CONVERT(varchar(80), CONVERT(varbinary(%d), %s), 1) + '...' "
                "ELSE CONVERT(varchar(80), CONVERT(varbinary(%d), %s), 1) END"
                % (q, MAX_BINARY, MAX_BINARY, q, MAX_BINARY, q))
    elif base in LONG_TYPES or column.get('max_length') == -1:
        expr = 'LEFT(CONVERT(nvarchar(max), %s), %d)' % (q, MAX_TEXT + 1)
    elif base == 'sql_variant':
        expr = 'CONVERT(nvarchar(4000), %s)' % q
    else:
        expr = q
    return '%s AS [%s]' % (expr, alias)


def rows_sql(login, schema, table, columns, page):
    if not columns:
        raise SQLError('Unknown table.')
    page = int(page)
    if page < 0 or page > 10 ** 7:
        raise SQLError('Invalid page.')
    keys = sorted((c for c in columns if c.get('pk')), key=lambda c: c['pk'])
    order = ', '.join(quote_column(c['name']) for c in keys) or '(SELECT NULL)'
    select = ', '.join(_browse_expr(c, 'c%d' % i) for i, c in enumerate(columns))
    return viewer_sql(login, [_json_doc('SELECT %s FROM %s ORDER BY %s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY'
                                        % (select, object_name(schema, table), order, page * PAGE_SIZE, PAGE_SIZE))])


def query_sql(login, sql):
    query = readonly_query(sql)
    describe = _json_doc('SELECT name, system_type_name AS type, error_message FROM '
                         'sys.dm_exec_describe_first_result_set(%s, NULL, 0) ORDER BY column_ordinal'
                         % quote_string(query))
    # The query keeps its own lines; FOR JSON goes on a new line so a trailing -- comment cannot hide it.
    run_query = 'SET ROWCOUNT %d;\n%s\nFOR JSON PATH, INCLUDE_NULL_VALUES;\nSET ROWCOUNT 0;' % (ROW_CAP, query)
    return viewer_sql(login, [describe, run_query])


def documents(out):
    """Parse the JSON documents printed between the markers (None for an empty one)."""
    docs, current = [], None
    for line in out.splitlines():
        mark = line.strip()
        if mark in (DOC_MARK, END_MARK):
            if current is not None:
                docs.append(current)
            if mark == END_MARK:
                break
            current = []
        elif current is not None and mark and not _HEADER_RE.match(mark):
            current.append(line.rstrip('\r'))
    else:
        raise SQLError('Unexpected output from SQL Server: %s' % out.strip()[-300:])
    parsed = []
    for chunks in docs:
        text = ''.join(chunks)
        if not text or text.strip() == 'NULL':
            parsed.append(None)
            continue
        try:
            parsed.append(json.loads(text, object_pairs_hook=lambda pairs: pairs))
        except ValueError:
            raise SQLError('Could not read the result from SQL Server.')
    return parsed


def _as_dict(pairs):
    if isinstance(pairs, dict):
        return pairs
    return {k: (_as_dict(v) if isinstance(v, list) and v and isinstance(v[0], tuple) else v) for k, v in pairs}


def records(doc):
    """List of dicts from a FOR JSON document parsed by documents()."""
    return [_as_dict(row) for row in (doc or [])]


def _plain(value):
    """Nested JSON (from dotted aliases or JSON columns) as text."""
    if isinstance(value, list):
        if value and isinstance(value[0], tuple):
            return json.dumps(_as_dict(value), default=str)
        return json.dumps([_as_dict(v) if isinstance(v, list) and v and isinstance(v[0], tuple) else v
                           for v in value], default=str)
    return value


def display_value(value, binary=False):
    value = _plain(value)
    if binary and isinstance(value, str):
        import base64
        import binascii
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raw = None
        if raw is not None:
            return '0x' + raw[:MAX_BINARY].hex().upper() + ('...' if len(raw) > MAX_BINARY else '')
    if isinstance(value, str) and len(value) > MAX_TEXT:
        return value[:MAX_TEXT] + '...'
    return value


def result_table(describe, rows_doc):
    """{'columns', 'rows', 'capped'} from a query's describe document and its FOR JSON rows."""
    described = [c for c in records(describe) if c.get('name') is not None or c.get('type')]
    errors = [c['error_message'] for c in records(describe) if c.get('error_message')]
    rows = rows_doc or []
    names = [k for k, _ in rows[0]] if rows else [c.get('name') for c in described]
    binary = [False] * len(names)
    if not errors and len(described) == len(names):
        binary = [(c.get('type') or '').split('(')[0].lower() in BINARY_TYPES for c in described]
    table = [[display_value(v, binary[i] if i < len(binary) else False) for i, (_, v) in enumerate(row)]
             for row in rows]
    return {'columns': names, 'rows': table, 'capped': len(table) >= ROW_CAP}


def check_size(result):
    if len(json.dumps(result, default=str)) > MAX_OUTPUT_BYTES:
        raise SQLError('The result is larger than 2 MB. Select fewer rows or columns.')
    return result


def capped_runner(argv, stdout=None, stderr=None, universal_newlines=True, timeout=None, env=None,
                  limit=MAX_OUTPUT_BYTES, popen=subprocess.Popen):
    """subprocess.run stand-in that stops reading (and kills sqlcmd) past `limit` bytes of output."""
    import threading
    proc = popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    timer = threading.Timer(timeout or QUERY_TIMEOUT + 15, proc.kill)
    timer.start()
    try:
        data = proc.stdout.read(limit + 1)
        if len(data) > limit:
            proc.kill()
            proc.wait()
            raise SQLError('The result is larger than 2 MB. Select fewer rows or columns.')
        code = proc.wait()
    finally:
        timer.cancel()
        proc.stdout.close()
    if code == -9:
        raise subprocess.TimeoutExpired(argv, timeout)
    return subprocess.CompletedProcess(argv, code, data.decode('utf-8', 'replace'))


def viewer_run(sql, password, database, runner=None):
    try:
        out = sqlcmd(sql, password, runner or capped_runner, database=quote_ident(database)[1:-1],
                     options=VIEWER_FORMAT, timeout=QUERY_TIMEOUT + 15)
    except SQLError as exc:
        # Keep SQL Server's own message, not the marker lines printed before it.
        text = str(exc)
        start = text.rfind('\nMsg ')
        raise SQLError('SQL Server reported an error: ' + text[start + 1:]) if start >= 0 else exc
    return documents(out)
