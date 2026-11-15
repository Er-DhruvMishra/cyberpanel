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
# filter could neither keep a change nor see another database or server-level data. Changes (see
# change_batch) run the same way but commit, one statement at a time.

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
             'WRITETEXT', 'UPDATETEXT', 'READTEXT', 'IF', 'WHILE', 'GOTO', 'RETURN',
             'OPEN', 'CLOSE', 'DEALLOCATE', 'BREAK', 'CONTINUE', 'RECEIVE')
# Statements that start with words too common to refuse alone (column names), and procedure calls.
_PHRASES = (r'\bxp_', r'\bsp_', r'\b(ENABLE|DISABLE)\s+TRIGGER\b', r'\bSEND\s+ON\b', r'\bMOVE\s+CONVERSATION\b',
            r'\bGET\s+CONVERSATION\b', r'\bADD\s+(COUNTER\s+)?SIGNATURE\b', r'\bEND\s+CONVERSATION\b')
_FORBIDDEN_RE = re.compile(r'\b(%s)\b|%s' % ('|'.join(FORBIDDEN), '|'.join(_PHRASES)), re.IGNORECASE)
DML_VERBS = ('INSERT', 'UPDATE', 'DELETE', 'MERGE')
# In change mode INTO (after INSERT/MERGE) and SET (in UPDATE/MERGE) are checked by position instead.
_FORBIDDEN_DML_RE = re.compile(r'\b(%s)\b|%s' % ('|'.join(w for w in FORBIDDEN if w not in DML_VERBS + ('INTO', 'SET')),
                                                 '|'.join(_PHRASES)), re.IGNORECASE)
_DML_START_RE = re.compile(r'^\s*(SELECT|WITH|INSERT|UPDATE|DELETE|MERGE)\b', re.IGNORECASE)
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


def _prepare(sql, start_re, start_message):
    """Checks shared by both query modes; (sql, bare) without the optional trailing ';'."""
    if not isinstance(sql, str) or not sql.strip():
        raise SQLError('Enter a query.')
    if len(sql) > MAX_QUERY_CHARS:
        raise SQLError('The query is longer than %d characters.' % MAX_QUERY_CHARS)
    if '\x00' in sql:
        raise SQLError('Invalid characters in the query.')
    if _SQLCMD_LINE_RE.search(sql):
        raise SQLError('GO and sqlcmd commands (lines starting with : or !!) are not allowed.')
    bare = strip_sql(sql)
    if not start_re.match(bare):
        raise SQLError(start_message)
    trimmed = bare.rstrip()
    if trimmed.endswith(';'):
        cut = len(trimmed) - 1
        sql, bare = sql[:cut] + sql[cut + 1:], bare[:cut] + bare[cut + 1:]
    if ';' in bare:
        raise SQLError('Only a single statement is allowed.')
    if _GO_RE.search(bare):
        raise SQLError('GO is not allowed.')
    return sql, bare


def readonly_query(sql):
    """Validate a read-only query; return it without its optional trailing ';'."""
    sql, bare = _prepare(sql, _START_RE, 'Only a single SELECT (or WITH ... SELECT) query is allowed.')
    found = _FORBIDDEN_RE.search(bare)
    if found:
        raise SQLError('Read-only queries cannot use %s.' % found.group(0).upper())
    return sql


_TOKEN_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_@#$]*|[()]')


def _tokens(bare):
    """[(WORD, depth)] of the words in stripped SQL, with their parenthesis depth."""
    out, depth = [], 0
    for match in _TOKEN_RE.finditer(bare):
        word = match.group(0)
        if word == '(':
            depth += 1
        elif word == ')':
            depth = max(0, depth - 1)
        else:
            out.append((word.upper(), depth))
    return out


def change_query(sql):
    """Validate a query for change mode: one SELECT/WITH or one INSERT, UPDATE, DELETE or MERGE.

    Returns {'sql', 'verb', 'where', 'output'}. T-SQL needs no ';' between statements, so the
    statement's words are checked by position: exactly one data-changing verb (MERGE may also use
    INSERT/UPDATE/DELETE after THEN), INTO only right after INSERT/MERGE, SET only in UPDATE (or after
    MERGE's THEN UPDATE), and no further top-level SELECT that could start a second statement.
    """
    sql, bare = _prepare(sql, _DML_START_RE, 'Only one SELECT, WITH, INSERT, UPDATE, DELETE or MERGE statement is allowed.')
    found = _FORBIDDEN_DML_RE.search(bare)
    if found:
        raise SQLError('Queries cannot use %s.' % found.group(0).upper())
    tokens = _tokens(bare)
    main = next((i for i, (w, d) in enumerate(tokens) if d == 0 and w in ('SELECT',) + DML_VERBS), None)
    if main is None:
        raise SQLError('Only one SELECT, WITH, INSERT, UPDATE, DELETE or MERGE statement is allowed.')
    verb = tokens[main][0]
    if verb == 'SELECT':
        return {'sql': readonly_query(sql), 'verb': 'SELECT', 'where': True, 'output': False}
    single = 'Only one INSERT, UPDATE, DELETE or MERGE statement is allowed.'
    if verb == 'UPDATE' and main + 1 < len(tokens) and tokens[main + 1][0] == 'STATISTICS':
        raise SQLError('UPDATE STATISTICS is not allowed.')
    has_values = any(d == 0 and (w == 'VALUES') for w, d in tokens[main:])
    selects = 0
    for i, (word, depth) in enumerate(tokens):
        before = tokens[i - 1][0] if i else ''
        if word in DML_VERBS and i != main:
            if not (verb == 'MERGE' and depth == 0 and before == 'THEN'):
                raise SQLError(single)
        elif word == 'INTO':
            following = [w for w, d in tokens[main + 1:i] if d == 0]
            if verb not in ('INSERT', 'MERGE') or i < main or any(w not in ('TOP', 'PERCENT') for w in following):
                raise SQLError('INTO is only allowed in INSERT INTO or MERGE INTO.')
        elif word == 'SET':
            if depth or not ((verb == 'UPDATE' and i > main) or (verb == 'MERGE' and before == 'UPDATE' and i >= 2
                                                                 and tokens[i - 2][0] == 'THEN')):
                raise SQLError(single)
        elif word == 'SELECT' and depth == 0 and i > main:
            if verb != 'INSERT' or has_values or (selects and before not in ('UNION', 'ALL', 'EXCEPT', 'INTERSECT')):
                raise SQLError(single)
            selects += 1
    if verb == 'UPDATE' and sum(1 for w, d in tokens if w == 'SET' and d == 0) > 1:
        raise SQLError(single)
    where = any(w == 'WHERE' and d == 0 for w, d in tokens[main:])
    output = any(w == 'OUTPUT' and d == 0 for w, d in tokens[main:])
    return {'sql': sql, 'verb': verb, 'where': where, 'output': output}


def refuse_readonly(sql, refused):
    """Re-raise a read-only refusal, saying when the query would be allowed with "Allow changes"."""
    try:
        info = change_query(sql)
    except SQLError:
        raise refused
    if info['verb'] != 'SELECT':
        raise SQLError('Tick "Allow changes" to run %s statements.' % info['verb'])
    raise refused


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
        "c.max_length, c.precision, c.scale, c.is_nullable AS nullable, ic.key_ordinal AS pk, "
        "c.is_identity AS [identity], c.is_computed AS computed, dc.definition AS [default], "
        "cc.definition AS computed_definition, CAST(idc.seed_value AS nvarchar(40)) AS seed, "
        "CAST(idc.increment_value AS nvarchar(40)) AS increment, c.collation_name AS collation, "
        "CASE o.type WHEN 'U' THEN 'table' ELSE 'view' END AS kind "
        "FROM sys.columns c JOIN sys.objects o ON o.object_id = c.object_id AND o.type IN ('U', 'V') "
        "LEFT JOIN sys.indexes i ON i.object_id = c.object_id AND i.is_primary_key = 1 "
        "LEFT JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
        "AND ic.column_id = c.column_id "
        "LEFT JOIN sys.default_constraints dc ON dc.object_id = c.default_object_id "
        "LEFT JOIN sys.computed_columns cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id "
        "LEFT JOIN sys.identity_columns idc ON idc.object_id = c.object_id AND idc.column_id = c.column_id "
        "WHERE c.object_id = OBJECT_ID(%s) ORDER BY c.column_id" % target)])


def structure_sql(login, schema, table):
    """Indexes, foreign keys (both directions) and size of one table or view."""
    target = 'OBJECT_ID(%s)' % quote_string(object_name(schema, table))
    key_list = ("(SELECT STRING_AGG(CAST(c.name + CASE WHEN ic.is_descending_key = 1 THEN N' DESC' ELSE N'' END "
                "AS nvarchar(max)), N', ') WITHIN GROUP (ORDER BY ic.key_ordinal, ic.index_column_id) "
                "FROM sys.index_columns ic JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id "
                "WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = %d)")
    fk_cols = ("(SELECT STRING_AGG(CAST(COL_NAME(k.%s_object_id, k.%s_column_id) AS nvarchar(max)), N', ') "
               "WITHIN GROUP (ORDER BY k.constraint_column_id) FROM sys.foreign_key_columns k "
               "WHERE k.constraint_object_id = fk.object_id)")
    indexes = _json_doc(
        "SELECT i.name, i.type_desc AS type, i.is_unique AS [unique], i.is_primary_key AS [primary], "
        "i.is_unique_constraint AS unique_constraint, i.is_disabled AS disabled, i.filter_definition AS filter, "
        "%s AS columns, %s AS included, (SELECT SUM(p.used_page_count) * 8 FROM sys.dm_db_partition_stats p "
        "WHERE p.object_id = i.object_id AND p.index_id = i.index_id) AS size_kb "
        "FROM sys.indexes i WHERE i.object_id = %s AND i.type > 0 ORDER BY i.index_id"
        % (key_list % 0, key_list % 1, target))
    foreign = _json_doc(
        "SELECT fk.name, CASE WHEN fk.parent_object_id = %s THEN 'out' ELSE 'in' END AS direction, "
        "OBJECT_SCHEMA_NAME(fk.parent_object_id) AS [schema], OBJECT_NAME(fk.parent_object_id) AS [table], "
        "%s AS columns, OBJECT_SCHEMA_NAME(fk.referenced_object_id) AS ref_schema, "
        "OBJECT_NAME(fk.referenced_object_id) AS ref_table, %s AS ref_columns, "
        "fk.delete_referential_action_desc AS on_delete, fk.update_referential_action_desc AS on_update, "
        "fk.is_disabled AS disabled FROM sys.foreign_keys fk "
        "WHERE fk.parent_object_id = %s OR fk.referenced_object_id = %s ORDER BY direction DESC, fk.name"
        % (target, fk_cols % ('parent', 'parent'), fk_cols % ('referenced', 'referenced'), target, target))
    stats = _json_doc(
        "SELECT o.type_desc AS type, o.create_date AS created, o.modify_date AS modified, "
        "(SELECT SUM(p.row_count) FROM sys.dm_db_partition_stats p WHERE p.object_id = o.object_id "
        "AND p.index_id IN (0, 1)) AS [rows], "
        "(SELECT SUM(p.reserved_page_count) * 8 FROM sys.dm_db_partition_stats p WHERE p.object_id = o.object_id) AS reserved_kb, "
        "(SELECT SUM(p.used_page_count) * 8 FROM sys.dm_db_partition_stats p WHERE p.object_id = o.object_id) AS used_kb, "
        "(SELECT SUM(p.in_row_data_page_count + p.lob_used_page_count + p.row_overflow_used_page_count) * 8 "
        "FROM sys.dm_db_partition_stats p WHERE p.object_id = o.object_id AND p.index_id IN (0, 1)) AS data_kb "
        "FROM sys.objects o WHERE o.object_id = %s" % target)
    return viewer_sql(login, [indexes, foreign, stats])


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


PAGE_SIZES = (25, 50, 100)
MAX_FILTER_CHARS = 200
DATE_TYPES = ('date', 'time', 'datetime', 'datetime2', 'smalldatetime', 'datetimeoffset')
UNSORTABLE = ('text', 'ntext', 'image', 'xml')


def _key_expr(column, alias):
    """A primary-key value exactly as text, so the browser can send it back for edit/delete."""
    q, base = quote_column(column['name']), column.get('base')
    if base in BINARY_TYPES:
        expr = 'CONVERT(varchar(max), CONVERT(varbinary(max), %s), 1)' % q
    elif base in ('float', 'real'):
        expr = 'CONVERT(nvarchar(50), %s, 3)' % q
    elif base in ('money', 'smallmoney'):
        expr = 'CONVERT(nvarchar(50), %s, 2)' % q
    elif base in DATE_TYPES:
        expr = q  # FOR JSON writes ISO 8601 with full precision
    else:
        expr = 'CONVERT(nvarchar(4000), %s)' % q
    return '%s AS [%s]' % (expr, alias)


def _filter_expr(column):
    q, base = quote_column(column['name']), column.get('base')
    if column.get('clr'):
        return '%s.ToString()' % q
    if base in BINARY_TYPES:
        return 'CONVERT(varchar(max), CONVERT(varbinary(max), %s), 1)' % q
    if base in DATE_TYPES:
        return 'CONVERT(nvarchar(max), %s, 121)' % q
    return 'CONVERT(nvarchar(max), %s)' % q


def like_pattern(text):
    """'%text%' with LIKE's wildcards escaped (ESCAPE '\\')."""
    for char in ('\\', '%', '_', '['):
        text = text.replace(char, '\\' + char)
    return '%' + text + '%'


def find_column(columns, name):
    """The column called `name` (exact, as SQL Server reports it), or SQLError."""
    for column in columns:
        if column['name'] == name:
            return column
    raise SQLError('Unknown column %r.' % (name,))


def browse_options(columns, page_size=PAGE_SIZE, sort=None, descending=False, filter_column=None, filter_text=None):
    """Validated (page_size, sort column, descending, filter column, filter text)."""
    if page_size not in PAGE_SIZES or isinstance(page_size, bool):
        raise SQLError('Page size must be 25, 50 or 100.')
    sort_col = None
    if sort not in (None, ''):
        sort_col = find_column(columns, sort)
        if sort_col.get('clr') or sort_col.get('base') in UNSORTABLE:
            raise SQLError('Cannot sort by a %s column.' % sort_col.get('type'))
    filter_col = None
    if filter_text not in (None, ''):
        if not isinstance(filter_text, str) or len(filter_text) > MAX_FILTER_CHARS or '\x00' in filter_text:
            raise SQLError('The filter is at most %d characters.' % MAX_FILTER_CHARS)
        filter_col = find_column(columns, filter_column)
    return page_size, sort_col, descending is True, filter_col, filter_text if filter_col else None


def rows_sql(login, schema, table, columns, page, page_size=PAGE_SIZE, sort=None, descending=False,
             filter_column=None, filter_text=None):
    if not columns:
        raise SQLError('Unknown table.')
    page = int(page)
    if page < 0 or page > 10 ** 7:
        raise SQLError('Invalid page.')
    page_size, sort_col, descending, filter_col, filter_text = browse_options(
        columns, page_size, sort, descending, filter_column, filter_text)
    keys = sorted((c for c in columns if c.get('pk')), key=lambda c: c['pk'])
    order = [quote_column(c['name']) for c in keys if c is not sort_col]
    if sort_col is not None:
        order.insert(0, quote_column(sort_col['name']) + (' DESC' if descending else ''))
    select = [_browse_expr(c, 'c%d' % i) for i, c in enumerate(columns)]
    select += [_key_expr(c, 'k%d' % i) for i, c in enumerate(keys)]
    where = ''
    if filter_col is not None:
        where = " WHERE %s LIKE @f ESCAPE N'\\'" % _filter_expr(filter_col)
    inner = _json_doc('SELECT %s FROM %s%s ORDER BY %s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY'
                      % (', '.join(select), object_name(schema, table), where, ', '.join(order) or '(SELECT NULL)',
                         page * page_size, page_size))
    # The filter text is a typed parameter of sp_executesql, never part of the statement.
    document = 'EXEC sp_executesql %s, N\'@f nvarchar(%d)\', @f = %s;' % (
        quote_string(inner), MAX_FILTER_CHARS * 2 + 2, quote_string(like_pattern(filter_text or '')))
    return viewer_sql(login, [document])


def query_sql(login, sql):
    query = readonly_query(sql)
    describe = _json_doc('SELECT name, system_type_name AS type, error_message FROM '
                         'sys.dm_exec_describe_first_result_set(%s, NULL, 0) ORDER BY column_ordinal'
                         % quote_string(query))
    # The query keeps its own lines; FOR JSON goes on a new line so a trailing -- comment cannot hide it.
    run_query = 'SET ROWCOUNT %d;\n%s\nFOR JSON PATH, INCLUDE_NULL_VALUES;\nSET ROWCOUNT 0;' % (ROW_CAP, query)
    return viewer_sql(login, [describe, run_query])


# ----------------------------------------------------------------------------- changes
#
# Changes (a DML query with "Allow changes", or a row edit) run as one statement as the database's
# own login, inside a transaction that is committed only when the statement succeeded. XACT_ABORT
# makes any error abort the batch and roll back.

def needs_confirmation(info):
    """An UPDATE or DELETE without a top-level WHERE changes every row: the user confirms it explicitly."""
    return info['verb'] in ('UPDATE', 'DELETE') and not info['where']


def change_batch(login, body, commit=True, max_rows=None):
    """Batch running `body` (which sets @ua_n, @ua_d and @ua_j) as the login, then printing the documents."""
    lines = ['SET NOCOUNT ON;', 'SET LOCK_TIMEOUT 5000;', 'SET XACT_ABORT ON;',
             'DECLARE @ua_n bigint, @ua_d nvarchar(max), @ua_j nvarchar(max), @ua_cols nvarchar(max), '
             '@ua_err nvarchar(2048), @ua_run nvarchar(max);',
             'BEGIN TRANSACTION;',
             'EXECUTE AS LOGIN = %s;' % quote_string(quote_ident(login)[1:-1])]
    lines += body
    lines.append('REVERT;')
    if max_rows is not None:
        lines.append("IF @ua_n > %d BEGIN ROLLBACK; THROW 50000, N'More than %d row(s) matched; nothing was changed.', 1; END;"
                     % (max_rows, max_rows))
    lines.append('COMMIT;' if commit else 'ROLLBACK;')
    for doc in ('@ua_d', '@ua_j', '(SELECT @ua_n AS affected FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)'):
        lines += ["SELECT N'%s';" % DOC_MARK, 'SELECT %s;' % doc]
    lines += ["SELECT N'%s';" % END_MARK, 'GO']
    return '\n'.join(lines) + '\n'


def dml_sql(login, sql, commit=True):
    """Batch for one INSERT/UPDATE/DELETE/MERGE from the query box.

    Without OUTPUT the statement runs through sp_executesql and @@ROWCOUNT is read right after it.
    With OUTPUT its result set is captured with INSERT ... EXEC into a temporary table whose
    columns SQL Server itself describes, then returned as one FOR JSON document.
    """
    info = change_query(sql)
    if info['verb'] == 'SELECT':
        raise SQLError('Not a data-changing statement.')
    # The statement keeps its own lines; ';' goes on a new line (a trailing -- comment cannot hide it,
    # and MERGE must be terminated).
    body = ['DECLARE @ua_q nvarchar(max) = %s;' % quote_string(info['sql'] + '\n;')]
    if not info['output']:
        body += ["SET @ua_run = @ua_q + N' SET @ua_rc = @@ROWCOUNT;';",
                 "EXEC sp_executesql @ua_run, N'@ua_rc bigint OUTPUT', @ua_rc = @ua_n OUTPUT;"]
        return change_batch(login, body, commit)
    body += [
        "SELECT @ua_cols = STRING_AGG(CAST(N'[c' + CAST(column_ordinal AS nvarchar(10)) + N'] ' + "
        "CASE WHEN system_type_name IN (N'timestamp', N'rowversion') THEN N'binary(8)' ELSE system_type_name END "
        "+ N' NULL' AS nvarchar(max)), N', ') WITHIN GROUP (ORDER BY column_ordinal), @ua_err = MAX(error_message) "
        "FROM sys.dm_exec_describe_first_result_set(@ua_q, NULL, 0);",
        "SET @ua_d = (SELECT name, system_type_name AS type FROM sys.dm_exec_describe_first_result_set(@ua_q, NULL, 0) "
        "WHERE error_message IS NULL ORDER BY column_ordinal FOR JSON PATH, INCLUDE_NULL_VALUES);",
        "IF @ua_err IS NOT NULL OR @ua_cols IS NULL BEGIN SET @ua_err = ISNULL(@ua_err, N'Could not read the OUTPUT "
        "columns.'); THROW 50000, @ua_err, 1; END;",
        "SET @ua_run = N'CREATE TABLE #ua_out (' + @ua_cols + N'); INSERT INTO #ua_out EXEC sp_executesql @q; "
        "SET @n = @@ROWCOUNT; SET @j = (SELECT TOP (%d) * FROM #ua_out FOR JSON PATH, INCLUDE_NULL_VALUES);';" % ROW_CAP,
        "EXEC sp_executesql @ua_run, N'@q nvarchar(max), @n bigint OUTPUT, @j nvarchar(max) OUTPUT', "
        "@q = @ua_q, @n = @ua_n OUTPUT, @j = @ua_j OUTPUT;",
    ]
    return change_batch(login, body, commit)


def change_result(docs, verb):
    """{'verb', 'affected', 'columns', 'rows', 'capped'} from the three documents of change_batch()."""
    if len(docs) != 3:
        raise SQLError('Could not read the result from SQL Server.')
    describe, rows_doc, count = docs
    # {"affected": n} parsed as pairs; {} when nothing ran
    count = dict(count) if isinstance(count, list) and all(isinstance(p, tuple) for p in count) else {}
    described = records(describe)
    names = [c.get('name') or '(no name)' for c in described]
    binary = [(c.get('type') or '').split('(')[0].lower() in BINARY_TYPES for c in described]
    rows = []
    for row in rows_doc or []:
        values = dict(row)
        rows.append([display_value(values.get('c%d' % (i + 1)), binary[i]) for i in range(len(names))])
    affected = count.get('affected')
    return {'verb': verb, 'affected': affected, 'columns': names, 'rows': rows,
            'capped': bool(names) and isinstance(affected, int) and affected > ROW_CAP, 'committed': True}


# ----------------------------------------------------------------------------- row editing

INT_RANGES = {'tinyint': (0, 255), 'smallint': (-2 ** 15, 2 ** 15 - 1), 'int': (-2 ** 31, 2 ** 31 - 1),
              'bigint': (-2 ** 63, 2 ** 63 - 1)}
STRING_TYPES = ('char', 'varchar', 'nchar', 'nvarchar', 'text', 'ntext', 'xml', 'sql_variant', 'sysname')
_DECIMAL_RE = re.compile(r'^[+-]?(\d+(\.\d*)?|\.\d+)$')
_FLOAT_RE = re.compile(r'^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$')
_DATE_RE = re.compile(r'^[0-9A-Za-z :.,/+-]{1,40}$')
_GUID_RE = re.compile(r'^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$')
_HEX_RE = re.compile(r'^0x([0-9A-Fa-f]{2})*$')
MAX_ROW_CHARS = 256 * 1024


def param_type(column):
    """The sp_executesql parameter type for a column, or None if the panel cannot edit it."""
    base, length = column.get('base'), column.get('max_length')
    if column.get('clr') or base in ('timestamp', 'rowversion', 'hierarchyid', 'geometry', 'geography') or not base:
        return None
    if base in ('char', 'varchar', 'binary', 'varbinary'):
        return '%s(%s)' % (base, 'max' if length == -1 else length)
    if base in ('nchar', 'nvarchar', 'sysname'):
        return '%s(%s)' % ('nvarchar' if base == 'sysname' else base, 'max' if length == -1 else length // 2)
    if base in ('decimal', 'numeric'):
        return '%s(%d,%d)' % (base, column.get('precision') or 18, column.get('scale') or 0)
    if base in ('datetime2', 'time', 'datetimeoffset'):
        return '%s(%d)' % (base, column.get('scale') if column.get('scale') is not None else 7)
    if base in ('text', 'ntext', 'image'):
        return {'text': 'varchar(max)', 'ntext': 'nvarchar(max)', 'image': 'varbinary(max)'}[base]
    if base in ('int', 'bigint', 'smallint', 'tinyint', 'bit', 'float', 'real', 'money', 'smallmoney', 'date',
                'datetime', 'smalldatetime', 'uniqueidentifier', 'xml', 'sql_variant'):
        return base
    return None


def editable(column):
    return not column.get('identity') and not column.get('computed') and param_type(column) is not None


def char_limit(column):
    """Maximum characters (or bytes for binary) a column holds, None for (max)."""
    base, length = column.get('base'), column.get('max_length')
    if length == -1 or base in ('text', 'ntext', 'image', 'xml', 'sql_variant'):
        return None
    if base in ('nchar', 'nvarchar', 'sysname'):
        return length // 2
    if base in ('char', 'varchar', 'binary', 'varbinary'):
        return length
    return None


def value_literal(column, value):
    """SQL literal for one parameter value, after checking it against the column's type."""
    name, base = column['name'], column.get('base')
    if value is None:
        if not column.get('nullable'):
            raise SQLError('%s cannot be NULL.' % name)
        return 'NULL'
    if isinstance(value, bool):
        if base != 'bit':
            raise SQLError('Invalid value for %s.' % name)
        value = '1' if value else '0'
    elif isinstance(value, (int, float)):
        value = repr(value)
    if not isinstance(value, str):
        raise SQLError('Invalid value for %s.' % name)
    if '\x00' in value:
        raise SQLError('%s: NUL characters are not allowed.' % name)
    limit = char_limit(column)
    bad = None
    if base in BINARY_TYPES:
        if not _HEX_RE.match(value):
            bad = 'a hex value such as 0x0A1B'
        elif limit is not None and (len(value) - 2) // 2 > limit:
            raise SQLError('%s holds at most %d bytes.' % (name, limit))
        else:
            return value  # a validated binary literal (nvarchar does not convert to varbinary implicitly)
    elif base in INT_RANGES:
        low, high = INT_RANGES[base]
        if not re.match(r'^[+-]?\d{1,20}$', value.strip()) or not low <= int(value) <= high:
            bad = 'a whole number from %d to %d' % (low, high)
    elif base == 'bit':
        mapped = {'1': '1', '0': '0', 'true': '1', 'false': '0'}.get(value.strip().lower())
        if mapped is None:
            bad = '0 or 1'
        value = mapped or value
    elif base in ('decimal', 'numeric', 'money', 'smallmoney'):
        if not _DECIMAL_RE.match(value.strip()):
            bad = 'a number such as 12.50'
        elif base in ('decimal', 'numeric'):
            whole = value.strip().lstrip('+-').split('.')[0].lstrip('0')
            precision, scale = column.get('precision') or 18, column.get('scale') or 0
            if len(whole) > precision - scale:
                bad = 'a number with at most %d digits before the decimal point' % (precision - scale)
    elif base in ('float', 'real'):
        if not _FLOAT_RE.match(value.strip()):
            bad = 'a number such as 1.5 or 2e10'
    elif base in DATE_TYPES:
        if not _DATE_RE.match(value.strip()):
            bad = 'a date/time such as 2024-01-31 or 2024-01-31T13:45:00'
    elif base == 'uniqueidentifier':
        if not _GUID_RE.match(value.strip()):
            bad = 'a GUID such as 6F9619FF-8B86-D011-B42D-00C04FC964FF'
    elif base in STRING_TYPES:
        if limit is not None and len(value) > limit:
            raise SQLError('%s holds at most %d characters.' % (name, limit))
        return quote_string(value)
    else:
        raise SQLError('%s cannot be edited here.' % name)
    if bad:
        raise SQLError('%s must be %s.' % (name, bad))
    return quote_string(value.strip())


def _primary_key(columns):
    keys = sorted((c for c in columns if c.get('pk')), key=lambda c: c['pk'])
    if not keys or columns[0].get('kind', 'table') != 'table':
        raise SQLError('Rows can only be changed in tables with a primary key.')
    for column in keys:
        if param_type(column) is None:
            raise SQLError('Rows of this table cannot be changed here (primary key of type %s).' % column.get('type'))
    return keys


def _key_condition(keys, key, params):
    if not isinstance(key, dict) or set(key) != {c['name'] for c in keys}:
        raise SQLError('The row is identified by its full primary key.')
    parts = []
    for i, column in enumerate(keys):
        if key[column['name']] is None:
            raise SQLError('Primary key values cannot be NULL.')
        params.append(('@k%d' % i, param_type(column), value_literal(column, key[column['name']])))
        parts.append('%s = @k%d' % (quote_column(column['name']), i))
    return ' AND '.join(parts)


def _check_size(values):
    total = sum(len(v) for v in values.values() if isinstance(v, str)) + sum(len(k) for k in values)
    if total > MAX_ROW_CHARS:
        raise SQLError('The row is larger than %d KB.' % (MAX_ROW_CHARS // 1024))


def row_statement(action, schema, table, columns, key=None, values=None):
    """(statement, [(name, type, literal)]) for one parameterised row change.

    Column names are checked against the table's own columns; every value becomes a typed
    sp_executesql parameter, so values are never part of the statement text.
    """
    target, params = object_name(schema, table), []
    values = {} if values is None else values
    if not isinstance(values, dict):
        raise SQLError('Invalid row values.')
    _check_size(values)
    if action == 'insert':
        if not columns or columns[0].get('kind', 'table') != 'table':
            raise SQLError('Rows can only be inserted into tables.')
        for name in values:
            find_column(columns, name)
        names = []
        for column in columns:
            if column['name'] not in values or not editable(column):
                continue  # identity, computed and rowversion columns are filled in by SQL Server
            value = values[column['name']]
            if value == '':
                continue  # empty field: the column's default
            params.append(('@p%d' % len(names), param_type(column), value_literal(column, value)))
            names.append(quote_column(column['name']))
        if not names:
            return 'INSERT INTO %s DEFAULT VALUES;' % target, params
        return ('INSERT INTO %s (%s) VALUES (%s);' % (target, ', '.join(names),
                                                       ', '.join(p[0] for p in params)), params)
    keys = _primary_key(columns)
    if action == 'delete':
        return 'DELETE FROM %s WHERE %s;' % (target, _key_condition(keys, key, params)), params
    if action != 'update':
        raise SQLError('Invalid action.')
    if not values:
        raise SQLError('Nothing was changed.')
    sets = []
    for i, name in enumerate(sorted(values)):
        column = find_column(columns, name)
        if not editable(column):
            raise SQLError('%s cannot be changed (identity, computed or unsupported type).' % name)
        params.append(('@p%d' % i, param_type(column), value_literal(column, values[name])))
        sets.append('%s = @p%d' % (quote_column(name), i))
    condition = _key_condition(keys, key, params)
    return 'UPDATE %s SET %s WHERE %s;' % (target, ', '.join(sets), condition), params


def row_sql(login, schema, table, columns, action, key=None, values=None):
    """Committed batch for one row change; refused (and rolled back) if more than one row matched."""
    statement, params = row_statement(action, schema, table, columns, key, values)
    declare = ', '.join(['%s %s' % (name, kind) for name, kind, _ in params] + ['@ua_rc bigint OUTPUT'])
    assign = ', '.join(['%s = %s' % (name, literal) for name, _, literal in params] + ['@ua_rc = @ua_n OUTPUT'])
    body = ['EXEC sp_executesql %s, %s, %s;' % (quote_string(statement + ' SET @ua_rc = @@ROWCOUNT;'),
                                                quote_string(declare), assign)]
    return change_batch(login, body, commit=True, max_rows=1)


# ----------------------------------------------------------------------------- export

def _cell_text(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return '1' if value else '0'
    if isinstance(value, list):
        return _plain(value)
    if isinstance(value, dict):
        return json.dumps(value, default=str, ensure_ascii=False)
    return str(value)


def _csv_safe(text):
    """Spreadsheets run cells starting with = + - @ (or tab/CR) as formulas; prefix a quote so
    exported data opens as text (CSV injection). Plain negative numbers are left alone."""
    if text and text[0] in '=+-@\t\r':
        try:
            float(text)
            return text
        except ValueError:
            return "'" + text
    return text


def to_csv(columns, rows):
    """RFC 4180 CSV with a UTF-8 BOM (so Excel reads it as UTF-8) and CRLF line ends."""
    import csv
    import io
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator='\r\n')
    writer.writerow([_csv_safe(_cell_text(c)) for c in columns])
    for row in rows:
        writer.writerow([_csv_safe(_cell_text(v)) for v in row])
    return '﻿' + buffer.getvalue()


def to_json(columns, rows):
    """A JSON array of objects; repeated column names get a _2, _3 ... suffix."""
    names, seen = [], {}
    for column in columns:
        column = str(column)
        seen[column] = seen.get(column, 0) + 1
        names.append(column if seen[column] == 1 else '%s_%d' % (column, seen[column]))
    return json.dumps([dict(zip(names, row)) for row in rows], ensure_ascii=False, indent=1, default=str)


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
