"""MySQL Manager: status, process list, tuning advisor and upgrade readiness for MariaDB/MySQL.

A free, independent replacement for the panel's licence-gated MySQL Manager / Optimizer /
Upgrade pages. Everything in this file is pure logic (parsing, maths, rendering, validation)
so it can be unit-tested; actions.py does the root-side I/O.

Safety rules
- SQL text is fixed. The only values ever placed into SQL are thread ids (Python ints).
- Tuning is written ONLY to a dedicated drop-in in the server's include directory
  (zz-cyberpanel-tuning.cnf), every value is checked against SPEC, and the previous drop-in is
  kept as a timestamped backup so "Revert" can restore it.
- Applying tuning never restarts the server. Restart is a separate action that first checks
  the configuration with `mysqld --help --verbose` (MariaDB has no --validate-config) and
  refuses to restart on any error.
- Kill refuses system/replication threads, the runner's own connection and the panel's own
  database user.
"""
import math
import re

KB, MB, GB = 1024, 1024 ** 2, 1024 ** 3
SYSTEM_SCHEMAS = ('mysql', 'information_schema', 'performance_schema', 'sys')
DROPIN_NAME = 'zz-cyberpanel-tuning.cnf'
MIN_UPTIME = 6 * 3600   # counter-based advice is tentative before this much uptime
SPLIT = '@@UA-SPLIT@@'


class MySQLError(ValueError):
    pass


# ----------------------------------------------------------------------------- query output

def parse_rows(text):
    """mysql -N -B output -> list of column lists."""
    return [line.split('\t') for line in (text or '').splitlines() if line.strip()]


def multi_sql(statements):
    """Join statements with marker rows so one connection returns several result sets."""
    marker = "SELECT '%s', ''" % SPLIT
    return (';\n%s;\n' % marker).join(statements)


def split_results(rows, count):
    sets, current = [], []
    for row in rows:
        if row and row[0] == SPLIT:
            sets.append(current)
            current = []
        else:
            current.append(row)
    sets.append(current)
    if len(sets) != count:
        raise MySQLError('Unexpected output from the MySQL client.')
    return sets


def as_dict(rows):
    return {r[0]: (r[1] if len(r) > 1 else '') for r in rows}


def num(data, name, default=0):
    try:
        return float(data.get(name, default))
    except (TypeError, ValueError):
        return default


def parse_version(text):
    """'10.3.28-MariaDB' -> ('MariaDB', (10, 3, 28))."""
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)', text or '')
    if not match:
        return 'unknown', (0, 0, 0)
    flavour = 'MariaDB' if 'mariadb' in (text or '').lower() else 'MySQL'
    return flavour, tuple(int(x) for x in match.groups())


# ----------------------------------------------------------------------------- sizes

_SIZE = re.compile(r'^\s*(\d{1,13})\s*([KMG]?)B?\s*$', re.I)


def parse_size(value):
    if isinstance(value, bool):
        raise MySQLError('Invalid size.')
    if isinstance(value, int):
        return value
    match = _SIZE.match(str(value))
    if not match:
        raise MySQLError('Invalid size "%s" (use a number with K, M or G).' % value)
    return int(match.group(1)) * {'': 1, 'K': KB, 'M': MB, 'G': GB}[match.group(2).upper()]


def fmt_size(value):
    value = int(value)
    for unit, size in (('G', GB), ('M', MB), ('K', KB)):
        if value and value % size == 0:
            return '%d%s' % (value // size, unit)
    return str(value)


def human(value):
    value = float(value or 0)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(value) < 1024:
            return ('%.0f %s' if unit in ('B', 'KB') else '%.1f %s') % (value, unit)
        value /= 1024
    return '%.1f TB' % value


def round_up(value, step):
    return int(math.ceil(float(value) / step) * step)


def round_down(value, step):
    return int(value // step * step)


# ----------------------------------------------------------------------------- host facts

def parse_meminfo(text):
    fields = {}
    for line in (text or '').splitlines():
        parts = line.replace(':', ' ').split()
        if len(parts) >= 2 and parts[1].isdigit():
            fields[parts[0]] = int(parts[1]) * KB
    total = fields.get('MemTotal', 0)
    return {'total': total, 'available': fields.get('MemAvailable', fields.get('MemFree', 0)),
            'swap_total': fields.get('SwapTotal', 0), 'swap_free': fields.get('SwapFree', 0)}


def parse_vmstat_oom(text):
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == 'oom_kill' and parts[1].isdigit():
            return int(parts[1])
    return 0


def memory_pressure(mem):
    reasons = []
    total = mem.get('total') or 1
    if mem.get('swap_total') and (mem['swap_total'] - mem.get('swap_free', 0)) > 0.5 * mem['swap_total']:
        reasons.append('swap is %d%% used' % round(100.0 * (mem['swap_total'] - mem.get('swap_free', 0)) /
                                                     mem['swap_total']))
    if mem.get('available', total) < 0.15 * total:
        reasons.append('only %s of %s RAM is available' % (human(mem.get('available')), human(total)))
    if mem.get('oom_kills'):
        reasons.append('the kernel has killed %d process(es) for lack of memory since boot' % mem['oom_kills'])
    return reasons


# ----------------------------------------------------------------------------- dashboard

def metrics(v, s):
    uptime = max(num(s, 'Uptime'), 1)
    flavour, version = parse_version(v.get('version', ''))
    pages_total = num(s, 'Innodb_buffer_pool_pages_total')
    pages_free = num(s, 'Innodb_buffer_pool_pages_free')
    read_requests = num(s, 'Innodb_buffer_pool_read_requests')
    tmp_tables = num(s, 'Created_tmp_tables')
    opened = num(s, 'Opened_tables')
    return {
        'version': v.get('version', ''), 'flavour': flavour, 'version_tuple': list(version),
        'uptime': int(uptime),
        'connections': int(num(s, 'Threads_connected')), 'running': int(num(s, 'Threads_running')),
        'max_connections': int(num(v, 'max_connections')), 'peak_connections': int(num(s, 'Max_used_connections')),
        'qps': round(num(s, 'Questions') / uptime, 2), 'slow_queries': int(num(s, 'Slow_queries')),
        'slow_log': v.get('slow_query_log', 'OFF'), 'long_query_time': v.get('long_query_time', ''),
        'buffer_pool_bytes': int(num(v, 'innodb_buffer_pool_size')),
        'buffer_pool_used': round((pages_total - pages_free) / pages_total, 4) if pages_total else None,
        'buffer_pool_hit': round(1 - num(s, 'Innodb_buffer_pool_reads') / read_requests, 4) if read_requests else None,
        'tmp_tables': int(tmp_tables), 'tmp_disk_tables': int(num(s, 'Created_tmp_disk_tables')),
        'tmp_disk_ratio': round(num(s, 'Created_tmp_disk_tables') / tmp_tables, 4) if tmp_tables else None,
        'open_tables': int(num(s, 'Open_tables')), 'opened_tables': int(opened),
        'table_open_cache': int(num(v, 'table_open_cache')),
        'table_cache_efficiency': round(min(num(s, 'Open_tables') / opened, 1), 4) if opened else None,
        'opened_tables_per_hour': round(opened / uptime * 3600, 1),
        'aborted_connects': int(num(s, 'Aborted_connects')), 'aborted_clients': int(num(s, 'Aborted_clients')),
        'force_recovery': int(num(v, 'innodb_force_recovery')),
    }


def database_rows(rows):
    """Rows of (schema, tables, bytes, free) -> sorted dicts."""
    out = []
    for row in rows:
        if len(row) < 4:
            continue
        out.append({'name': row[0], 'tables': int(num({'x': row[1]}, 'x')), 'bytes': int(num({'x': row[2]}, 'x')),
                    'free_bytes': int(num({'x': row[3]}, 'x')), 'system': row[0] in SYSTEM_SCHEMAS})
    return sorted(out, key=lambda d: (d['system'], -d['bytes']))


def datadir_summary(files):
    """(db, file, bytes) from the datadir -> ({'InnoDB': {...}, 'MyISAM': {...}}, table count).

    Used by the advisor instead of information_schema.tables, which would open every table and
    distort the very table-cache counters being analysed. InnoDB bytes are .ibd file sizes (they
    include free space, so they slightly overstate the data); ibdata1 is not counted."""
    innodb = {'tables': 0, 'bytes': 0, 'index_bytes': 0}
    myisam = {'tables': 0, 'bytes': 0, 'index_bytes': 0}
    tables = 0
    for db, name, size in files:
        if db in ('performance_schema',) or name.startswith('#sql'):
            continue
        if name.endswith('.frm'):
            tables += 1
        elif name.endswith('.ibd'):
            innodb['tables'] += 1
            innodb['bytes'] += size
        elif name.endswith('.MYI'):
            myisam['tables'] += 1
            myisam['index_bytes'] += size
            myisam['bytes'] += size
        elif name.endswith('.MYD'):
            myisam['bytes'] += size
    return {'InnoDB': innodb, 'MyISAM': myisam}, tables


# ----------------------------------------------------------------------------- memory estimate

PER_THREAD = ('sort_buffer_size', 'join_buffer_size', 'read_buffer_size', 'read_rnd_buffer_size', 'thread_stack',
              'binlog_cache_size', 'net_buffer_length')
GLOBAL_BUFFERS = ('innodb_buffer_pool_size', 'key_buffer_size', 'query_cache_size', 'aria_pagecache_buffer_size',
                  'innodb_log_buffer_size')


def memory_estimate(v, s, overrides=None):
    merged = dict(v, **{k: str(parse_size(x)) for k, x in (overrides or {}).items() if k in GLOBAL_BUFFERS + PER_THREAD
                         or k == 'max_connections'})
    global_bytes = sum(num(merged, k) for k in GLOBAL_BUFFERS)
    per_thread = sum(num(merged, k) for k in PER_THREAD)
    return {'global': int(global_bytes), 'per_thread': int(per_thread),
            'at_peak': int(global_bytes + per_thread * max(num(s, 'Max_used_connections'), 1)),
            'worst_case': int(global_bytes + per_thread * num(merged, 'max_connections'))}


# ----------------------------------------------------------------------------- advisor

def _rec(out, variable, current, recommended, level, reason, optional=False, tentative=False, applicable=True):
    out.append({'variable': variable, 'current': current, 'recommended': recommended, 'level': level,
                'reason': reason, 'optional': optional, 'tentative': tentative,
                'applicable': applicable and recommended is not None and level == 'change'})


def buffer_pool_ceiling(total_ram):
    """Share of RAM InnoDB may take on a shared web/mail host (not a dedicated DB server)."""
    if total_ram <= 4 * GB:
        return 0.25 * total_ram
    if total_ram <= 16 * GB:
        return 0.4 * total_ram
    return 0.5 * total_ram


def advise(v, s, mem, engines, total_tables, datadir_fs='ext4'):
    """Return {'recommendations': [...], 'notes': [...], 'pressure': [...]}.

    v/s: SHOW GLOBAL VARIABLES/STATUS as dicts. mem: parse_meminfo() plus 'oom_kills'.
    engines: datadir_summary()[0]. total_tables: number of .frm files (all schemas).
    """
    recs, notes = [], []
    uptime = num(s, 'Uptime')
    tentative = uptime < MIN_UPTIME
    total_ram = mem.get('total') or 1
    pressure = memory_pressure(mem)
    flavour, version = parse_version(v.get('version', ''))
    innodb_bytes = engines.get('InnoDB', {}).get('bytes', 0)
    if tentative:
        notes.append('MySQL has been running for only %s; advice based on activity counters is marked tentative. '
                     'Check again after a day of normal traffic.' % _duration(uptime))
    if pressure:
        notes.append('Memory is short (%s). The advisor will not raise any memory setting and suggests ways to free '
                     'memory instead.' % '; '.join(pressure))

    # innodb_force_recovery: an emergency setting, not tuning
    force = int(num(v, 'innodb_force_recovery'))
    if force:
        _rec(recs, 'innodb_force_recovery', str(force), '0', 'critical',
             'InnoDB is running in forced-recovery mode %d. This is meant only for rescuing data after corruption: '
             'from level 2 the purge thread is stopped (undo history and ibdata1 grow without limit), from 3 '
             'transactions are not rolled back after a crash, and 4 or more make InnoDB read-only. Check the error '
             'log, dump or verify the affected tables, then delete the line from the file shown below and restart. '
             'The tuning drop-in cannot override it when it is set later in /etc/my.cnf.' % force, applicable=False)

    # innodb_buffer_pool_size
    current_bp = int(num(v, 'innodb_buffer_pool_size'))
    chunk = int(num(v, 'innodb_buffer_pool_chunk_size', 128 * MB)) or 128 * MB
    step = chunk * max(int(num(v, 'innodb_buffer_pool_instances', 1)), 1)
    ceiling = round_down(buffer_pool_ceiling(total_ram), step)
    wanted = round_up(max(innodb_bytes * 1.2, step), step)
    target = max(min(wanted, ceiling), step)
    hit = num(s, 'Innodb_buffer_pool_reads') / num(s, 'Innodb_buffer_pool_read_requests', 1) if \
        num(s, 'Innodb_buffer_pool_read_requests') else 0
    planned_bp = current_bp
    if pressure and target > current_bp:
        _rec(recs, 'innodb_buffer_pool_size', fmt_size(current_bp), None, 'warn',
             'InnoDB data and indexes total %s, so up to %s would help (miss rate %.1f%%), but there is no spare '
             'memory. Free memory first (see the other suggestions), then raise it.' % (
                 human(innodb_bytes), fmt_size(target), hit * 100), tentative=tentative)
    elif target > current_bp * 1.1 or target < current_bp * 0.9 and current_bp > ceiling:
        planned_bp = target
        _rec(recs, 'innodb_buffer_pool_size', fmt_size(current_bp), fmt_size(target), 'change',
             'InnoDB data and indexes total %s; a shared web server should give InnoDB at most ~%d%% of its %s RAM '
             '(%s). Rounded to the %s chunk size.' % (human(innodb_bytes), round(100 * buffer_pool_ceiling(total_ram) /
                                                                                 total_ram), human(total_ram),
                                                      fmt_size(ceiling), fmt_size(step)))
    else:
        _rec(recs, 'innodb_buffer_pool_size', fmt_size(current_bp), None, 'ok',
             'Fits the %s of InnoDB data within this server\'s memory budget.' % human(innodb_bytes))

    if current_bp < GB and num(v, 'innodb_buffer_pool_instances', 1) > 1 and version < (10, 5, 0):
        _rec(recs, 'innodb_buffer_pool_instances', v.get('innodb_buffer_pool_instances'), '1', 'change',
             'Several buffer pool instances only help with pools of several GB.')

    # key_buffer_size (MyISAM index cache, allocated at startup)
    key_buffer = int(num(v, 'key_buffer_size'))
    myisam_index = engines.get('MyISAM', {}).get('index_bytes', 0)
    key_target = max(8 * MB, round_up(myisam_index * 1.5, 8 * MB))
    if key_buffer > 2 * key_target and key_buffer - key_target >= 16 * MB:
        _rec(recs, 'key_buffer_size', fmt_size(key_buffer), fmt_size(key_target), 'change',
             'Only %s of MyISAM indexes exist (%d MyISAM tables); shrinking the key cache frees %s of RAM.' % (
                 human(myisam_index), engines.get('MyISAM', {}).get('tables', 0), human(key_buffer - key_target)))
    else:
        _rec(recs, 'key_buffer_size', fmt_size(key_buffer), None, 'ok', 'Matches the MyISAM index size.')

    # query cache (removed in MySQL 8)
    if 'query_cache_type' in v:
        qc_type = v.get('query_cache_type', 'OFF').upper()
        qc_size = int(num(v, 'query_cache_size'))
        hits, inserts = num(s, 'Qcache_hits'), num(s, 'Qcache_inserts')
        lookups = hits + inserts + num(s, 'Qcache_not_cached')
        if qc_type in ('ON', '1', 'DEMAND', '2'):
            ratio = hits / lookups if lookups else 0
            if lookups >= 1000 and (ratio < 0.2 or num(s, 'Qcache_lowmem_prunes') > inserts * 0.5):
                _rec(recs, 'query_cache_type', qc_type, 'OFF', 'change',
                     'The query cache answers only %.0f%% of cacheable queries and serialises every write behind a '
                     'global lock; it is usually slower than no cache with InnoDB.' % (ratio * 100), tentative=tentative)
                _rec(recs, 'query_cache_size', fmt_size(qc_size), '0', 'change', 'Frees the cache memory once it is off.')
            else:
                _rec(recs, 'query_cache_type', qc_type, None, 'ok', 'The query cache is earning its keep '
                     '(%.0f%% hit rate).' % (ratio * 100), tentative=tentative or lookups < 1000)
        elif qc_size > 0:
            _rec(recs, 'query_cache_size', fmt_size(qc_size), '0', 'change',
                 'The query cache is off (the right choice on %s) but %s is still reserved for it; size 0 also '
                 'removes the query-cache mutex.' % (v.get('version', 'this server'), human(qc_size)), optional=True)
        else:
            _rec(recs, 'query_cache_type', qc_type, None, 'ok', 'The query cache is disabled.')

    # tmp_table_size / max_heap_table_size
    tmp, heap = int(num(v, 'tmp_table_size')), int(num(v, 'max_heap_table_size'))
    created, on_disk = num(s, 'Created_tmp_tables'), num(s, 'Created_tmp_disk_tables')
    ratio = on_disk / created if created else 0
    limit = min(tmp, heap)
    if tmp != heap:
        both = fmt_size(max(tmp, heap) if not pressure else limit)
        for name, value in (('tmp_table_size', tmp), ('max_heap_table_size', heap)):
            _rec(recs, name, fmt_size(value), both, 'change' if fmt_size(value) != both else 'ok',
                 'In-memory temporary tables are limited by the smaller of tmp_table_size and max_heap_table_size, '
                 'so they should be equal.')
    elif created >= 1000 and ratio > 0.25 and not pressure and limit < 64 * MB:
        new = fmt_size(min(limit * 2, 64 * MB, round_down(total_ram * 0.01, MB) or MB))
        for name in ('tmp_table_size', 'max_heap_table_size'):
            _rec(recs, name, fmt_size(limit), new, 'change',
                 '%.0f%% of temporary tables went to disk. Note: queries that sort TEXT/BLOB columns always use disk; '
                 'raising the limit only helps the rest.' % (ratio * 100), tentative=tentative)
    else:
        _rec(recs, 'tmp_table_size', fmt_size(tmp), None, 'ok',
             '%.0f%% of %d temporary tables went to disk.' % (ratio * 100, created), tentative=tentative)

    # table_open_cache / table_definition_cache
    toc, open_tables, opened = num(v, 'table_open_cache'), num(s, 'Open_tables'), num(s, 'Opened_tables')
    per_hour = opened / max(uptime, 1) * 3600
    files_cap = max(int(num(v, 'open_files_limit', 0) / 2), 400) if num(v, 'open_files_limit') else 65536
    if open_tables >= 0.9 * toc and per_hour > 100:
        new = int(min(max(round_up(total_tables * 1.2, 100), toc * 2), files_cap, 65536))
        if new > toc:
            _rec(recs, 'table_open_cache', str(int(toc)), str(new), 'change',
                 'The cache is full (%d of %d) and %.0f tables per hour are being reopened.' % (open_tables, toc, per_hour),
                 tentative=tentative)
    else:
        _rec(recs, 'table_open_cache', str(int(toc)), None, 'ok',
             '%d of %d slots in use; %.0f tables reopened per hour.' % (open_tables, toc, per_hour), tentative=tentative)
    tdc = num(v, 'table_definition_cache')
    if total_tables > tdc:
        new = int(min(round_up(total_tables * 1.1, 100), 20000))
        _rec(recs, 'table_definition_cache', str(int(tdc)), str(new), 'change',
             'There are %d tables but only %d table definitions are cached, so definitions are re-read from disk. '
             'Costs roughly %s of RAM.' % (total_tables, tdc, human((new - tdc) * 4 * KB)),
             optional=bool(pressure))
    else:
        _rec(recs, 'table_definition_cache', str(int(tdc)), None, 'ok', 'Holds all %d tables.' % total_tables)

    # innodb_log_file_size
    files = max(int(num(v, 'innodb_log_files_in_group', 1)), 1) if version < (10, 5, 0) or flavour != 'MariaDB' else 1
    log_size = int(num(v, 'innodb_log_file_size'))
    hourly = num(s, 'Innodb_os_log_written') / max(uptime, 1) * 3600
    want_total = max(hourly if not tentative else 0, planned_bp * 0.25, 48 * MB * files)
    want = round_up(min(want_total / files, 2 * GB), 16 * MB)
    if want > log_size * 1.5 and not force:
        _rec(recs, 'innodb_log_file_size', fmt_size(log_size), fmt_size(want), 'change',
             'The redo log (%d x %s) holds less than an hour of writes (%s/h); a larger log means fewer checkpoint '
             'flushes. The new size takes effect after a clean restart.' % (files, fmt_size(log_size), human(hourly)),
             tentative=tentative)
    elif want > log_size * 1.5:
        _rec(recs, 'innodb_log_file_size', fmt_size(log_size), None, 'warn',
             'A larger redo log would help, but do not resize it while innodb_force_recovery is set.')
    else:
        _rec(recs, 'innodb_log_file_size', fmt_size(log_size), None, 'ok',
             '%d x %s for %s of redo per hour.' % (files, fmt_size(log_size), human(hourly)), tentative=tentative)

    # max_connections
    max_conn, peak = num(v, 'max_connections'), num(s, 'Max_used_connections')
    if peak >= 0.85 * max_conn:
        new = round_up(peak * 1.5, 10)
        if pressure:
            _rec(recs, 'max_connections', str(int(max_conn)), None, 'warn',
                 'Peak use %d of %d connections; raising the limit needs memory this server does not have. Look for '
                 'sites holding idle connections.' % (peak, max_conn), tentative=tentative)
        else:
            _rec(recs, 'max_connections', str(int(max_conn)), str(int(new)), 'change',
                 'Peak use %d of %d connections.' % (peak, max_conn), tentative=tentative)
    else:
        _rec(recs, 'max_connections', str(int(max_conn)), None, 'ok',
             'Peak use %d of %d connections.' % (peak, max_conn), tentative=tentative)

    # thread cache
    connections, created_threads = num(s, 'Connections'), num(s, 'Threads_created')
    if connections > 1000 and created_threads / connections > 0.1 and num(v, 'thread_cache_size') < 64:
        _rec(recs, 'thread_cache_size', v.get('thread_cache_size'), '64', 'change',
             '%.0f%% of connections needed a new thread.' % (100 * created_threads / connections), tentative=tentative)

    # flush method
    method = v.get('innodb_flush_method', '')
    if method.lower() in ('fsync', '') and datadir_fs in ('ext4', 'xfs', 'ext3', 'btrfs'):
        _rec(recs, 'innodb_flush_method', method or 'fsync', 'O_DIRECT', 'change',
             'With fsync every InnoDB page is cached twice (buffer pool and the kernel page cache). O_DIRECT avoids '
             'that, which leaves more RAM for PHP and the web server.')

    # slow query log
    if v.get('slow_query_log', 'OFF').upper() in ('OFF', '0'):
        _rec(recs, 'slow_query_log', 'OFF', 'ON', 'change',
             'Logs queries slower than long_query_time to <datadir>/<host>-slow.log so slow sites can be found. '
             'The file is not rotated automatically.', optional=True)
        if num(v, 'long_query_time', 10) > 2:
            _rec(recs, 'long_query_time', v.get('long_query_time'), '2', 'change',
                 'Ten seconds hides most problem queries on a web server.', optional=True)

    if flavour == 'MariaDB' and version < (10, 6, 0) or flavour == 'MySQL' and version < (8, 0, 0):
        notes.append('%s %s is end-of-life; see the Upgrade tab.' % (flavour, '.'.join(map(str, version[:2]))))
    return {'recommendations': recs, 'notes': notes, 'pressure': pressure,
            'memory': memory_estimate(v, s), 'ram': total_ram, 'uptime': int(uptime)}


def _duration(seconds):
    seconds = int(seconds)
    if seconds < 3600:
        return '%d minutes' % (seconds // 60)
    if seconds < 86400:
        return '%.1f hours' % (seconds / 3600.0)
    return '%.1f days' % (seconds / 86400.0)


# ----------------------------------------------------------------------------- drop-in validation

ENUMS = {
    'innodb_flush_method': ('fsync', 'O_DSYNC', 'O_DIRECT', 'O_DIRECT_NO_FSYNC'),
    'query_cache_type': ('OFF', 'ON', 'DEMAND'),
}
# name: (kind, minimum, maximum)
SPEC = {
    'innodb_buffer_pool_size': ('size', 32 * MB, 512 * GB),
    'innodb_buffer_pool_instances': ('int', 1, 64),
    'innodb_log_file_size': ('size', 4 * MB, 4 * GB),
    'innodb_flush_method': ('enum', None, None),
    'key_buffer_size': ('size', MB, 4 * GB),
    'query_cache_type': ('enum', None, None),
    'query_cache_size': ('size', 0, 512 * MB),
    'query_cache_limit': ('size', 0, 64 * MB),
    'tmp_table_size': ('size', MB, 2 * GB),
    'max_heap_table_size': ('size', MB, 2 * GB),
    'table_open_cache': ('int', 64, 65536),
    'table_definition_cache': ('int', 400, 65536),
    'max_connections': ('int', 10, 10000),
    'thread_cache_size': ('int', 0, 16384),
    'slow_query_log': ('bool', None, None),
    'long_query_time': ('float', 0, 3600),
}


def normalise(name, value):
    if name not in SPEC:
        raise MySQLError('%s cannot be set from the panel.' % name)
    kind, low, high = SPEC[name]
    if kind == 'size':
        number = parse_size(value)
        if not low <= number <= high:
            raise MySQLError('%s must be between %s and %s.' % (name, fmt_size(low) if low else '0', fmt_size(high)))
        return fmt_size(number) if number else '0'
    if kind == 'int':
        if isinstance(value, bool) or not re.match(r'^\d{1,6}$', str(value).strip()):
            raise MySQLError('%s must be a whole number.' % name)
        number = int(str(value).strip())
        if not low <= number <= high:
            raise MySQLError('%s must be between %d and %d.' % (name, low, high))
        return str(number)
    if kind == 'float':
        if isinstance(value, bool) or not re.match(r'^\d{1,4}(\.\d{1,6})?$', str(value).strip()):
            raise MySQLError('%s must be a number of seconds.' % name)
        number = float(str(value).strip())
        if not low <= number <= high:
            raise MySQLError('%s must be between %d and %d.' % (name, low, high))
        return ('%g' % number)
    if kind == 'bool':
        text = str(value).strip().upper()
        if value is True or text in ('ON', '1', 'TRUE'):
            return 'ON'
        if value is False or text in ('OFF', '0', 'FALSE'):
            return 'OFF'
        raise MySQLError('%s must be ON or OFF.' % name)
    text = {'0': 'OFF', '1': 'ON', '2': 'DEMAND'}.get(str(value).strip(), str(value).strip())
    for option in ENUMS[name]:
        if text.upper() == option.upper():
            return option
    raise MySQLError('%s must be one of %s.' % (name, ', '.join(ENUMS[name])))


def validate_settings(settings, current, total_ram):
    """Check a {name: value} dict. Returns (normalised dict, warnings). Raises MySQLError."""
    if not isinstance(settings, dict) or len(settings) > len(SPEC):
        raise MySQLError('Invalid settings.')
    clean = {}
    for name, value in settings.items():
        if not isinstance(name, str) or not isinstance(value, (str, int, float)):
            raise MySQLError('Invalid settings.')
        clean[name] = normalise(name, value)
    warnings = []
    merged = dict(current or {})
    merged.update({k: str(parse_size(x)) if SPEC[k][0] == 'size' else x for k, x in clean.items()})
    bp = num(merged, 'innodb_buffer_pool_size')
    if total_ram and bp > 0.75 * total_ram:
        raise MySQLError('innodb_buffer_pool_size %s is more than 75%% of the %s RAM.' % (
            fmt_size(int(bp)), human(total_ram)))
    global_bytes = sum(num(merged, k) for k in GLOBAL_BUFFERS)
    if total_ram and global_bytes > 0.8 * total_ram:
        raise MySQLError('Global buffers would total %s, more than 80%% of the %s RAM.' % (
            human(global_bytes), human(total_ram)))
    chunk = num(merged, 'innodb_buffer_pool_chunk_size', 128 * MB) * max(num(merged, 'innodb_buffer_pool_instances', 1), 1)
    if 'innodb_buffer_pool_size' in clean and chunk and bp % chunk:
        warnings.append('innodb_buffer_pool_size is rounded up by the server to a multiple of %s.' % fmt_size(int(chunk)))
    qcs = num(merged, 'query_cache_size')
    if 0 < qcs < 40 * KB:
        raise MySQLError('query_cache_size must be 0 or at least 40K.')
    if str(merged.get('query_cache_type', 'OFF')).upper() in ('ON', 'DEMAND') and qcs == 0:
        warnings.append('query_cache_type is on but query_cache_size is 0, so nothing is cached.')
    if num(merged, 'tmp_table_size') != num(merged, 'max_heap_table_size'):
        warnings.append('tmp_table_size and max_heap_table_size differ; the smaller one is the real limit.')
    if 'innodb_log_file_size' in clean and num(merged, 'innodb_force_recovery'):
        warnings.append('innodb_force_recovery is set: InnoDB may refuse to resize the redo log at the next restart.')
    return clean, warnings


def render_dropin(settings, stamp):
    lines = ['# Managed by CyberPanel Universal Add-ons (MySQL Manager).',
             '# Written %s. "Apply" replaces this file; earlier versions are kept for "Revert".' % stamp,
             '# Settings later in /etc/my.cnf (after !includedir) override this file.', '', '[mysqld]']
    for name in sorted(settings):
        if name not in SPEC:
            raise MySQLError('%s cannot be set from the panel.' % name)
        lines.append('%s = %s' % (name, normalise(name, settings[name])))
    return '\n'.join(lines) + '\n'


# ----------------------------------------------------------------------------- my.cnf parsing

_SERVER_GROUP = re.compile(r'^(mysqld|server|mariadb|mariadbd)(-\d+\.\d+)?$')


def option_key(text):
    key = text.strip().lower().replace('-', '_')
    for prefix in ('loose_', 'enable_'):
        if key.startswith(prefix):
            key = key[len(prefix):]
    return key


def parse_cnf(text):
    """Entries: ('includedir', path, line) / ('include', path, line) / ('option', group, key, value, line)."""
    entries, group = [], ''
    for number, raw in enumerate((text or '').splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in '#;':
            continue
        if line.startswith('!includedir'):
            entries.append(('includedir', line[len('!includedir'):].strip(), number))
        elif line.startswith('!include'):
            entries.append(('include', line[len('!include'):].strip(), number))
        elif line.startswith('[') and line.endswith(']'):
            group = line[1:-1].strip().lower()
        else:
            key, _, value = line.partition('=')
            entries.append(('option', group, option_key(key), value.split('#')[0].strip().strip('"\''), number))
    return entries


def is_server_group(group):
    return bool(_SERVER_GROUP.match(group or ''))


def choose_include_dir(text, isdir):
    dirs = [e[1].rstrip('/') for e in parse_cnf(text) if e[0] == 'includedir' and isdir(e[1])]
    return dirs[-1] if dirs else None


def overridden_after_include(text, include_dir):
    """{key: line} for server options set in my.cnf after the include directory (they win over the drop-in)."""
    out, seen = {}, False
    for entry in parse_cnf(text):
        if entry[0] == 'includedir' and entry[1].rstrip('/') == include_dir:
            seen = True
        elif seen and entry[0] == 'option' and is_server_group(entry[1]):
            out[entry[2]] = entry[4]
    return out


def find_option(files, key):
    """files: [(path, text)] -> [{'path', 'line', 'value'}] where a server group sets key."""
    found = []
    for path, text in files:
        for entry in parse_cnf(text):
            if entry[0] == 'option' and is_server_group(entry[1]) and entry[2] == key:
                found.append({'path': path, 'line': entry[4], 'value': entry[3]})
    return found


def parse_dropin(text):
    return {e[2]: e[3] for e in parse_cnf(text) if e[0] == 'option' and is_server_group(e[1])}


# ----------------------------------------------------------------------------- config check

def parse_help_verbose(output):
    """`mysqld --help --verbose` -> ({variable: value}, [error lines])."""
    errors = [line.strip() for line in (output or '').splitlines() if '[ERROR]' in line]
    values, started = {}, False
    for line in (output or '').splitlines():
        if re.match(r'^-{10,} -{5,}', line):
            started = True
            continue
        if started:
            parts = line.split(None, 1)
            if not line.strip():
                if values:
                    break
                continue
            if len(parts) == 2 and re.match(r'^[a-z][a-z0-9-]*$', parts[0]):
                values[option_key(parts[0])] = parts[1].strip()
    return values, errors


def compare_effective(settings, effective):
    """Settings from the drop-in whose effective value (per --help --verbose) differs."""
    mismatches = []
    for name, wanted in settings.items():
        if name not in SPEC or name not in effective:
            continue
        kind = SPEC[name][0]
        actual = effective[name]
        try:
            if kind == 'size':
                same = parse_size(wanted) <= int(actual) <= round_up(parse_size(wanted), 128 * MB) \
                    if name == 'innodb_buffer_pool_size' else parse_size(wanted) == int(actual)
            elif kind == 'int':
                same = int(wanted) == int(actual)
            elif kind == 'float':
                same = abs(float(wanted) - float(actual)) < 1e-6
            elif kind == 'bool':
                same = (wanted == 'ON') == (actual.upper() in ('TRUE', 'ON', '1'))
            else:
                same = wanted.upper() == actual.upper() or (name == 'query_cache_type' and
                                                            {'OFF': '0', 'ON': '1', 'DEMAND': '2'}[wanted] == actual)
        except (ValueError, KeyError, MySQLError):
            same = False
        if not same:
            mismatches.append({'variable': name, 'wanted': wanted, 'effective': actual})
    return mismatches


# ----------------------------------------------------------------------------- process list / kill

PROTECTED_USERS = ('system user', 'event_scheduler', 'unauthenticated user')
PROTECTED_COMMANDS = ('Daemon', 'Binlog Dump', 'Binlog Dump GTID', 'Slave_IO', 'Slave_SQL', 'Slave_worker',
                      'Register Slave', 'Table Dump')
PROCESS_COLUMNS = ('id', 'user', 'host', 'db', 'command', 'time', 'state', 'info')
PROCESS_SQL = ("SELECT ID, USER, IFNULL(HOST,''), IFNULL(DB,''), IFNULL(COMMAND,''), IFNULL(TIME,0), "
               "IFNULL(STATE,''), LEFT(IFNULL(INFO,''), 500) FROM information_schema.PROCESSLIST")


def process_rows(rows):
    out = []
    for row in rows:
        if len(row) < len(PROCESS_COLUMNS) or not row[0].isdigit():
            continue
        item = dict(zip(PROCESS_COLUMNS, row[:len(PROCESS_COLUMNS)]))
        item['id'] = int(item['id'])
        item['time'] = int(num(item, 'time'))
        out.append(item)
    return sorted(out, key=lambda p: (p['command'] == 'Sleep', -p['time']))


def kill_refusal(process, own_id, panel_users):
    """Why this thread must not be killed, or '' if it may be."""
    if process is None:
        return 'That thread no longer exists.'
    if process['id'] == own_id:
        return 'That is the panel\'s own monitoring connection.'
    if process['user'] in PROTECTED_USERS:
        return 'System and replication threads are never killed from the panel.'
    if process['command'] in PROTECTED_COMMANDS or process['command'].startswith('Slave'):
        return 'Replication and server background threads are never killed from the panel.'
    if process['user'] in panel_users:
        return 'Connections of the panel\'s own database user (%s) are never killed.' % process['user']
    return ''


def thread_id(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not re.match(r'^\d{1,19}$', str(value)):
        raise MySQLError('Invalid thread id.')
    number = int(value)
    if not 0 < number < 2 ** 63:
        raise MySQLError('Invalid thread id.')
    return number


def kill_sql(tid, mode):
    if mode not in ('query', 'connection'):
        raise MySQLError('Invalid kill mode.')
    return 'KILL %s %d' % ('QUERY' if mode == 'query' else 'CONNECTION', thread_id(tid))


# ----------------------------------------------------------------------------- upgrade readiness

# (major, minor): (end of community support, LTS)
MARIADB_RELEASES = {
    (10, 3): ('2023-05-25', False), (10, 4): ('2024-06-18', False), (10, 5): ('2025-06-24', False),
    (10, 6): ('2026-07-06', True), (10, 11): ('2028-02-16', True), (11, 4): ('2029-05-29', True),
    (11, 8): ('2028-06-04', True),
}
EL_TARGETS = ((10, 11), (11, 4), (10, 6), (11, 8))


def parse_os_release(text):
    data = {}
    for line in (text or '').splitlines():
        key, _, value = line.partition('=')
        data[key.strip()] = value.strip().strip('"')
    ids = (data.get('ID', '') + ' ' + data.get('ID_LIKE', '')).lower().split()
    family = 'rhel' if set(ids) & {'rhel', 'centos', 'fedora', 'almalinux', 'rocky', 'ol', 'cloudlinux'} else \
        ('debian' if set(ids) & {'debian', 'ubuntu'} else 'other')
    try:
        major = int(data.get('VERSION_ID', '0').split('.')[0])
    except ValueError:
        major = 0
    return {'id': data.get('ID', ''), 'name': data.get('PRETTY_NAME', data.get('NAME', '')), 'family': family,
            'major': major}


def upgrade_report(version_text, os_info, databases, datadir_bytes, free_bytes, today, force_recovery=0,
                   shim_present=False, myisam_tables=0):
    flavour, version = parse_version(version_text)
    series = version[:2]
    eol = MARIADB_RELEASES.get(series, (None, False))[0] if flavour == 'MariaDB' else None
    user_dbs = [d for d in databases if not d['system']]
    targets = []
    if flavour == 'MariaDB' and os_info['family'] == 'rhel' and os_info['major'] in (8, 9):
        for target in EL_TARGETS:
            end, lts = MARIADB_RELEASES[target]
            if target > series:
                targets.append({'version': '%d.%d' % target, 'eol': end, 'lts': lts, 'supported': end > today,
                                'source': 'MariaDB Foundation repository (rhel%d)' % os_info['major']})
    targets.sort(key=lambda t: tuple(int(x) for x in t['version'].split('.')))
    recommended = next((t['version'] for t in targets if t['supported']), None)
    data_bytes = sum(d['bytes'] for d in user_dbs)
    needed = int(data_bytes * 1.5 + 2 * GB)    # logical dump + temporary space during the upgrade
    blockers, warnings = [], []
    if force_recovery:
        blockers.append('innodb_force_recovery=%d is set. An upgrade needs a clean InnoDB shutdown '
                        '(innodb_fast_shutdown=0) on a healthy datadir; fix the underlying corruption first.' % force_recovery)
    if free_bytes < needed:
        blockers.append('Only %s free next to the datadir; about %s is needed for a logical backup plus upgrade '
                        'headroom.' % (human(free_bytes), human(needed)))
    if free_bytes < datadir_bytes + 2 * GB:
        warnings.append('A physical copy of the datadir (%s, mariabackup) does not fit on this disk; write it to '
                        'another disk or a remote host, or rely on the logical dump.' % human(datadir_bytes))
    if os_info['family'] == 'rhel' and os_info['id'] == 'centos' and os_info['major'] == 8:
        warnings.append('CentOS Linux 8 itself is end-of-life; consider migrating the OS (e.g. to AlmaLinux 8) '
                        'before or together with the database upgrade.')
    if myisam_tables:
        warnings.append('%d MyISAM tables (including system tables) are not crash-safe; check them '
                        '(mysqlcheck --all-databases --check) before upgrading.' %
                        myisam_tables)
    target = recommended or 'X.Y'
    steps = []
    if force_recovery:
        steps.append('Resolve innodb_force_recovery: find out why it was set (error log), dump and reload damaged '
                     'tables, remove the line from /etc/my.cnf and restart until MariaDB starts cleanly without it.')
    steps += [
        'Take two backups: a physical one (mariabackup --backup --target-dir=/root/mysql-preupgrade-$(date +%F), '
        'then mariabackup --prepare) and a logical one (mysqldump --all-databases --routines --events --triggers '
        '--single-transaction | gzip > /root/all-databases-$(date +%F).sql.gz). Copy /etc/my.cnf and /etc/my.cnf.d too.',
        'Check the free space shown above and pick a quiet maintenance window; every site loses its database during the switch.',
        'Read the MariaDB upgrade notes for every major version between %s and %s (removed options, changed '
        'defaults). Remove options the new version rejects from the tuning drop-in (e.g. innodb_log_files_in_group, '
        'innodb_buffer_pool_instances are ignored or removed from 10.5).' % ('.'.join(map(str, series)), target),
        'mysql -e "SET GLOBAL innodb_fast_shutdown=0" and then systemctl stop mariadb (clean, full shutdown).',
        'dnf module reset mariadb -y && dnf module disable mariadb -y (stop AppStream from supplying 10.3).',
        'Add the MariaDB %s repository (curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | bash -s -- '
        '--mariadb-server-version=mariadb-%s) and check /etc/yum.repos.d/mariadb.repo.' % (target, target),
        'dnf install MariaDB-server MariaDB-client MariaDB-backup MariaDB-shared --allowerasing; review the '
        'transaction: only mariadb* packages may be removed.',
        'systemctl enable --now mariadb, then mariadb-upgrade (mysql_upgrade on old names) and read the error log.',
        'Verify: panel login, a few sites, mysqlcheck --all-databases --check, and the MySQL Manager status page.',
        'Rollback plan: if anything fails, reinstall the AppStream 10.3 packages and restore the mariabackup copy '
        'into an empty /var/lib/mysql (a datadir opened by a newer version cannot be used by 10.3 again).',
    ]
    django = ('Django 4.2, which the panel runs on, officially requires MariaDB 10.4 or later. The panel currently '
              'works on %s only through a compatibility shim (CyberCP/mariadb_compat.py) that lowers Django\'s minimum '
              'version check to 10.3 for MariaDB. After an upgrade to 10.4+ the shim is no longer needed '
              '(it only lowers the floor, so it is harmless to keep).' % version_text) if flavour == 'MariaDB' else ''
    return {
        'installed': version_text, 'flavour': flavour, 'series': '.'.join(map(str, series)),
        'eol': eol, 'is_eol': bool(eol and eol <= today), 'os': os_info, 'targets': targets,
        'recommended': recommended, 'databases': len(user_dbs),
        'data_bytes': data_bytes, 'datadir_bytes': datadir_bytes,
        'free_bytes': free_bytes, 'needed_bytes': needed, 'disk_ok': free_bytes >= needed,
        'blockers': blockers, 'warnings': warnings, 'steps': steps, 'django': django,
        'shim_present': shim_present, 'ready': not blockers,
    }
