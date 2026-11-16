"""Root-side PostgreSQL database actions (dispatched by universalAddons/runner.py).

The views check who may act on which site; every action here also checks that each database and
role belongs to that site in the registry. psql runs as the postgres OS user (peer login over the
local socket); restores run as the site user with a temporary member role. See service.py.
"""
import fcntl
import json
import os
import pwd
import shutil
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from universalAddons import jobs, privileged, siteinfo
from universalAddons.pgsql import service as pg
from universalAddons.pgsql.service import PGError

CLEAN_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


# ----------------------------------------------------------------------------- registry

@contextmanager
def _locked():
    os.makedirs(pg.STATE_DIR, mode=0o700, exist_ok=True)
    with open(os.path.join(pg.STATE_DIR, '.lock'), 'w') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def load_registry(path=None):
    try:
        with open(path or pg.REGISTRY) as handle:
            return pg.normalise_registry(json.load(handle))
    except (OSError, ValueError):
        return pg.empty_registry()


def save_registry(reg, path=None):
    path = path or pg.REGISTRY
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(reg, handle, indent=1, sort_keys=True)
    os.replace(path + '.tmp', path)


# ----------------------------------------------------------------------------- psql

def _major():
    major = pg.installed_major()
    if not major:
        raise PGError('PostgreSQL is not installed. An administrator can install it from Applications.')
    return major


def psql(name, database='postgres', runner=subprocess.run, timeout=300, **values):
    """Run a constant script as the postgres OS user; values travel in its environment."""
    text, env = pg.script(name, **values)
    if database != 'postgres':
        pg.check_name(database)
    account = pwd.getpwnam('postgres')
    env.update(PATH=CLEAN_PATH, LANG='C.UTF-8', HOME=account.pw_dir, PGDATABASE=database, PGAPPNAME='indianscloud')
    try:
        out = runner(pg.psql_argv(_major()), input=text, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     universal_newlines=True, timeout=timeout, env=env, cwd='/', user=account.pw_uid,
                     group=account.pw_gid, extra_groups=[])
    except subprocess.TimeoutExpired:
        raise PGError('PostgreSQL did not answer in time.')
    if out.returncode != 0:
        raise PGError('PostgreSQL refused: %s' % (out.stdout or '').strip()[-400:])
    return out.stdout or ''


def _exists(name):
    return int((psql('exists', name=name).strip() or '0').splitlines()[-1]) > 0


def _website(domain):
    """(Websites row, Site) for a top-level website; PostgreSQL databases belong to websites."""
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import Websites
    try:
        website = Websites.objects.get(domain=domain)
    except Websites.DoesNotExist:
        raise PGError('Unknown website.')
    return website, siteinfo.resolve(domain)


def _quota(website, reg):
    mysql = website.databases_set.all().count()
    return pg.quota_check(website.package.dataBases, mysql, pg.count_for_site(reg, website.domain))


def _secret():
    password = pg.new_password()
    return password, pg.scram_secret(password)


def _connection(name, role, password):
    return {'database': name, 'role': role, 'password': password, 'host': '127.0.0.1', 'port': 5432,
            'uri': 'postgresql://%s:%s@127.0.0.1:5432/%s' % (role, password, name)}


# ----------------------------------------------------------------------------- listing

def overview(domains=None):
    major = pg.installed_major()
    reg = load_registry()
    view = pg.site_view(reg, None if domains is None else set(domains))
    if major:
        _cleanup_temps(reg)
        try:
            sizes = pg.parse_sizes(psql('sizes'))
        except PGError:
            sizes = {}
        for entry in view['databases']:
            entry['bytes'] = sizes.get(entry['name'])
            entry['missing'] = bool(sizes) and entry['name'] not in sizes
    quotas = {}
    if domains is not None:
        for domain in sorted(set(domains)):
            try:
                quotas[domain] = _quota(_website(domain)[0], reg)
            except PGError as exc:
                quotas[domain] = str(exc)
    return dict(view, installed=bool(major), major=major, quotas=quotas, adminer=pg.adminer_installed(),
                connection=pg.connection_info(major) if major else None)


# ----------------------------------------------------------------------------- databases and roles

def create_db(domain, name):
    """Database <prefix>_<name> owned by a new role of the same name; the password is returned once."""
    _major()
    db = pg.full_name(domain, name)
    website, _ = _website(domain)
    with _locked():
        reg = load_registry()
        _quota(website, reg)
        if db in reg['databases'] or db in reg['roles'] or _exists(db):
            raise PGError('%s already exists.' % db)
        password, secret = _secret()
        psql('create_role', role=db, secret=secret)
        try:
            psql('create_db', db=db, owner=db)
            psql('own_schema', database=db, owner=db)
        except PGError:
            try:
                psql('drop_db', db=db)
            finally:
                psql('drop_role', role=db)
            raise
        now = int(time.time())
        reg['roles'][db] = {'domain': domain, 'created': now}
        reg['databases'][db] = {'domain': domain, 'owner': db, 'created': now, 'grants': {}}
        save_registry(reg)
    return _connection(db, db, password)


def drop_db(domain, name, drop_owner=True):
    with _locked():
        reg = load_registry()
        entry = pg.require_db(reg, domain, name)
        psql('drop_db', db=name)
        del reg['databases'][name]
        dropped_role = None
        owner = entry.get('owner')
        still_used = any(owner in e.get('grants', {}) or e.get('owner') == owner for e in reg['databases'].values())
        if drop_owner and owner in reg['roles'] and not still_used:
            psql('drop_role', role=owner)
            del reg['roles'][owner]
            dropped_role = owner
        save_registry(reg)
    return {'dropped': name, 'dropped_role': dropped_role}


def create_role(domain, name):
    _major()
    role = pg.full_name(domain, name)
    with _locked():
        reg = load_registry()
        if role in reg['roles'] or role in reg['databases'] or _exists(role):
            raise PGError('%s already exists.' % role)
        password, secret = _secret()
        psql('create_role', role=role, secret=secret)
        reg['roles'][role] = {'domain': domain, 'created': int(time.time())}
        save_registry(reg)
    return {'role': role, 'password': password, 'host': '127.0.0.1', 'port': 5432}


def drop_role(domain, name):
    with _locked():
        reg = load_registry()
        pg.require_role(reg, domain, name)
        owns = [d for d, e in reg['databases'].items() if e.get('owner') == name]
        if owns:
            raise PGError('%s owns %s; delete the database first.' % (name, ', '.join(sorted(owns))))
        for db, entry in reg['databases'].items():
            if name in entry.get('grants', {}):
                psql('revoke_in_db', database=db, role=name, owner=entry['owner'])
                psql('revoke_connect', db=db, role=name)
                entry['grants'].pop(name)
        psql('drop_role', role=name)
        del reg['roles'][name]
        save_registry(reg)
    return {'dropped': name}


def reset_password(domain, role):
    reg = load_registry()
    pg.require_role(reg, domain, role)
    password, secret = _secret()
    psql('password', role=role, secret=secret)
    return {'role': role, 'password': password}


def grant(domain, db, role, level='all'):
    if level not in pg.LEVELS:
        raise PGError('Access must be all or read.')
    with _locked():
        reg = load_registry()
        entry = pg.require_db(reg, domain, db)
        pg.require_role(reg, domain, role)
        if entry['owner'] == role:
            raise PGError('%s owns %s already.' % (role, db))
        if role in entry['grants']:
            psql('revoke_in_db', database=db, role=role, owner=entry['owner'])
        psql('grant_connect', db=db, role=role)
        psql('grant_' + level, database=db, role=role, owner=entry['owner'])
        entry['grants'][role] = level
        save_registry(reg)
    return {'database': db, 'role': role, 'level': level}


def revoke(domain, db, role):
    with _locked():
        reg = load_registry()
        entry = pg.require_db(reg, domain, db)
        pg.require_role(reg, domain, role)
        if role not in entry['grants']:
            raise PGError('%s has no access to %s.' % (role, db))
        psql('revoke_in_db', database=db, role=role, owner=entry['owner'])
        psql('revoke_connect', db=db, role=role)
        entry['grants'].pop(role)
        save_registry(reg)
    return {'database': db, 'role': role}


# ----------------------------------------------------------------------------- temporary member roles

def _utc(minutes):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S+00')


def _temp_role(reg, db, owner, minutes, purpose):
    name = pg.TEMP_PREFIX + os.urandom(8).hex()
    password, secret = _secret()
    psql('temp_role', role=name, secret=secret, owner=owner, until=_utc(minutes))
    reg['temps'][name] = {'database': db, 'owner': owner, 'expires': int(time.time()) + minutes * 60,
                          'purpose': purpose}
    save_registry(reg)
    return name, password


def _drop_temp(reg, name):
    entry = reg['temps'].get(name) or {}
    db, owner = entry.get('database'), entry.get('owner')
    try:
        if db in reg['databases'] and owner:
            psql('disown', database=db, role=name, owner=owner)
        psql('drop_role', role=name)
    finally:
        reg['temps'].pop(name, None)


def _cleanup_temps(reg, force=()):
    """Drop temporary roles whose time is up (Adminer logins, finished restores)."""
    now = time.time()
    expired = [n for n, e in reg['temps'].items() if n in force or e.get('expires', 0) < now]
    if not expired:
        return
    with _locked():
        reg = load_registry()
        for name in expired:
            if name in reg['temps']:
                try:
                    _drop_temp(reg, name)
                except PGError:
                    pass
        save_registry(reg)


def adminer_login(domain, db):
    """A 30-minute login for Adminer that acts as the database owner."""
    if not pg.adminer_installed():
        raise PGError('Adminer is not installed.')
    with _locked():
        reg = load_registry()
        entry = pg.require_db(reg, domain, db)
        name, password = _temp_role(reg, db, entry['owner'], pg.ADMINER_MINUTES, 'adminer')
    return {'username': name, 'password': password, 'database': db, 'minutes': pg.ADMINER_MINUTES,
            'url': pg.ADMINER_PATH}


# ----------------------------------------------------------------------------- backups

def _backup_dir_fd(site, create=False):
    """An O_NOFOLLOW descriptor of <home>/pgsql-backups (owned by the site user), or None."""
    if create:
        code, out = siteinfo.run_as(site, ['mkdir', '-p', '-m', '700', os.path.join(site.home, pg.BACKUP_DIR)],
                                    timeout=30)
        if code != 0:
            raise PGError('Could not create %s: %s' % (pg.BACKUP_DIR, out.strip()[-200:]))
    home = os.open(site.home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(pg.BACKUP_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
    except FileNotFoundError:
        return None
    finally:
        os.close(home)
    if os.fstat(fd).st_uid != site.uid:
        os.close(fd)
        raise PGError('%s does not belong to the site user.' % pg.BACKUP_DIR)
    return fd


def backups(domain):
    reg = load_registry()
    names = {n for n, e in reg['databases'].items() if e.get('domain') == domain}
    site = siteinfo.resolve(domain)
    fd = _backup_dir_fd(site)
    found = []
    if fd is not None:
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    match = pg.BACKUP_RE.match(entry.name)
                    if not match or match.group(1) not in names:
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if entry.is_file(follow_symlinks=False) and info.st_uid == site.uid:
                        found.append({'file': entry.name, 'database': match.group(1), 'bytes': info.st_size,
                                      'time': int(info.st_mtime)})
        finally:
            os.close(fd)
    return {'backups': sorted(found, key=lambda b: -b['time']),
            'directory': os.path.join(site.home, pg.BACKUP_DIR)}


def backup(domain, db):
    reg = load_registry()
    pg.require_db(reg, domain, db)
    _major()
    return jobs.spawn('pgsql', 'backup_run', {'domain': domain, 'db': db})


def backup_run(job_id, domain, db):
    def dump(job):
        reg = load_registry()
        pg.require_db(reg, domain, db)
        site = siteinfo.resolve(domain)
        fd = _backup_dir_fd(site, create=True)
        os.close(fd)
        name = pg.backup_name(db, time.strftime('%Y%m%d-%H%M%S'))
        target = os.path.join(site.home, pg.BACKUP_DIR, name)
        account = pwd.getpwnam('postgres')
        env = {'PATH': CLEAN_PATH, 'LANG': 'C.UTF-8', 'HOME': account.pw_dir, 'PGDATABASE': db}
        # pg_dump reads as postgres; the file is written by the site user (dd never follows a link
        # and never overwrites), so root never writes into the site's home.
        dumper = subprocess.Popen([os.path.join(pg.pg_bin(_major()), 'pg_dump'), '-Fc', '--no-password'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd='/',
                                  user=account.pw_uid, group=account.pw_gid, extra_groups=[])
        writer = subprocess.Popen(['dd', 'of=' + target, 'bs=1M', 'status=none', 'conv=excl', 'oflag=nofollow'],
                                  stdin=dumper.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  env=siteinfo.user_env(site), cwd=site.home, user=site.uid, group=site.gid,
                                  extra_groups=[], umask=0o077)
        dumper.stdout.close()
        written = writer.communicate(timeout=6 * 3600)[0]
        errors = dumper.stderr.read().decode('utf-8', 'replace')
        dumper.wait(timeout=60)
        if dumper.returncode != 0 or writer.returncode != 0:
            siteinfo.run_as(site, ['rm', '-f', '--', target], timeout=30)
            raise PGError('pg_dump failed: %s %s' % (errors.strip()[-400:], written.decode('utf-8', 'replace')[-200:]))
        job.log('Saved %s' % target)
        return {'file': name, 'path': target}
    return jobs.run_job(job_id, [('Dump %s' % db, dump)])


def stage_download(domain, file):
    """Copy a backup of the site into the spool for the web process to stream."""
    match = pg.BACKUP_RE.match(file or '')
    reg = load_registry()
    if not match:
        raise PGError('Invalid backup name.')
    pg.require_db(reg, domain, match.group(1))
    site = siteinfo.resolve(domain)
    fd = siteinfo.open_owned(site, os.path.join(site.home, pg.BACKUP_DIR, file))
    with os.fdopen(fd, 'rb') as source:
        size = os.fstat(source.fileno()).st_size
        if size > pg.MAX_DOWNLOAD_BYTES:
            raise PGError('Backups over 2 GB must be fetched with SFTP from %s.' % pg.BACKUP_DIR)
        uid = privileged.panel_uid()
        os.makedirs(privileged.SPOOL_DIR, mode=0o700, exist_ok=True)
        spool_id = privileged.new_spool_id()
        target = privileged.spool_path(spool_id)
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, 'wb') as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
        os.chown(target, uid, uid)
    return {'spool_id': spool_id, 'name': file, 'size': size}


def delete_backup(domain, file):
    match = pg.BACKUP_RE.match(file or '')
    if not match:
        raise PGError('Invalid backup name.')
    pg.require_db(load_registry(), domain, match.group(1))
    site = siteinfo.resolve(domain)
    code, out = siteinfo.run_as(site, ['rm', '-f', '--', os.path.join(site.home, pg.BACKUP_DIR, file)], timeout=30)
    if code != 0:
        raise PGError(out.strip()[-200:])
    return {'deleted': file}


# ----------------------------------------------------------------------------- restore

def restore(domain, db, spool_id):
    reg = load_registry()
    pg.require_db(reg, domain, db)
    privileged.spool_path(spool_id)  # validates the id
    _major()
    return jobs.spawn('pgsql', 'restore_run', {'domain': domain, 'db': db, 'spool_id': spool_id})


def restore_run(job_id, domain, db, spool_id):
    state = {}

    def open_upload(job):
        path, handle = privileged.open_spool(spool_id, privileged.panel_uid())
        os.unlink(path)  # the open handle keeps the data
        state['handle'] = handle
        state['format'] = pg.dump_format(handle.read(4096))
        handle.seek(0)
        job.log('Upload is a %s dump.' % ('pg_dump custom' if state['format'] == 'custom' else 'plain SQL'))

    def temp_login(job):
        with _locked():
            reg = load_registry()
            entry = pg.require_db(reg, domain, db)
            state['owner'] = entry['owner']
            state['role'], state['password'] = _temp_role(reg, db, entry['owner'], 6 * 60, 'restore')
        job.log('Restoring as a temporary member of %s (not as a superuser).' % state['owner'])

    def run_restore(job):
        site = siteinfo.resolve(domain)
        bindir = pg.pg_bin(_major())
        if state['format'] == 'custom':
            argv = [os.path.join(bindir, 'pg_restore'), '--no-owner', '--no-privileges', '--no-password',
                    '--role=' + pg.check_name(state['owner']), '-d', db]
        else:
            argv = [os.path.join(bindir, 'psql'), '-X', '-q', '--no-password', '-v', 'ON_ERROR_STOP=0', '-f', '-']
        env = siteinfo.user_env(site, {'PGHOST': '127.0.0.1', 'PGPORT': '5432', 'PGUSER': state['role'],
                                       'PGPASSWORD': state['password'], 'PGDATABASE': db,
                                       'PGAPPNAME': 'indianscloud-restore'}, path=CLEAN_PATH)
        process = subprocess.run(['timeout', '-k', '10', str(6 * 3600)] + argv, stdin=state['handle'],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=site.home,
                                 user=site.uid, group=site.gid, extra_groups=[], umask=0o077)
        output = process.stdout.decode('utf-8', 'replace')
        job.log(output[-6000:])
        errors = pg.count_errors(output)
        # pg_restore exits 1 when it skipped failing statements (reported below); psql with
        # ON_ERROR_STOP=0 exits non-zero only when it could not run at all.
        if process.returncode != 0 and (state['format'] == 'plain' or not errors):
            raise PGError('The restore did not run (exit %d).' % process.returncode)
        job.log('%d statement error(s).' % errors if errors else 'Restore finished without errors.')
        return {'errors': errors}

    def cleanup(job):
        if state.get('handle'):
            state['handle'].close()
        if state.get('role'):
            _cleanup_temps(load_registry(), force=(state['role'],))

    def guarded(step):
        def run(job):
            try:
                return step(job)
            except Exception:
                cleanup(job)
                raise
        return run

    try:
        return jobs.run_job(job_id, [('Read the upload', guarded(open_upload)),
                                     ('Create a temporary login', guarded(temp_login)),
                                     ('Restore into %s' % db, guarded(run_restore)),
                                     ('Remove the temporary login', cleanup)])
    finally:
        try:
            os.unlink(privileged.spool_path(spool_id))
        except OSError:
            pass


# ----------------------------------------------------------------------------- Adminer (administrators)

def adminer_install():
    return jobs.spawn('pgsql', 'adminer_install_run', {})


def adminer_install_run(job_id):
    work = os.path.join(pg.STATE_DIR, 'download')

    def fetch(job):
        os.makedirs(work, mode=0o700, exist_ok=True)
        target = os.path.join(work, pg.ADMINER_FILE)
        code, out = siteinfo.run(['curl', '-fsSL', '--proto', '=https', '--max-time', '120', '-o', target,
                                  pg.ADMINER_URL], timeout=180)
        if code != 0:
            raise PGError('Download failed: %s' % out.strip()[-300:])
        digest = pg.sha256_file(target)
        if digest != pg.ADMINER_SHA256:
            os.unlink(target)
            raise PGError('Checksum mismatch: got %s, expected %s. Nothing was installed.' % (digest, pg.ADMINER_SHA256))
        job.log('SHA-256 %s matches the pinned release digest.' % digest)

    def place(job):
        os.makedirs(pg.ADMINER_DIR, mode=0o755, exist_ok=True)
        os.chmod(pg.ADMINER_DIR, 0o755)
        shutil.copyfile(os.path.join(work, pg.ADMINER_FILE), os.path.join(pg.ADMINER_DIR, pg.ADMINER_FILE + '.tmp'))
        os.replace(os.path.join(pg.ADMINER_DIR, pg.ADMINER_FILE + '.tmp'), os.path.join(pg.ADMINER_DIR, pg.ADMINER_FILE))
        with open(os.path.join(pg.ADMINER_DIR, 'index.php.tmp'), 'w') as handle:
            handle.write(pg.ADMINER_WRAPPER)
        os.replace(os.path.join(pg.ADMINER_DIR, 'index.php.tmp'), os.path.join(pg.ADMINER_DIR, 'index.php'))
        for name in os.listdir(pg.ADMINER_DIR):
            os.chmod(os.path.join(pg.ADMINER_DIR, name), 0o644)
        job.log('Installed in %s, served at %s' % (pg.ADMINER_DIR, pg.ADMINER_PATH))
        return {'path': pg.ADMINER_PATH, 'version': pg.ADMINER_VERSION}

    return jobs.run_job(job_id, [('Download Adminer %s' % pg.ADMINER_VERSION, fetch), ('Install', place)])


def adminer_remove():
    if os.path.isdir(pg.ADMINER_DIR) and not os.path.islink(pg.ADMINER_DIR):
        shutil.rmtree(pg.ADMINER_DIR)
    return {'removed': True}


ACTIONS = {
    'overview': lambda domains=None: overview(domains),
    'create_db': create_db,
    'drop_db': drop_db,
    'create_role': create_role,
    'drop_role': drop_role,
    'reset_password': reset_password,
    'grant': grant,
    'revoke': revoke,
    'adminer_login': adminer_login,
    'backups': backups,
    'backup': backup,
    'backup_run': backup_run,
    'stage_download': stage_download,
    'delete_backup': delete_backup,
    'restore': restore,
    'restore_run': restore_run,
    'adminer_install': adminer_install,
    'adminer_install_run': adminer_install_run,
    'adminer_remove': adminer_remove,
    'job': lambda job_id: jobs.status(job_id),
}
