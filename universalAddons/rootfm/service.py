"""Root File Manager: whole-server file operations, run as root by universalAddons/runner.py.

Safety model
- Every path is absolute, normalised with os.path.normpath and must not contain NUL. Symlinks
  are never followed for destructive operations (we act on the link itself).
- PROTECTED trees refuse writes unless the caller passes unlock=True (the UI asks first).
  READ_ONLY trees (/proc, /sys, /dev) refuse writes always.
- Deletes move into TRASH_DIR (restorable); purge is a separate, explicit action.
- Every change is appended to AUDIT_LOG as one JSON line.
- No shell is ever used; archives are handled with tarfile/zipfile and member paths are
  checked so extraction cannot escape the destination.
"""
import grp
import hashlib
import json
import os
import pwd
import shutil
import stat
import tarfile
import time
import zipfile

TRASH_DIR = '/root/.cp-rootfm-trash'
AUDIT_LOG = '/var/log/cyberpanel_rootfm.log'
MAX_EDIT_BYTES = 2 * 1024 * 1024
MAX_LIST_ENTRIES = 5000
MAX_SEARCH_RESULTS = 500

READ_ONLY = ('/proc', '/sys', '/dev')
PROTECTED = (
    '/', '/bin', '/sbin', '/lib', '/lib64', '/usr', '/boot', '/etc', '/var/lib/mysql',
    '/root/.ssh', '/usr/local/CyberCP', '/usr/local/lscp', '/usr/local/lsws/bin',
)
# Never writable, even when unlocked.
DENY_WRITE_FILES = ('/etc/shadow', '/etc/gshadow', '/etc/passwd', '/etc/group', '/etc/sudoers')


class FMError(ValueError):
    pass


def clean_path(path):
    if not isinstance(path, str) or not path or '\x00' in path:
        raise FMError('Invalid path.')
    if not path.startswith('/'):
        raise FMError('Paths must be absolute.')
    return os.path.normpath(path) if path != '/' else '/'


def _under(path, roots):
    return any(path == root or path.startswith(root.rstrip('/') + '/') for root in roots)


def check_writable(path, unlock=False):
    """Raise FMError if path may not be modified."""
    path = clean_path(path)
    real = os.path.realpath(path)
    for candidate in {path, real}:
        if _under(candidate, READ_ONLY):
            raise FMError('%s is a kernel/device filesystem and cannot be modified.' % candidate)
        if candidate in DENY_WRITE_FILES:
            raise FMError('%s is a credential database; edit it with the proper system tools.' % candidate)
        if candidate == '/':
            raise FMError('The filesystem root itself cannot be modified.')
        if not unlock and _under(candidate, [p for p in PROTECTED if p != '/']):
            raise FMError('PROTECTED:%s is a protected system path. Unlock protected paths to change it.' % candidate)
    if os.path.dirname(path) == '/' and not unlock:
        raise FMError('PROTECTED:%s is a top-level directory. Unlock protected paths to change it.' % path)
    return path


def audit(action, actor='', log_path=None, **details):
    entry = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'action': action, 'actor': actor}
    entry.update(details)
    try:
        fd = os.open(log_path or AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, 'a') as handle:
            handle.write(json.dumps(entry) + '\n')
    except OSError:
        pass


def _owner(uid, gid):
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = str(uid)
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = str(gid)
    return user, group


def describe(path, name=None):
    info = os.lstat(path)
    user, group = _owner(info.st_uid, info.st_gid)
    kind = 'dir' if stat.S_ISDIR(info.st_mode) else 'link' if stat.S_ISLNK(info.st_mode) else \
        'file' if stat.S_ISREG(info.st_mode) else 'other'
    entry = {
        'name': name if name is not None else os.path.basename(path) or '/',
        'path': path, 'type': kind, 'size': info.st_size, 'mtime': int(info.st_mtime),
        'mode': '%04o' % stat.S_IMODE(info.st_mode), 'perms': stat.filemode(info.st_mode),
        'owner': user, 'group': group,
    }
    if kind == 'link':
        try:
            entry['target'] = os.readlink(path)
        except OSError:
            entry['target'] = '?'
    return entry


def list_dir(path, show_hidden=True):
    path = clean_path(path)
    if not os.path.isdir(path):
        raise FMError('%s is not a directory.' % path)
    entries, truncated = [], False
    with os.scandir(path) as iterator:
        for item in iterator:
            if not show_hidden and item.name.startswith('.'):
                continue
            if len(entries) >= MAX_LIST_ENTRIES:
                truncated = True
                break
            try:
                entries.append(describe(item.path, item.name))
            except OSError:
                continue
    entries.sort(key=lambda e: (e['type'] != 'dir', e['name'].lower()))
    return {'path': path, 'parent': os.path.dirname(path) if path != '/' else None,
            'entries': entries, 'truncated': truncated}


def _is_text(data):
    if b'\x00' in data[:8192]:
        return False
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def read_file(path):
    path = clean_path(path)
    if _under(path, READ_ONLY) and not _under(path, ('/proc',)):
        raise FMError('Device files cannot be opened.')
    if not os.path.isfile(path):
        raise FMError('%s is not a regular file.' % path)
    size = os.path.getsize(path)
    if size > MAX_EDIT_BYTES:
        raise FMError('File is %d bytes; the editor opens files up to %d bytes. Download it instead.'
                      % (size, MAX_EDIT_BYTES))
    with open(path, 'rb') as handle:
        data = handle.read(MAX_EDIT_BYTES + 1)
    if not _is_text(data):
        raise FMError('Binary file; download it instead of editing.')
    return {'path': path, 'content': data.decode('utf-8'), 'sha256': hashlib.sha256(data).hexdigest(),
            'writable': _writable_quiet(path)}


def _writable_quiet(path):
    try:
        check_writable(path)
        return 'yes'
    except FMError as exc:
        return 'protected' if str(exc).startswith('PROTECTED:') else 'no'


def write_file(path, content, expected_sha256=None, unlock=False, actor=''):
    """Atomically replace a text file, keeping mode/owner and refusing lost updates."""
    path = check_writable(path, unlock)
    if not isinstance(content, str):
        raise FMError('Invalid content.')
    data = content.encode('utf-8')
    if len(data) > MAX_EDIT_BYTES:
        raise FMError('Content exceeds %d bytes.' % MAX_EDIT_BYTES)
    existing = os.path.lexists(path)
    if existing:
        if os.path.islink(path) or not os.path.isfile(path):
            raise FMError('%s is not a regular file.' % path)
        if expected_sha256:
            with open(path, 'rb') as handle:
                if hashlib.sha256(handle.read()).hexdigest() != expected_sha256:
                    raise FMError('The file changed on disk since it was opened. Reload before saving.')
        info = os.stat(path)
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        raise FMError('Directory %s does not exist.' % directory)
    temporary = os.path.join(directory, '.%s.cp-rootfm.%d' % (os.path.basename(path), os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if existing:
            os.chmod(temporary, stat.S_IMODE(info.st_mode))
            os.chown(temporary, info.st_uid, info.st_gid)
        else:
            os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    audit('write', actor, path=path, bytes=len(data), created=not existing)
    return {'path': path, 'sha256': hashlib.sha256(data).hexdigest()}


def _validate_name(name):
    if not isinstance(name, str) or not name or name in ('.', '..') or '/' in name or '\x00' in name \
            or len(name) > 255:
        raise FMError('Invalid name.')
    return name


def create(directory, name, kind, unlock=False, actor=''):
    target = check_writable(os.path.join(clean_path(directory), _validate_name(name)), unlock)
    if os.path.lexists(target):
        raise FMError('%s already exists.' % target)
    if kind == 'dir':
        os.mkdir(target, 0o755)
    elif kind == 'file':
        os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644))
    else:
        raise FMError('Invalid type.')
    audit('create', actor, path=target, kind=kind)
    return describe(target)


def rename(path, new_name, unlock=False, actor=''):
    path = check_writable(path, unlock)
    target = check_writable(os.path.join(os.path.dirname(path), _validate_name(new_name)), unlock)
    if os.path.lexists(target):
        raise FMError('%s already exists.' % target)
    os.rename(path, target)
    audit('rename', actor, path=path, to=target)
    return describe(target)


def _destination(source, destination_dir, unlock):
    destination_dir = clean_path(destination_dir)
    if not os.path.isdir(destination_dir):
        raise FMError('%s is not a directory.' % destination_dir)
    target = check_writable(os.path.join(destination_dir, os.path.basename(source)), unlock)
    if os.path.lexists(target):
        raise FMError('%s already exists.' % target)
    if os.path.isdir(source) and not os.path.islink(source) and \
            (target + '/').startswith(source.rstrip('/') + '/'):
        raise FMError('Cannot copy or move a directory into itself.')
    return target


def copy(paths, destination_dir, unlock=False, actor=''):
    done = []
    for source in paths:
        source = clean_path(source)
        if not os.path.lexists(source):
            raise FMError('%s does not exist.' % source)
        target = _destination(source, destination_dir, unlock)
        if os.path.isdir(source) and not os.path.islink(source):
            shutil.copytree(source, target, symlinks=True)
        else:
            shutil.copy2(source, target, follow_symlinks=False)
        done.append(target)
    audit('copy', actor, paths=list(paths), to=destination_dir)
    return {'copied': done}


def move(paths, destination_dir, unlock=False, actor=''):
    done = []
    for source in paths:
        source = check_writable(source, unlock)
        target = _destination(source, destination_dir, unlock)
        shutil.move(source, target)
        done.append(target)
    audit('move', actor, paths=list(paths), to=destination_dir)
    return {'moved': done}


def trash(paths, unlock=False, actor='', trash_dir=None):
    trash_dir = trash_dir or TRASH_DIR
    os.makedirs(trash_dir, mode=0o700, exist_ok=True)
    moved = []
    for source in paths:
        source = check_writable(source, unlock)
        if not os.path.lexists(source):
            raise FMError('%s does not exist.' % source)
        if (source + '/').startswith(trash_dir.rstrip('/') + '/'):
            raise FMError('Use purge to delete items that are already in the trash.')
        item_id = '%d-%s' % (int(time.time() * 1000), os.urandom(3).hex())
        item_dir = os.path.join(trash_dir, item_id)
        os.mkdir(item_dir, 0o700)
        with open(os.path.join(item_dir, 'origin.json'), 'w') as handle:
            json.dump({'path': source, 'deleted': int(time.time()), 'actor': actor}, handle)
        shutil.move(source, os.path.join(item_dir, 'item'))
        moved.append({'id': item_id, 'path': source})
    audit('trash', actor, paths=list(paths))
    return {'trashed': moved}


def list_trash(trash_dir=None):
    trash_dir = trash_dir or TRASH_DIR
    items = []
    if os.path.isdir(trash_dir):
        for item_id in sorted(os.listdir(trash_dir), reverse=True):
            try:
                with open(os.path.join(trash_dir, item_id, 'origin.json')) as handle:
                    origin = json.load(handle)
                payload = os.path.join(trash_dir, item_id, 'item')
                items.append({'id': item_id, 'path': origin['path'], 'deleted': origin['deleted'],
                              'type': 'dir' if os.path.isdir(payload) and not os.path.islink(payload) else 'file'})
            except (OSError, ValueError, KeyError):
                continue
    return {'items': items}


def _trash_item(item_id, trash_dir):
    if not isinstance(item_id, str) or not item_id or '/' in item_id or item_id.startswith('.'):
        raise FMError('Invalid trash item.')
    item_dir = os.path.join(trash_dir, item_id)
    if not os.path.isdir(item_dir):
        raise FMError('Trash item not found.')
    return item_dir


def restore(item_id, unlock=False, actor='', trash_dir=None):
    trash_dir = trash_dir or TRASH_DIR
    item_dir = _trash_item(item_id, trash_dir)
    with open(os.path.join(item_dir, 'origin.json')) as handle:
        origin = check_writable(json.load(handle)['path'], unlock)
    if os.path.lexists(origin):
        raise FMError('%s exists again; move it away before restoring.' % origin)
    os.makedirs(os.path.dirname(origin), exist_ok=True)
    shutil.move(os.path.join(item_dir, 'item'), origin)
    shutil.rmtree(item_dir)
    audit('restore', actor, path=origin)
    return {'restored': origin}


def purge(item_ids, actor='', trash_dir=None):
    trash_dir = trash_dir or TRASH_DIR
    for item_id in item_ids:
        shutil.rmtree(_trash_item(item_id, trash_dir))
    audit('purge', actor, items=list(item_ids))
    return {'purged': list(item_ids)}


def chmod(paths, mode, recursive=False, unlock=False, actor=''):
    if not isinstance(mode, str) or not mode.isdigit() or len(mode) not in (3, 4) or any(c > '7' for c in mode):
        raise FMError('Mode must be 3 or 4 octal digits, e.g. 0644.')
    value = int(mode, 8)
    for path in paths:
        path = check_writable(path, unlock)
        targets = [path]
        if recursive and os.path.isdir(path) and not os.path.islink(path):
            for root, dirs, files in os.walk(path):
                targets.extend(os.path.join(root, name) for name in dirs + files)
        for target in targets:
            if not os.path.islink(target):
                os.chmod(target, value)
    audit('chmod', actor, paths=list(paths), mode=mode, recursive=bool(recursive))
    return {'mode': mode}


def chown(paths, owner, group='', recursive=False, unlock=False, actor=''):
    try:
        uid = pwd.getpwnam(owner).pw_uid
    except (KeyError, TypeError):
        raise FMError('Unknown user %r.' % owner)
    gid = -1
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            raise FMError('Unknown group %r.' % group)
    for path in paths:
        path = check_writable(path, unlock)
        targets = [path]
        if recursive and os.path.isdir(path) and not os.path.islink(path):
            for root, dirs, files in os.walk(path):
                targets.extend(os.path.join(root, name) for name in dirs + files)
        for target in targets:
            os.lchown(target, uid, gid)
    audit('chown', actor, paths=list(paths), owner=owner, group=group, recursive=bool(recursive))
    return {'owner': owner, 'group': group}


def _safe_member(destination, name):
    target = os.path.normpath(os.path.join(destination, name))
    if os.path.isabs(name) or not (target + '/').startswith(destination.rstrip('/') + '/'):
        raise FMError('Archive member %r would be extracted outside the destination.' % name)
    return target


def extract(archive, destination_dir, unlock=False, actor=''):
    archive = clean_path(archive)
    destination = check_writable(destination_dir, unlock)
    if not os.path.isdir(destination):
        raise FMError('%s is not a directory.' % destination)
    count = 0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                _safe_member(destination, member.filename)
            bundle.extractall(destination)
            count = len(bundle.infolist())
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            for member in members:
                _safe_member(destination, member.name)
                if member.issym() or member.islnk():
                    _safe_member(destination, os.path.join(os.path.dirname(member.name), member.linkname))
                if member.isdev():
                    raise FMError('Archive contains device files; refusing to extract.')
            bundle.extractall(destination, members=members)
            count = len(members)
    else:
        raise FMError('Unsupported archive (zip, tar, tar.gz, tar.bz2, tar.xz).')
    audit('extract', actor, archive=archive, to=destination, members=count)
    return {'extracted': count, 'to': destination}


def compress(paths, destination_dir, archive_name, fmt='tar.gz', unlock=False, actor=''):
    archive_name = _validate_name(archive_name)
    modes = {'zip': None, 'tar': 'w', 'tar.gz': 'w:gz', 'tar.bz2': 'w:bz2', 'tar.xz': 'w:xz'}
    if fmt not in modes:
        raise FMError('Invalid archive format.')
    if not archive_name.endswith('.' + fmt):
        archive_name += '.' + fmt
    target = check_writable(os.path.join(clean_path(destination_dir), archive_name), unlock)
    if os.path.lexists(target):
        raise FMError('%s already exists.' % target)
    sources = [clean_path(p) for p in paths]
    if fmt == 'zip':
        with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as bundle:
            for source in sources:
                base = os.path.dirname(source)
                if os.path.isdir(source):
                    for root, dirs, files in os.walk(source):
                        for name in files:
                            full = os.path.join(root, name)
                            bundle.write(full, os.path.relpath(full, base))
                else:
                    bundle.write(source, os.path.basename(source))
    else:
        with tarfile.open(target, modes[fmt]) as bundle:
            for source in sources:
                bundle.add(source, arcname=os.path.basename(source))
    os.chmod(target, 0o600)
    audit('compress', actor, paths=sources, archive=target)
    return describe(target)


def search(root, pattern, max_results=MAX_SEARCH_RESULTS, max_seconds=20):
    """Case-insensitive file-name substring search under root, without crossing filesystems."""
    root = clean_path(root)
    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 200:
        raise FMError('Enter a name to search for.')
    needle = pattern.strip().lower()
    device = os.lstat(root).st_dev
    deadline = time.monotonic() + max_seconds
    results, complete = [], True
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not _under(os.path.join(current, d), READ_ONLY)
                   and _same_device(os.path.join(current, d), device)]
        for name in dirs + files:
            if needle in name.lower():
                try:
                    results.append(describe(os.path.join(current, name), name))
                except OSError:
                    continue
                if len(results) >= max_results:
                    return {'results': results, 'complete': False}
        if time.monotonic() > deadline:
            complete = False
            break
    return {'results': results, 'complete': complete}


def _same_device(path, device):
    try:
        return os.lstat(path).st_dev == device
    except OSError:
        return False


def disk_usage(path, max_seconds=20):
    """Size of a directory tree (apparent bytes), without following symlinks."""
    path = clean_path(path)
    total, files, deadline = 0, 0, time.monotonic() + max_seconds
    for current, dirs, names in os.walk(path):
        for name in names:
            try:
                total += os.lstat(os.path.join(current, name)).st_size
                files += 1
            except OSError:
                continue
        if time.monotonic() > deadline:
            return {'path': path, 'bytes': total, 'files': files, 'complete': False}
    return {'path': path, 'bytes': total, 'files': files, 'complete': True}


def checksum(path):
    path = clean_path(path)
    if not os.path.isfile(path):
        raise FMError('%s is not a regular file.' % path)
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return {'path': path, 'sha256': digest.hexdigest()}
