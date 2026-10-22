"""Root-side Root File Manager actions (dispatched by universalAddons/runner.py)."""
import os
import shutil

from universalAddons import privileged
from universalAddons.rootfm import service
from universalAddons.rootfm.service import FMError

MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024


def _paths(paths):
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or not paths or len(paths) > 500:
        raise FMError('Select between 1 and 500 items.')
    return [service.clean_path(p) for p in paths]


def upload(spool_id, directory, name, unlock=False, actor=''):
    """Move an uploaded spool file into directory/name (never overwrites)."""
    target = service.check_writable(os.path.join(service.clean_path(directory), service._validate_name(name)), unlock)
    if os.path.lexists(target):
        raise FMError('%s already exists.' % target)
    if not os.path.isdir(os.path.dirname(target)):
        raise FMError('Directory does not exist.')
    path, handle = privileged.open_spool(spool_id, privileged.panel_uid())
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with handle, os.fdopen(fd, 'wb') as output:
            shutil.copyfileobj(handle, output, 1024 * 1024)
    finally:
        os.unlink(path)
    os.chown(target, 0, 0)
    service.audit('upload', actor, path=target, bytes=os.path.getsize(target))
    return service.describe(target)


def download(path):
    """Stage a copy of path in the spool for the web process to stream."""
    path = service.clean_path(path)
    if not os.path.isfile(path):
        raise FMError('%s is not a regular file.' % path)
    size = os.path.getsize(path)
    if size > MAX_DOWNLOAD_BYTES:
        raise FMError('Files over 1 GB must be fetched with SFTP/scp.')
    uid = privileged.panel_uid()
    spool_dir = privileged.SPOOL_DIR
    os.makedirs(spool_dir, mode=0o700, exist_ok=True)
    os.chown(spool_dir, uid, uid)
    spool_id = privileged.new_spool_id()
    target = privileged.spool_path(spool_id)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with open(path, 'rb') as source, os.fdopen(fd, 'wb') as output:
        shutil.copyfileobj(source, output, 1024 * 1024)
    os.chown(target, uid, uid)
    return {'spool_id': spool_id, 'name': os.path.basename(path), 'size': size}


ACTIONS = {
    'list': lambda path, show_hidden=True: service.list_dir(path, show_hidden),
    'read': lambda path: service.read_file(path),
    'write': lambda path, content, expected_sha256=None, unlock=False, actor='':
        service.write_file(path, content, expected_sha256, unlock, actor),
    'create': lambda directory, name, kind, unlock=False, actor='':
        service.create(directory, name, kind, unlock, actor),
    'rename': lambda path, new_name, unlock=False, actor='': service.rename(path, new_name, unlock, actor),
    'copy': lambda paths, destination, unlock=False, actor='':
        service.copy(_paths(paths), destination, unlock, actor),
    'move': lambda paths, destination, unlock=False, actor='':
        service.move(_paths(paths), destination, unlock, actor),
    'trash': lambda paths, unlock=False, actor='': service.trash(_paths(paths), unlock, actor),
    'list_trash': lambda: service.list_trash(),
    'restore': lambda item_id, unlock=False, actor='': service.restore(item_id, unlock, actor),
    'purge': lambda item_ids, actor='': service.purge(list(item_ids), actor),
    'chmod': lambda paths, mode, recursive=False, unlock=False, actor='':
        service.chmod(_paths(paths), mode, recursive, unlock, actor),
    'chown': lambda paths, owner, group='', recursive=False, unlock=False, actor='':
        service.chown(_paths(paths), owner, group, recursive, unlock, actor),
    'extract': lambda archive, destination, unlock=False, actor='':
        service.extract(archive, destination, unlock, actor),
    'compress': lambda paths, destination, name, fmt='tar.gz', unlock=False, actor='':
        service.compress(_paths(paths), destination, name, fmt, unlock, actor),
    'search': lambda root, pattern: service.search(root, pattern),
    'du': lambda path: service.disk_usage(path),
    'checksum': lambda path: service.checksum(path),
    'upload': upload,
    'download': download,
}
