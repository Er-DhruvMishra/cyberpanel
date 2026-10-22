import os

from django.http import FileResponse, HttpResponse

from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, is_admin, ok

MAX_UPLOAD_BYTES = 50 * 1024 * 1024


def _actor(request):
    try:
        from loginSystem.models import Administrator
        return Administrator.objects.get(pk=request.session['userID']).userName
    except Exception:
        return ''


def _call(action, **args):
    try:
        return ok(result=privileged.call('rootfm', action, **args))
    except RuntimeError as exc:
        message = str(exc)
        if message.startswith('PROTECTED:'):
            return error(message[len('PROTECTED:'):], protected=1)
        return error(message)


def _str(data, key, required=True, limit=4096):
    value = data.get(key, '')
    if not isinstance(value, str) or (required and not value) or len(value) > limit:
        raise ValueError('Invalid or missing %s.' % key)
    return value


def _paths(data):
    paths = data.get('paths')
    if not isinstance(paths, list) or not paths or len(paths) > 500 or \
            not all(isinstance(p, str) and p.startswith('/') and len(p) < 4096 for p in paths):
        raise ValueError('Select between 1 and 500 items.')
    return paths


def _unlock(data):
    return data.get('unlock') is True


def page(request):
    return httpProc(request, 'universalAddons/rootfm.html', {'start': data_start()}, 'admin').render()


def data_start():
    return '/home'


@admin_api
def listing(request, data):
    return _call('list', path=_str(data, 'path'), show_hidden=data.get('showHidden') is not False)


@admin_api
def read(request, data):
    return _call('read', path=_str(data, 'path'))


@admin_api
def write(request, data):
    # 'fileContent' is the key CyberPanel's input filter reserves for file contents.
    content = data.get('fileContent')
    if not isinstance(content, str):
        return error('Invalid content.', status=400)
    return _call('write', path=_str(data, 'path'), content=content,
                 expected_sha256=_str(data, 'sha256', required=False, limit=64) or None,
                 unlock=_unlock(data), actor=_actor(request))


@admin_api
def create(request, data):
    kind = data.get('kind')
    if kind not in ('file', 'dir'):
        return error('Invalid type.', status=400)
    return _call('create', directory=_str(data, 'directory'), name=_str(data, 'name', limit=255), kind=kind,
                 unlock=_unlock(data), actor=_actor(request))


@admin_api
def rename(request, data):
    return _call('rename', path=_str(data, 'path'), new_name=_str(data, 'name', limit=255),
                 unlock=_unlock(data), actor=_actor(request))


@admin_api
def copy(request, data):
    return _call('copy', paths=_paths(data), destination=_str(data, 'destination'), unlock=_unlock(data),
                 actor=_actor(request))


@admin_api
def move(request, data):
    return _call('move', paths=_paths(data), destination=_str(data, 'destination'), unlock=_unlock(data),
                 actor=_actor(request))


@admin_api
def trash(request, data):
    return _call('trash', paths=_paths(data), unlock=_unlock(data), actor=_actor(request))


@admin_api
def list_trash(request, data):
    return _call('list_trash')


@admin_api
def restore(request, data):
    return _call('restore', item_id=_str(data, 'id', limit=64), unlock=_unlock(data), actor=_actor(request))


@admin_api
def purge(request, data):
    ids = data.get('ids')
    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) and len(i) < 64 for i in ids):
        return error('Select trash items to purge.', status=400)
    return _call('purge', item_ids=ids, actor=_actor(request))


@admin_api
def chmod(request, data):
    return _call('chmod', paths=_paths(data), mode=_str(data, 'mode', limit=4), recursive=data.get('recursive') is True,
                 unlock=_unlock(data), actor=_actor(request))


@admin_api
def chown(request, data):
    return _call('chown', paths=_paths(data), owner=_str(data, 'owner', limit=32),
                 group=_str(data, 'group', required=False, limit=32), recursive=data.get('recursive') is True,
                 unlock=_unlock(data), actor=_actor(request))


@admin_api
def extract(request, data):
    return _call('extract', archive=_str(data, 'path'), destination=_str(data, 'destination'),
                 unlock=_unlock(data), actor=_actor(request))


@admin_api
def compress(request, data):
    fmt = data.get('format', 'tar.gz')
    if fmt not in ('zip', 'tar', 'tar.gz', 'tar.bz2', 'tar.xz'):
        return error('Invalid archive format.', status=400)
    return _call('compress', paths=_paths(data), destination=_str(data, 'destination'),
                 name=_str(data, 'name', limit=255), fmt=fmt, unlock=_unlock(data), actor=_actor(request))


@admin_api
def search(request, data):
    return _call('search', root=_str(data, 'path'), pattern=_str(data, 'pattern', limit=200))


@admin_api
def du(request, data):
    return _call('du', path=_str(data, 'path'))


@admin_api
def checksum(request, data):
    return _call('checksum', path=_str(data, 'path'))


def upload(request):
    """Multipart upload: the file is spooled privately, then moved into place by root."""
    admin = is_admin(request)
    if not admin:
        return error('Administrator access is required.', status=401 if admin is None else 403)
    if request.method != 'POST':
        return error('POST required.', status=405)
    uploaded = request.FILES.get('file')
    directory = request.POST.get('directory', '')
    if not uploaded or not directory.startswith('/'):
        return error('Choose a file and a destination directory.', status=400)
    if uploaded.size > MAX_UPLOAD_BYTES:
        return error('Uploads are limited to 50 MB here; use SFTP for larger files.', status=400)
    spool_dir = privileged.SPOOL_DIR
    os.makedirs(spool_dir, mode=0o700, exist_ok=True)
    spool_id = privileged.new_spool_id()
    fd = os.open(privileged.spool_path(spool_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        for chunk in uploaded.chunks():
            handle.write(chunk)
    response = _call('upload', spool_id=spool_id, directory=directory, name=os.path.basename(uploaded.name),
                     unlock=request.POST.get('unlock') == '1', actor=_actor(request))
    try:
        os.unlink(privileged.spool_path(spool_id))
    except OSError:
        pass
    return response


def download(request):
    admin = is_admin(request)
    if not admin:
        return HttpResponse('Administrator access is required.', status=401 if admin is None else 403)
    path = request.GET.get('path', '')
    if not path.startswith('/'):
        return HttpResponse('Invalid path.', status=400)
    try:
        staged = privileged.call('rootfm', 'download', path=path)
    except RuntimeError as exc:
        return HttpResponse(str(exc), status=400, content_type='text/plain')
    spool = privileged.spool_path(staged['spool_id'])
    handle = open(spool, 'rb')
    os.unlink(spool)  # the open handle keeps the data until the response is sent
    return FileResponse(handle, as_attachment=True, filename=staged['name'])
