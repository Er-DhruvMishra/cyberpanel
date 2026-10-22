"""Run add-on actions as root through runner.py.

The web process is not root; CyberPanel executes root commands through lscpd (or a shell
when already root). To keep request data away from any shell, the command line only ever
contains fixed paths, a whitelisted module/action pair and the arguments as URL-safe base64
(alphabet A-Z a-z 0-9 - _ =). runner.py decodes them and does all work with argv lists.
"""
import base64
import json
import os
import re
import stat

PYTHON = '/usr/local/CyberCP/bin/python'
RUNNER = '/usr/local/CyberCP/universalAddons/runner.py'
MARKER = '@@UA-RESULT@@'
_TOKEN = re.compile(r'^[a-z][a-z0-9_]{0,40}$')
_SPOOL_ID = re.compile(r'^[0-9a-f]{32}$')

# Payloads too large for one command-line argument (Linux caps an argument at 128 KiB), and
# file uploads/downloads, pass through this directory. It belongs to the panel user
# (cyberpanel) with mode 0700; the root side only trusts regular files owned by that user.
SPOOL_DIR = os.environ.get('UA_SPOOL_DIR', '/home/cyberpanel/ua-spool')
PANEL_USER = 'cyberpanel'
INLINE_LIMIT = 64 * 1024


def encode_args(args):
    return base64.urlsafe_b64encode(json.dumps(args).encode()).decode('ascii')


def decode_args(token):
    if not re.match(r'^[A-Za-z0-9_=-]*$', token or ''):
        raise ValueError('Invalid argument encoding.')
    return json.loads(base64.urlsafe_b64decode(token.encode('ascii')).decode('utf-8')) if token else {}


def new_spool_id():
    return os.urandom(16).hex()


def spool_path(spool_id, spool_dir=None):
    if not _SPOOL_ID.match(spool_id or ''):
        raise ValueError('Invalid spool id.')
    return os.path.join(spool_dir or SPOOL_DIR, spool_id)


def write_spool(data, spool_dir=None):
    """Web side: store bytes in a new private spool file and return its id."""
    spool_dir = spool_dir or SPOOL_DIR
    os.makedirs(spool_dir, mode=0o700, exist_ok=True)
    spool_id = new_spool_id()
    fd = os.open(spool_path(spool_id, spool_dir), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    return spool_id


def open_spool(spool_id, expected_uid, spool_dir=None):
    """Root side: open a spool file only if it is a private regular file of the panel user."""
    path = spool_path(spool_id, spool_dir)
    directory = os.lstat(os.path.dirname(path))
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != expected_uid or directory.st_mode & 0o077:
        raise ValueError('Spool directory has unsafe ownership or permissions.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError('Spool file has unsafe ownership or permissions.')
    return path, os.fdopen(fd, 'rb')


def panel_uid():
    import pwd
    return pwd.getpwnam(PANEL_USER).pw_uid


def read_spool_args(spool_id, expected_uid=None, spool_dir=None):
    path, handle = open_spool(spool_id, panel_uid() if expected_uid is None else expected_uid, spool_dir)
    with handle:
        data = handle.read()
    os.unlink(path)
    return json.loads(data.decode('utf-8'))


def build_command(module, action, args, spool_dir=None):
    if not _TOKEN.match(module) or not _TOKEN.match(action):
        raise ValueError('Invalid action name.')
    token = encode_args(args or {})
    if len(token) > INLINE_LIMIT:
        spool_id = write_spool(json.dumps(args).encode('utf-8'), spool_dir)
        return '%s %s %s %s --spool %s' % (PYTHON, RUNNER, module, action, spool_id)
    return '%s %s %s %s %s' % (PYTHON, RUNNER, module, action, token)


def parse_output(output):
    """Return the result dict from runner output, or raise RuntimeError with its error."""
    for line in reversed((output or '').splitlines()):
        if line.startswith(MARKER):
            payload = json.loads(line[len(MARKER):])
            if payload.get('ok'):
                return payload.get('result')
            raise RuntimeError(payload.get('error') or 'Action failed.')
    raise RuntimeError('No result from the privileged runner: %s' % (output or '').strip()[-300:])


def call(module, action, executor=None, **args):
    if executor is None:
        from plogical.processUtilities import ProcessUtilities
        executor = ProcessUtilities.outputExecutioner
    response = executor(build_command(module, action, args), retRequired=True)
    output = response[1] if isinstance(response, tuple) else response
    return parse_output(output if isinstance(output, str) else '')
