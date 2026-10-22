"""Run add-on actions as root through runner.py.

The web process is not root; CyberPanel executes root commands through lscpd (or a shell
when already root). To keep request data away from any shell, the command line only ever
contains fixed paths, a whitelisted module/action pair and the arguments as URL-safe base64
(alphabet A-Z a-z 0-9 - _ =). runner.py decodes them and does all work with argv lists.
"""
import base64
import json
import re

PYTHON = '/usr/local/CyberCP/bin/python'
RUNNER = '/usr/local/CyberCP/universalAddons/runner.py'
MARKER = '@@UA-RESULT@@'
_TOKEN = re.compile(r'^[a-z][a-z0-9_]{0,40}$')


def encode_args(args):
    return base64.urlsafe_b64encode(json.dumps(args).encode()).decode('ascii')


def decode_args(token):
    if not re.match(r'^[A-Za-z0-9_=-]*$', token or ''):
        raise ValueError('Invalid argument encoding.')
    return json.loads(base64.urlsafe_b64decode(token.encode('ascii')).decode('utf-8')) if token else {}


def build_command(module, action, args):
    if not _TOKEN.match(module) or not _TOKEN.match(action):
        raise ValueError('Invalid action name.')
    return '%s %s %s %s %s' % (PYTHON, RUNNER, module, action, encode_args(args or {}))


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
