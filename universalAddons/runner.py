#!/usr/local/CyberCP/bin/python
"""Root-side entry point for add-on actions. See privileged.py.

Usage: runner.py <module> <action> <base64-json-args>
Prints one line: @@UA-RESULT@@{"ok": true, "result": ...} or {"ok": false, "error": "..."}.
"""
import importlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from universalAddons.privileged import MARKER, decode_args, read_spool_args  # noqa: E402

# module -> python module exposing ACTIONS = {name: callable(**args)}
MODULES = {
    'emaildebug': 'universalAddons.emaildebug.actions',
    'rootfm': 'universalAddons.rootfm.actions',
}


def run(argv):
    if len(argv) == 5 and argv[3] == '--spool':
        _, module, action, _, spool_id = argv
        args = read_spool_args(spool_id)
    elif len(argv) == 4:
        _, module, action, token = argv
        args = decode_args(token)
    else:
        raise ValueError('usage: runner.py <module> <action> <args> | --spool <id>')
    if module not in MODULES:
        raise ValueError('Unknown module.')
    actions = importlib.import_module(MODULES[module]).ACTIONS
    if action not in actions:
        raise ValueError('Unknown action.')
    return actions[action](**args)


def main(argv=None):
    try:
        payload = {'ok': True, 'result': run(argv or sys.argv)}
        code = 0
    except Exception as exc:  # report every failure as JSON for the web process
        payload = {'ok': False, 'error': str(exc)[:2000]}
        code = 1
    sys.stdout.write(MARKER + json.dumps(payload, default=str) + '\n')
    sys.stdout.flush()
    return code


if __name__ == '__main__':
    sys.exit(main())
