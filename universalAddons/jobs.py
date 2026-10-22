"""Detached long-running add-on jobs with a polled status file (root side).

spawn() starts `runner.py <module> <action> <args>` in a new session with `job_id` added to the
arguments; the action reports progress through Job. Status files live in JOB_DIR (root-only) and
are read back through the runner, so the web process never touches them directly.
"""
import json
import os
import re
import subprocess
import sys
import time

JOB_DIR = os.environ.get('UA_JOB_DIR', '/var/lib/cyberpanel-universal/jobs')
_JOB_ID = re.compile(r'^[0-9a-f]{24}$')
MAX_LOG_LINES = 400


def _path(job_id):
    if not _JOB_ID.match(job_id or ''):
        raise ValueError('Invalid job id.')
    return os.path.join(JOB_DIR, job_id + '.json')


class Job:
    def __init__(self, job_id):
        self.path = _path(job_id)
        self.job_id = job_id
        try:
            with open(self.path) as handle:
                self.data = json.load(handle)
        except (OSError, ValueError):
            self.data = {'id': job_id, 'state': 'running', 'log': [], 'started': int(time.time())}

    def _save(self):
        self.data['updated'] = int(time.time())
        temporary = self.path + '.tmp'
        with open(temporary, 'w') as handle:
            json.dump(self.data, handle)
        os.replace(temporary, self.path)

    def log(self, text):
        lines = self.data.setdefault('log', [])
        lines.extend(str(text).rstrip('\n').splitlines()[-100:])
        del lines[:-MAX_LOG_LINES]
        self._save()

    def step(self, title):
        self.data['step'] = title
        self.log('==> ' + title)

    def done(self, result=None):
        self.data.update(state='done', result=result)
        self._save()

    def fail(self, error):
        self.data.update(state='failed', error=str(error)[:2000])
        self._save()


def spawn(module, action, args, python=sys.executable, runner_path=None):
    from universalAddons.privileged import encode_args
    os.makedirs(JOB_DIR, mode=0o700, exist_ok=True)
    job_id = os.urandom(12).hex()
    job = Job(job_id)
    job.data.update(module=module, action=action)
    job._save()
    runner_path = runner_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'runner.py')
    args = dict(args, job_id=job_id)
    with open(os.devnull, 'rb') as devnull_in, open(job.path + '.out', 'ab') as output:
        subprocess.Popen([python, runner_path, module, action, encode_args(args)], stdin=devnull_in,
                         stdout=output, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
    return {'job_id': job_id}


def status(job_id):
    path = _path(job_id)
    try:
        with open(path) as handle:
            data = json.load(handle)
    except OSError:
        raise ValueError('Unknown job.')
    if data.get('state') == 'running' and time.time() - data.get('updated', data.get('started', 0)) > 3600:
        data['state'] = 'stalled'
    return data


def run_job(job_id, steps):
    """Run (title, callable) steps under a Job, recording output and the first failure."""
    job = Job(job_id)
    results = {}
    try:
        for title, func in steps:
            job.step(title)
            outcome = func(job)
            if outcome is not None:
                results[title] = outcome
        job.done(results)
    except Exception as exc:
        job.log('ERROR: %s' % exc)
        job.fail(exc)
    return job.data
