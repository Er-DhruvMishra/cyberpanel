"""Daily request/token budgets, per-minute pacing and 429 cool-downs.

State is kept in ``usage.json`` next to the settings, guarded by an flock so
the web workers, the background scan process and the scheduler agree.
Counters reset at 00:00 UTC.
"""
import contextlib
import fcntl
import os
import time
from datetime import datetime, timezone

from . import settings_store

MAX_COOLDOWN = 3600
MAX_PACING_WAIT = 65


class BudgetExceeded(Exception):
    pass


def today(now=None):
    return datetime.fromtimestamp(now if now is not None else time.time(), tz=timezone.utc).strftime('%Y-%m-%d')


@contextlib.contextmanager
def _locked():
    directory = settings_store._ensure_dir()
    fd = os.open(os.path.join(directory, 'usage.lock'), os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        usage = settings_store.read_json('usage.json', {})
        yield usage
        settings_store.write_json('usage.json', usage)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _day(usage, now):
    day = today(now)
    if usage.get('day') != day:
        cooldowns = usage.get('cooldown', {})
        usage.clear()
        usage.update({'day': day, 'buckets': {}, 'scans': {}, 'cooldown': cooldowns})
    usage.setdefault('buckets', {})
    usage.setdefault('scans', {})
    usage.setdefault('cooldown', {})
    return usage


def _bucket(usage, name):
    return usage['buckets'].setdefault(name, {'requests': 0, 'tokens': 0, 'recent': []})


def reserve(bucket, estimated_tokens, budget, now=None):
    """Count one request against ``bucket``; raise BudgetExceeded if over a cap.

    Returns the number of seconds the caller should wait first to respect the
    requests-per-minute pacing (0 when it may go now).
    """
    now = time.time() if now is None else now
    with _locked() as usage:
        _day(usage, now)
        until = float(usage['cooldown'].get(bucket, 0) or 0)
        if until > now:
            raise BudgetExceeded('The provider asked us to slow down; AI analysis resumes in %d s.' % int(until - now + 1))
        state = _bucket(usage, bucket)
        if state['requests'] + 1 > int(budget.get('max_requests_per_day', 0)):
            raise BudgetExceeded('Daily AI request limit reached (%d).' % int(budget.get('max_requests_per_day', 0)))
        if state['tokens'] + int(estimated_tokens) > int(budget.get('max_tokens_per_day', 0)):
            raise BudgetExceeded('Daily AI token limit reached (%d).' % int(budget.get('max_tokens_per_day', 0)))
        rpm = max(1, int(budget.get('requests_per_minute', 1)))
        recent = [t for t in state.get('recent', []) if now - t < 60]
        wait = 0.0
        if len(recent) >= rpm:
            wait = max(0.0, 60 - (now - recent[-rpm]))
        if wait > MAX_PACING_WAIT:
            raise BudgetExceeded('Requests-per-minute limit reached.')
        recent.append(now + wait)
        state['recent'] = recent[-max(rpm, 1) * 2:]
        state['requests'] += 1
        state['tokens'] += int(estimated_tokens)
        return wait


def settle(bucket, estimated_tokens, actual_tokens, now=None):
    """Replace the estimate with the real token count once the provider answers."""
    now = time.time() if now is None else now
    with _locked() as usage:
        _day(usage, now)
        state = _bucket(usage, bucket)
        if actual_tokens:
            state['tokens'] = max(0, state['tokens'] - int(estimated_tokens) + int(actual_tokens))


def cool_down(bucket, seconds, now=None):
    now = time.time() if now is None else now
    seconds = 30 if seconds is None else max(1, min(int(seconds), MAX_COOLDOWN))
    with _locked() as usage:
        _day(usage, now)
        usage['cooldown'][bucket] = now + seconds


def try_start_user_scan(user_id, cap, now=None):
    """Count one AI scan for a non-admin user; False when today's cap is used up."""
    now = time.time() if now is None else now
    with _locked() as usage:
        _day(usage, now)
        key = str(int(user_id))
        used = int(usage['scans'].get(key, 0))
        if used >= int(cap):
            return False
        usage['scans'][key] = used + 1
        return True


def snapshot(now=None):
    """Usage for the settings page (no secrets in here)."""
    now = time.time() if now is None else now
    usage = settings_store.read_json('usage.json', {})
    if usage.get('day') != today(now):
        return {'day': today(now), 'buckets': {}, 'scans': {}}
    buckets = {name: {'requests': b.get('requests', 0), 'tokens': b.get('tokens', 0)}
               for name, b in (usage.get('buckets') or {}).items()}
    return {'day': usage['day'], 'buckets': buckets, 'scans': dict(usage.get('scans') or {})}
