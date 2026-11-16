#!/usr/local/CyberCP/bin/python
"""Minute cron for uptime checks and queued notifications. Runs as the panel user, never as root.

/etc/cron.d/cyberpanel-universal-uptime:
  * * * * * cyberpanel /usr/local/CyberCP/bin/python /usr/local/CyberCP/universalAddons/uptime/cron.py >/dev/null 2>&1
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PANEL_USER = 'cyberpanel'
LOCK = os.environ.get('UA_UPTIME_LOCK', '/home/cyberpanel/ua-uptime/cron.lock')


def drop_root():
    """Started as root by mistake: become the panel user before touching anything."""
    if os.geteuid() != 0:
        return
    import pwd
    entry = pwd.getpwnam(PANEL_USER)
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)
    os.environ['HOME'] = entry.pw_dir


def main():
    drop_root()
    os.umask(0o077)
    import fcntl
    from universalAddons.notify import service as notify
    from universalAddons.uptime import service
    os.makedirs(os.path.dirname(LOCK), mode=0o700, exist_ok=True)
    handle = open(LOCK, 'a')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0   # the previous run is still busy
    try:
        os.nice(10)
    except OSError:
        pass
    now = time.time()
    with service.opened() as db:
        service.run_due(db, now)
        last = db.execute("SELECT value FROM meta WHERE key = 'pruned'").fetchone()
        if not last or now - float(last[0]) > 3600:
            service.prune(db, now)
            db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned', ?)", (str(now),))
    notify.flush_outbox()
    return 0


if __name__ == '__main__':
    sys.exit(main())
