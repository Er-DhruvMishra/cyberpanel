#!/usr/local/CyberCP/bin/python
"""acme.sh --reloadcmd: wire the renewed certificate into the vhost and reload services."""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def main(argv):
    domain = argv[1] if len(argv) == 2 else ''
    if not re.match(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$', domain):
        return 2
    from universalAddons import django_env
    django_env.setup()
    from plogical.sslUtilities import sslUtilities
    sslUtilities.installSSLForDomain(domain)
    for argv_ in (['/usr/local/lsws/bin/lswsctrl', 'restart'], ['systemctl', 'reload', 'postfix'],
                  ['systemctl', 'reload', 'dovecot']):
        subprocess.call(argv_, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
