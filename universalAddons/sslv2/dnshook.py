#!/usr/local/CyberCP/bin/python
"""Add/remove an _acme-challenge TXT record in the local PowerDNS zone (called by acme.sh)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

NAME_RE = re.compile(r'^_acme-challenge\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
VALUE_RE = re.compile(r'^[A-Za-z0-9_-]{20,128}$')


def find_zone(name, zones):
    """Longest zone name that name belongs to."""
    candidates = [z for z in zones if name == z or name.endswith('.' + z)]
    return max(candidates, key=len) if candidates else None


def main(argv):
    if len(argv) != 4 or argv[1] not in ('add', 'rm'):
        sys.stderr.write('usage: dnshook.py add|rm <fulldomain> <txtvalue>\n')
        return 2
    action, name, value = argv[1], argv[2].rstrip('.').lower(), argv[3]
    if not NAME_RE.match(name) or not VALUE_RE.match(value):
        sys.stderr.write('dns_cpuniversal: refusing unexpected record %r\n' % name)
        return 2
    from universalAddons import django_env
    django_env.setup()
    from dns.models import Domains, Records
    from plogical.dnsUtilities import DNS
    zone_name = find_zone(name, list(Domains.objects.values_list('name', flat=True)))
    if not zone_name:
        sys.stderr.write('dns_cpuniversal: no local DNS zone for %s\n' % name)
        return 1
    zone = Domains.objects.get(name=zone_name)
    if action == 'add':
        DNS.createDNSRecord(zone, name, 'TXT', value, 0, 60)
    else:
        for record in Records.objects.filter(domainOwner=zone, name=name, type='TXT', content=value):
            DNS.deleteDNSRecord(record.id)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
