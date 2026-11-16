"""DNS back ends for free subdomains.

Every provider offers the same three calls:

  test()                          check settings and credentials; creates nothing
  create(fqdn, ipv4, ipv6, ttl)   add A (and AAAA) records; returns references for delete()
  delete(fqdn, refs)              remove exactly the records create() added

Errors are raised as ProviderError with a message that is safe to show (never a token).
"""
import json
import time

API_TIMEOUT = (5, 20)


class ProviderError(Exception):
    pass


def _suffixes(name):
    """'a.b.example.com' -> ['a.b.example.com', 'b.example.com', 'example.com', 'com']"""
    parts = name.split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts))]


def _requests():
    import requests
    return requests


# ------------------------------------------------------------------------------------ PowerDNS

class LocalPowerDNS:
    """Records in a zone this server's PowerDNS is authoritative for, written with the panel's DNS code."""

    key = 'powerdns'
    title = 'Local PowerDNS zone'

    def __init__(self, base, dns_models=None, dns_utilities=None):
        self.base = base
        self._models = dns_models
        self._dns = dns_utilities

    def models(self):
        if self._models is None:
            from dns import models
            self._models = models
        return self._models

    def dns(self):
        if self._dns is None:
            from plogical.dnsUtilities import DNS
            self._dns = DNS
        return self._dns

    def zone(self):
        """The most specific panel zone that contains the base name."""
        Domains = self.models().Domains
        for name in _suffixes(self.base)[:-1]:
            zone = Domains.objects.filter(name=name).first()
            if zone is not None:
                if (zone.type or '').upper() not in ('NATIVE', 'MASTER'):
                    raise ProviderError('Zone %s is a %s zone on this server; free subdomains need a NATIVE or '
                                        'MASTER zone.' % (zone.name, zone.type))
                return zone
        raise ProviderError('This server has no DNS zone for %s. Create the zone in DNS > Create Zone first, '
                            'or choose another provider.' % self.base)

    def bump_serial(self, zone):
        """Increase the SOA serial. The panel helper only does this for MASTER zones; do NATIVE ones here."""
        if (zone.type or '').upper() == 'MASTER':
            return  # createDNSRecord / deleteDNSRecord already bumped it
        Records = self.models().Records
        for soa in Records.objects.filter(domainOwner=zone, type='SOA'):
            fields = (soa.content or '').split()
            if len(fields) >= 3 and fields[2].isdigit():
                fields[2] = str(int(fields[2]) + 1)
                soa.content = ' '.join(fields)
                soa.save(update_fields=['content'])

    def test(self):
        zone = self.zone()
        Records = self.models().Records
        ns = sorted(r.content for r in Records.objects.filter(domainOwner=zone, type='NS'))
        if not Records.objects.filter(domainOwner=zone, type='SOA').exists():
            raise ProviderError('Zone %s has no SOA record.' % zone.name)
        clash = Records.objects.filter(domainOwner=zone, name='*.' + self.base).exists()
        message = 'Zone %s (id %s, %s) is served by this server%s.' % (
            zone.name, zone.pk, zone.type, ' with name servers ' + ', '.join(ns) if ns else '')
        if clash:
            message += ' Note: a wildcard record *.%s already exists.' % self.base
        return message

    def create(self, fqdn, ipv4, ipv6, ttl):
        zone = self.zone()
        Records = self.models().Records
        if Records.objects.filter(name=fqdn).exists():
            raise ProviderError('%s already has DNS records.' % fqdn)
        wanted = [('A', ipv4)] + ([('AAAA', ipv6)] if ipv6 else [])
        created = []
        try:
            for rtype, value in wanted:
                self.dns().createDNSRecord(zone, fqdn, rtype, value, 0, ttl)
                record = Records.objects.filter(domainOwner=zone, name=fqdn, type=rtype, content=value).first()
                if record is None:
                    raise ProviderError('The %s record for %s could not be written.' % (rtype, fqdn))
                created.append(record.pk)
        except Exception:
            for pk in created:
                Records.objects.filter(pk=pk).delete()
            raise
        self.bump_serial(zone)
        return {'zone': zone.name, 'record_ids': created}

    def delete(self, fqdn, refs):
        zone = self.zone()
        Records = self.models().Records
        ids = [int(i) for i in (refs or {}).get('record_ids', []) if str(i).isdigit()]
        # Only ever our own A/AAAA records for exactly this name.
        records = Records.objects.filter(domainOwner=zone, name=fqdn, type__in=('A', 'AAAA'))
        if ids:
            records = records.filter(pk__in=ids)
        removed = 0
        for record in list(records):
            self.dns().deleteDNSRecord(record.pk)
            removed += 1
        if removed:
            self.bump_serial(zone)
        return removed


# ---------------------------------------------------------------------------------- Cloudflare

class Cloudflare:
    key = 'cloudflare'
    title = 'Cloudflare'
    API = 'https://api.cloudflare.com/client/v4'

    def __init__(self, base, zone_id, token, http=None):
        self.base, self.zone_id, self.token = base, zone_id, token
        self.http = http

    def _call(self, method, path, **kwargs):
        if not self.zone_id or not self.token:
            raise ProviderError('Enter the Cloudflare zone ID and API token.')
        http = self.http or _requests()
        try:
            response = http.request(method, self.API + path, timeout=API_TIMEOUT, allow_redirects=False,
                                    headers={'Authorization': 'Bearer ' + self.token,
                                             'Content-Type': 'application/json'}, **kwargs)
        except Exception as exc:
            raise ProviderError('Could not reach Cloudflare: %s' % type(exc).__name__)
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code >= 400 or not body.get('success', False):
            errors = '; '.join(str(e.get('message', '')) for e in body.get('errors') or [] if isinstance(e, dict))
            raise ProviderError('Cloudflare refused the request (HTTP %s)%s' % (
                response.status_code, ': ' + errors if errors else '.'))
        return body.get('result')

    def test(self):
        zone = self._call('GET', '/zones/%s' % self.zone_id) or {}
        name = (zone.get('name') or '').lower()
        if not (self.base == name or self.base.endswith('.' + name)):
            raise ProviderError('Zone %s does not contain %s.' % (name or self.zone_id, self.base))
        self._call('GET', '/zones/%s/dns_records' % self.zone_id, params={'per_page': 1})
        return 'The token can read zone %s and its DNS records. Write access is used when the first ' \
               'subdomain is created (the token needs Zone.DNS Edit).' % name

    def create(self, fqdn, ipv4, ipv6, ttl):
        existing = self._call('GET', '/zones/%s/dns_records' % self.zone_id, params={'name': fqdn})
        if existing:
            raise ProviderError('%s already has DNS records in Cloudflare.' % fqdn)
        ids = []
        try:
            for rtype, value in [('A', ipv4)] + ([('AAAA', ipv6)] if ipv6 else []):
                record = self._call('POST', '/zones/%s/dns_records' % self.zone_id, data=json.dumps(
                    {'type': rtype, 'name': fqdn, 'content': value, 'ttl': ttl, 'proxied': False,
                     'comment': 'IndiansCloud free subdomain'}))
                ids.append(record['id'])
        except Exception:
            for record_id in ids:
                try:
                    self._call('DELETE', '/zones/%s/dns_records/%s' % (self.zone_id, record_id))
                except ProviderError:
                    pass
            raise
        return {'zone_id': self.zone_id, 'record_ids': ids}

    def delete(self, fqdn, refs):
        ids = [i for i in (refs or {}).get('record_ids', []) if isinstance(i, str) and i.isalnum()]
        for record_id in ids:
            self._call('DELETE', '/zones/%s/dns_records/%s' % (self.zone_id, record_id))
        return len(ids)


# --------------------------------------------------------------------------------------- deSEC

class Desec:
    """deSEC (https://desec.io): a dedyn.io name or your own zone hosted there.

    API: GET /domains/?owns_qname=<name> finds the zone, records are RRsets addressed by subname.
    Writes use the bulk endpoint so each change costs deSEC one DNSSEC signing operation.
    """
    key = 'desec'
    title = 'deSEC'
    API = 'https://desec.io/api/v1'

    def __init__(self, base, token, http=None):
        self.base, self.token = base, token
        self.http = http
        self._domain = None

    def _call(self, method, path, expect=(200,), **kwargs):
        if not self.token:
            raise ProviderError('Enter the deSEC API token.')
        http = self.http or _requests()
        for attempt in range(2):
            try:
                response = http.request(method, self.API + path, timeout=API_TIMEOUT, allow_redirects=False,
                                        headers={'Authorization': 'Token ' + self.token,
                                                 'Content-Type': 'application/json'}, **kwargs)
            except Exception as exc:
                raise ProviderError('Could not reach deSEC: %s' % type(exc).__name__)
            if response.status_code == 429 and attempt == 0:
                time.sleep(min(int(response.headers.get('Retry-After', '2') or 2), 10))
                continue
            break
        if response.status_code in (401, 403):
            raise ProviderError('deSEC rejected the API token (HTTP %s).' % response.status_code)
        if response.status_code not in expect:
            detail = ''
            try:
                body = response.json()
                detail = body.get('detail', '') if isinstance(body, dict) else json.dumps(body)[:200]
            except ValueError:
                pass
            raise ProviderError('deSEC refused the request (HTTP %s)%s' % (
                response.status_code, ': ' + str(detail) if detail else '.'))
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError:
            return None

    def domain(self):
        if self._domain is None:
            found = self._call('GET', '/domains/', params={'owns_qname': self.base}) or []
            if not found:
                raise ProviderError('None of the domains in this deSEC account contains %s. Register it (for '
                                    'example yourname.dedyn.io) or add your zone at deSEC first.' % self.base)
            self._domain = found[0]
        return self._domain

    def subname(self, fqdn):
        zone = self.domain()['name']
        if fqdn == zone or not fqdn.endswith('.' + zone):
            raise ProviderError('%s is not inside the deSEC domain %s.' % (fqdn, zone))
        return fqdn[:-(len(zone) + 1)]

    def test(self):
        zone = self.domain()['name']
        detail = self._call('GET', '/domains/%s/' % zone) or {}
        minimum = detail.get('minimum_ttl')
        return 'The token can manage deSEC domain %s%s.' % (
            zone, ' (minimum TTL %ss)' % minimum if minimum else '')

    def create(self, fqdn, ipv4, ipv6, ttl):
        zone = self.domain()['name']
        sub = self.subname(fqdn)
        detail = self._call('GET', '/domains/%s/' % zone) or {}
        ttl = max(int(ttl), int(detail.get('minimum_ttl') or 0))
        existing = self._call('GET', '/domains/%s/rrsets/' % zone, params={'subname': sub}) or []
        if existing:
            raise ProviderError('%s already has DNS records at deSEC.' % fqdn)
        rrsets = [{'subname': sub, 'type': 'A', 'ttl': ttl, 'records': [ipv4]}]
        if ipv6:
            rrsets.append({'subname': sub, 'type': 'AAAA', 'ttl': ttl, 'records': [ipv6]})
        self._call('POST', '/domains/%s/rrsets/' % zone, expect=(200, 201), data=json.dumps(rrsets))
        return {'domain': zone, 'subname': sub, 'types': [r['type'] for r in rrsets]}

    def delete(self, fqdn, refs):
        refs = refs or {}
        zone = refs.get('domain') or self.domain()['name']
        sub = refs.get('subname') or self.subname(fqdn)
        types = [t for t in refs.get('types', ['A', 'AAAA']) if t in ('A', 'AAAA')]
        # An empty record list deletes the RRset; deleting a missing RRset is not an error.
        self._call('PATCH', '/domains/%s/rrsets/' % zone, expect=(200, 204),
                   data=json.dumps([{'subname': sub, 'type': t, 'records': []} for t in types]))
        return len(types)


PROVIDERS = {cls.key: cls for cls in (LocalPowerDNS, Cloudflare, Desec)}
