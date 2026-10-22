import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons.sslv2 import dnshook, service as ssl, views
from universalAddons.sslv2.service import SSLError

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def make_cert(names, days, issuer_cn='R11', org="Let's Encrypt", self_signed=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                                                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(7).not_valid_before(now - datetime.timedelta(days=30))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


class FakeResolver:
    def __init__(self, records):
        self.records = records

    def query(self, name, rtype):
        return self.records.get((name, rtype), [])


class Certificates(unittest.TestCase):
    def test_parse(self):
        info = ssl.parse_certificate(make_cert(['example.com', '*.example.com'], 60))
        self.assertTrue(info['wildcard'])
        self.assertIn(info['days_left'], (59, 60))
        self.assertIn("Let's Encrypt", info['issuer'])
        self.assertFalse(info['self_signed'])
        self.assertTrue(ssl.parse_certificate(make_cert(['a.com'], 5, self_signed=True))['self_signed'])
        self.assertTrue(ssl.parse_certificate(make_cert(['a.com'], 5, issuer_cn='(STAGING) Fake'))['staging'])

    def test_inventory_states_and_acme_config(self):
        live, home = tempfile.mkdtemp(), tempfile.mkdtemp()
        try:
            for domain, days, kw in (('ok.com', 60, {}), ('soon.com', 5, {}), ('old.com', -3, {}),
                                     ('self.com', 90, {'self_signed': True})):
                os.makedirs(os.path.join(live, domain))
                with open(os.path.join(live, domain, 'fullchain.pem'), 'wb') as handle:
                    handle.write(make_cert([domain], days, **kw))
            os.makedirs(os.path.join(home, 'ok.com_ecc'))
            with open(os.path.join(home, 'ok.com_ecc', 'ok.com.conf'), 'w') as handle:
                handle.write("Le_Webroot='dns_cpuniversal'\nLe_NextRenewTimeStr='2026-12-01T00:00:00Z'\n"
                             "Le_ReloadCmd='__ACME_BASE64__START_x'\n")
            rows = {r['domain']: r for r in ssl.inventory(['ok.com', 'soon.com', 'old.com', 'self.com', 'none.com'],
                                                          live, home)}
            self.assertEqual({d: r['state'] for d, r in rows.items()},
                             {'ok.com': 'ok', 'soon.com': 'expiring', 'old.com': 'expired', 'self.com': 'untrusted',
                              'none.com': 'missing'})
            self.assertEqual(rows['ok.com']['acme']['challenge'], 'dns-01 (dns_cpuniversal)')
            self.assertTrue(rows['ok.com']['acme']['reload'])
            self.assertEqual(sorted(r['domain'] for r in ssl.expiring(list(rows.values()))),
                             ['old.com', 'self.com', 'soon.com'])
            urgent, untrusted = ssl.alert_rows(list(rows.values()))
            self.assertEqual((sorted(r['domain'] for r in urgent), untrusted), (['old.com', 'soon.com'], 1))
            body = ssl.alert_body(urgent, 'host', untrusted)
            self.assertIn('soon.com: expiring', body)
            self.assertIn('1 site(s) also serve a self-signed', body)
            self.assertNotIn('self.com', body)
        finally:
            shutil.rmtree(live)
            shutil.rmtree(home)


class DnsReadiness(unittest.TestCase):
    def test_local_pdns(self):
        resolver = FakeResolver({('example.com', 'NS'): ['ns1.host.net.'], ('ns1.host.net', 'A'): ['203.0.113.5']})
        self.assertTrue(ssl.nameserver_check(resolver, 'example.com', 'pdns', ['203.0.113.5'])['ok'])
        self.assertFalse(ssl.nameserver_check(resolver, 'example.com', 'pdns', ['198.51.100.1'])['ok'])

    def test_subdomain_walks_up_to_zone(self):
        resolver = FakeResolver({('example.com', 'NS'): ['ana.ns.cloudflare.com', 'bob.ns.cloudflare.com']})
        result = ssl.nameserver_check(resolver, 'shop.example.com', 'cloudflare', [])
        self.assertEqual((result['ok'], result['zone']), (True, 'example.com'))


class Requests(unittest.TestCase):
    def test_validation(self):
        r = ssl.validate_request(' Example.COM ', 'pdns', wildcard=True, aliases=['example.net'])
        self.assertEqual(r['names'], ['example.com', '*.example.com', 'example.net', '*.example.net'])
        bad = [dict(domain='exa mple.com', provider='pdns'), dict(domain='a.com', provider='route53'),
               dict(domain='a.com', provider='pdns', ca='evil'), dict(domain='a.com', provider='pdns', key='1024'),
               dict(domain='a.com', provider='pdns', ca='zerossl'),
               dict(domain='a.com', provider='cloudflare', cf_token='x;rm -rf /'),
               dict(domain='a.com', provider='pdns', aliases=['$(id).com'])]
        for kwargs in bad:
            with self.assertRaises(SSLError, msg=kwargs):
                ssl.validate_request(**kwargs)

    def test_commands_pdns_ecc(self):
        cmds = ssl.acme_commands(ssl.validate_request('a.com', 'pdns'), acme='/acme.sh', live_dir='/live')
        issue, env = cmds[0]
        self.assertEqual(env, {})
        self.assertEqual(issue[:3], ['bash', '/acme.sh', '--issue'])
        self.assertIn('dns_cpuniversal', issue)
        self.assertEqual([issue[i + 1] for i, a in enumerate(issue) if a == '-d'], ['a.com', '*.a.com'])
        install = cmds[1][0]
        self.assertIn('--ecc', install)
        self.assertEqual(install[install.index('--reloadcmd') + 1], ssl.RELOAD_COMMAND + ' a.com')
        self.assertEqual(install[install.index('--fullchain-file') + 1], '/live/a.com/fullchain.pem')

    def test_commands_cloudflare_rsa_zerossl(self):
        token = 'A' * 40
        req = ssl.validate_request('a.com', 'cloudflare', wildcard=False, ca='zerossl', key='2048',
                                   email='me@a.com', cf_token=token)
        cmds = ssl.acme_commands(req, acme='/acme.sh')
        self.assertIn('--register-account', cmds[0][0])
        issue, env = cmds[1]
        self.assertIn('dns_cf', issue)
        self.assertEqual(env, {'CF_Token': token})
        self.assertNotIn(token, ' '.join(issue))
        self.assertNotIn('--ecc', cmds[2][0])

    def test_error_hints(self):
        self.assertIn('rate limit', ssl.acme_error('urn:ietf:params:acme:error:rateLimited'))
        self.assertIn('TXT', ssl.acme_error('Incorrect TXT record "x" found'))


class Hook(unittest.TestCase):
    def test_find_zone_prefers_longest(self):
        self.assertEqual(dnshook.find_zone('_acme-challenge.shop.example.com', ['example.com', 'shop.example.com']),
                         'shop.example.com')
        self.assertIsNone(dnshook.find_zone('_acme-challenge.other.org', ['example.com']))

    def test_rejects_unexpected_input_before_touching_django(self):
        for argv in (['h', 'add', 'example.com', 'a' * 43], ['h', 'add', '_acme-challenge.a.com', 'x;id'],
                     ['h', 'drop', '_acme-challenge.a.com', 'a' * 43], ['h']):
            self.assertEqual(dnshook.main(argv), 2, argv)

    def test_shell_hook_quotes_arguments(self):
        with open(os.path.join(REPO, 'universalAddons/sslv2/dns_cpuniversal.sh')) as handle:
            hook = handle.read()
        self.assertIn('dnshook.py add "$1" "$2"', hook)
        self.assertIn('dnshook.py rm "$1" "$2"', hook)
        self.assertNotIn('8081', hook)
        result = subprocess.run(['sh', '-n', os.path.join(REPO, 'universalAddons/sslv2/dns_cpuniversal.sh')])
        self.assertEqual(result.returncode, 0)


class SslViews(SimpleTestCase):
    def post(self, view, body, is_admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': is_admin}):
            response = view(request)
        return response.status_code, json.loads(response.content)

    def test_admin_only(self):
        for name in ('inventory', 'check', 'issue', 'job', 'monitor'):
            with mock.patch('universalAddons.privileged.call') as call:
                self.assertEqual(self.post(getattr(views, name), {}, is_admin=0)[0], 403)
            call.assert_not_called()

    def test_issue_validates_before_runner(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'j'}) as call:
            self.assertEqual(self.post(views.issue, {'domain': 'a.com', 'provider': 'pdns', 'key': '512'})[0], 400)
            call.assert_not_called()
            self.post(views.issue, {'domain': 'A.com', 'provider': 'pdns', 'wildcard': True})
        args = call.call_args[1]
        self.assertEqual((args['domain'], args['wildcard'], args['key']), ('a.com', True, 'ec-256'))

    def test_monitor_toggle(self):
        with mock.patch('universalAddons.privileged.call', return_value={'enabled': True}) as call:
            self.post(views.monitor, {})
            self.post(views.monitor, {'enable': True})
            self.assertEqual(self.post(views.monitor, {'enable': 'on'})[0], 400)
        self.assertEqual([c[0][1] for c in call.call_args_list], ['monitor_status', 'monitor_cron'])


if __name__ == '__main__':
    unittest.main()
