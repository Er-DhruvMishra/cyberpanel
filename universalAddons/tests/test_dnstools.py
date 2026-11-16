import json
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from universalAddons.dnstools import actions, service as sv, views
from universalAddons.tests.helpers import post

POLICY_ON = {'dnstools_for_users': True}

SHOW_SECURED = """This is a Native zone
Metadata items:
\tSOA-EDIT-API\tDEFAULT
Zone has NSEC semantics
keys:
ID = 1 (CSK), flags = 257, tag = 31337, algo = 13, bits = 256\t  Active\t Published  ( ECDSAP256SHA256 )
CSK DNSKEY = example.com. IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ== ; ( ECDSAP256SHA256 )
DS = example.com. IN DS 31337 13 1 a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 ; ( SHA1 digest )
DS = example.com. IN DS 31337 13 2 3a4b5c6d7e8f901234567890abcdef1234567890abcdef1234567890abcdef12 ; ( SHA256 digest )
DS = example.com. IN DS 31337 13 4 aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44 ; ( SHA-384 digest )
"""
SHOW_UNSIGNED = """This is a Native zone
Metadata items: None
Zone is not actively secured
No keys for zone 'example.com'.
"""


class ShowZone(SimpleTestCase):
    def test_ds_records_are_parsed(self):
        zone = sv.parse_show_zone(SHOW_SECURED)
        self.assertTrue(zone['secured'])
        self.assertEqual(zone['nsec'], 'NSEC')
        self.assertEqual(zone['keys'][0]['tag'], 31337)
        self.assertEqual(len(zone['ds']), 3)
        self.assertEqual(zone['ds'][0]['digest_type'], 2)          # SHA-256 first
        self.assertEqual(len(zone['recommended_ds']), 1)
        self.assertEqual(zone['recommended_ds'][0]['record'],
                         'example.com. IN DS 31337 13 2 3A4B5C6D7E8F901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12')
        self.assertEqual(zone['dnskey'][0]['flags'], 257)

    def test_unsigned(self):
        zone = sv.parse_show_zone(SHOW_UNSIGNED)
        self.assertFalse(zone['secured'])
        self.assertEqual(zone['ds'], [])

    def test_argv_and_zone_validation(self):
        self.assertEqual(sv.pdnsutil_argv('secure', 'Example.COM.'), ['/usr/bin/pdnsutil', 'secure-zone', 'example.com'])
        for bad in ('example.com; rm -rf /', '-example.com', '--help', 'a..b', 'x', 'exa mple.com', '$(id).com'):
            with self.assertRaises(sv.DNSToolsError, msg=bad):
                sv.pdnsutil_argv('show', bad)
        with self.assertRaises(sv.DNSToolsError):
            sv.pdnsutil_argv('delete-zone', 'example.com')

    def test_enable_with_mocked_pdnsutil(self):
        calls = []
        outputs = iter([SHOW_UNSIGNED, 'Securing zone with default key size\nZone example.com secured', '', SHOW_SECURED])

        def runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout=next(outputs))
        with mock.patch.object(actions, '_zone', side_effect=lambda z: sv.check_zone(z)), \
                mock.patch.object(actions, 'support', return_value={'ok': True, 'problems': [], 'facts': {}}):
            result = actions.enable('example.com', runner=runner)
        self.assertEqual([c[1] for c in calls], ['show-zone', 'secure-zone', 'rectify-zone', 'show-zone'])
        self.assertEqual(result['zone']['recommended_ds'][0]['tag'], 31337)

    def test_disable_requires_the_ds_confirmation(self):
        with self.assertRaisesRegex(sv.DNSToolsError, 'DS record'):
            actions.disable('example.com')


class PdnsConf(SimpleTestCase):
    def test_gmysql_without_dnssec_is_reported(self):
        conf = sv.parse_pdns_conf('launch=gmysql\ngmysql-host=localhost\napi=yes\napi-key=secret\n'
                                  'webserver=yes\nwebserver-allow-from=0.0.0.0/0\n')
        ok, problems, facts = sv.dnssec_support(conf)
        self.assertFalse(ok)
        self.assertIn('gmysql-dnssec=yes', problems[0])
        self.assertTrue(facts['api'])
        self.assertTrue(facts['webserver_open'])
        self.assertNotIn('secret', json.dumps(facts))
        ok, problems, _ = sv.dnssec_support(sv.parse_pdns_conf('launch=gmysql\ngmysql-dnssec=yes\n'))
        self.assertTrue(ok)


TEMPLATE = {'records': [
    {'name': '@', 'type': 'A', 'content': '{ip}', 'ttl': 3600},
    {'name': '@', 'type': 'AAAA', 'content': '{ipv6}', 'ttl': 3600},
    {'name': 'www', 'type': 'CNAME', 'content': '{domain}', 'ttl': 3600},
    {'name': '@', 'type': 'MX', 'content': 'mail.{domain}', 'ttl': 3600, 'prio': 10},
    {'name': 'mail.{domain}', 'type': 'A', 'content': '{ip}', 'ttl': 3600},
    {'name': '@', 'type': 'TXT', 'content': 'v=spf1 a mx ip4:{ip} ~all', 'ttl': 3600},
    {'name': '_sip._tcp', 'type': 'SRV', 'content': '5 5060 sip.{domain}', 'ttl': 3600, 'prio': 10},
    {'name': '@', 'type': 'CAA', 'content': '0 issue "letsencrypt.org"', 'ttl': 3600},
    {'name': 'host', 'type': 'CNAME', 'content': '{hostname}', 'ttl': 3600},
    {'name': '@', 'type': 'TXT', 'content': 'ns {ns1} {ns2}', 'ttl': 3600},
]}


class Templates(SimpleTestCase):
    def values(self, ipv6=''):
        return {'domain': 'shop.in', 'ip': '203.0.113.5', 'ipv6': ipv6, 'hostname': 'srv.host.net',
                'ns1': 'ns1.host.net', 'ns2': 'ns2.host.net'}

    def test_rendering_with_every_placeholder(self):
        records = sv.render_template(sv.validate_template(TEMPLATE), self.values('2001:db8::5'))
        by = {(r['name'], r['type'], r['content']) for r in records}
        self.assertIn(('shop.in', 'A', '203.0.113.5'), by)
        self.assertIn(('shop.in', 'AAAA', '2001:db8::5'), by)
        self.assertIn(('www.shop.in', 'CNAME', 'shop.in'), by)
        self.assertIn(('shop.in', 'MX', 'mail.shop.in'), by)
        self.assertIn(('mail.shop.in', 'A', '203.0.113.5'), by)
        self.assertIn(('_sip._tcp.shop.in', 'SRV', '5 5060 sip.shop.in'), by)
        self.assertIn(('host.shop.in', 'CNAME', 'srv.host.net'), by)
        self.assertIn(('shop.in', 'TXT', 'ns ns1.host.net ns2.host.net'), by)
        mx = [r for r in records if r['type'] == 'MX'][0]
        self.assertEqual(mx['prio'], 10)

    def test_ipv6_records_are_skipped_without_an_address(self):
        records = sv.render_template(sv.validate_template(TEMPLATE), self.values(''))
        self.assertFalse([r for r in records if r['type'] == 'AAAA'])

    def test_validation(self):
        bad = [
            {'records': [{'name': '@', 'type': 'NS', 'content': 'x.com'}]},                  # NS stays the panel's
            {'records': [{'name': '@', 'type': 'A', 'content': '{nope}'}]},                  # unknown placeholder
            {'records': [{'name': '@', 'type': 'A', 'content': '1.2.3.4\nevil'}]},
            {'records': [{'name': '@', 'type': 'A', 'content': 'not-an-ip'}]},
            {'records': [{'name': '@', 'type': 'CAA', 'content': 'issue letsencrypt'}]},
            {'records': [{'name': 'x', 'type': 'SRV', 'content': '5 5060 sip.x.com'}]},     # SRV name form
            {'records': [{'name': '@', 'type': 'CNAME', 'content': 'x.com'}]},              # apex CNAME
            {'records': [{'name': 'a', 'type': 'CNAME', 'content': 'x.com'}, {'name': 'a', 'type': 'A', 'content': '{ip}'}]},
            {'records': [{'name': 'evil.com.{ip}', 'type': 'A', 'content': '{ip}'}]},
            {'records': [{'name': 'other.org{domain}', 'type': 'A', 'content': '{ip}'}]},  # outside the zone
            {'records': [{'name': '@', 'type': 'A', 'content': '{ip}', 'ttl': 5}]},
            {'records': []},
        ]
        for template in bad:
            with self.assertRaises(sv.DNSToolsError, msg=template):
                sv.validate_template(template)

    def test_fixed_records_are_a_valid_template(self):
        records = sv.render_template(sv.validate_template({'records': sv.DEFAULT_RECORDS}), self.values())
        self.assertEqual(len(records), len(sv.DEFAULT_RECORDS))

    def test_reseller_template_wins_for_its_users(self):
        data = {'default': {'records': [1]}, 'resellers': {'5': {'records': [2]}}, 'ipv6': ''}
        self.assertEqual(sv.template_for(data, 9, owner_id=5), ({'records': [2]}, 'reseller:5'))
        self.assertEqual(sv.template_for(data, 5, owner_id=1), ({'records': [2]}, 'reseller:5'))
        self.assertEqual(sv.template_for(data, 9, owner_id=1), ({'records': [1]}, 'default'))
        self.assertEqual(sv.template_for(dict(data, default=None), 9, 1), (None, 'fixed'))

    def test_save_and_load(self):
        path = os.path.join(tempfile.mkdtemp(), 't.json')
        saved = actions.save_template('default', TEMPLATE, ipv6='2001:db8::1', path=path)
        self.assertEqual(saved['ipv6'], '2001:db8::1')
        actions.save_template('reseller:5', {'records': sv.DEFAULT_RECORDS}, path=path)
        self.assertIn('5', sv.load_templates(path)['resellers'])
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o644')
        actions.save_template('reseller:5', None, path=path)
        self.assertEqual(sv.load_templates(path)['resellers'], {})
        with self.assertRaises(sv.DNSToolsError):
            actions.save_template('reseller:x', TEMPLATE, path=path)
        with self.assertRaises(sv.DNSToolsError):
            actions.save_template('default', TEMPLATE, ipv6='::1', path=path)


class DnsTemplateHook(SimpleTestCase):
    def test_no_template_means_fixed_records(self):
        path = os.path.join(tempfile.mkdtemp(), 'missing.json')
        self.assertIsNone(sv.records_for_new_zone('shop.in', 3, 1, '203.0.113.5', path=path))

    def test_saved_template_renders_for_new_zones(self):
        path = os.path.join(tempfile.mkdtemp(), 't.json')
        actions.save_template('default', TEMPLATE, path=path)
        with mock.patch.object(sv, 'NAMESERVERS_FILE', os.path.join(os.path.dirname(path), 'none')):
            records = sv.records_for_new_zone('shop.in', 3, 1, '203.0.113.5', path=path)
        self.assertIn({'name': 'shop.in', 'type': 'A', 'content': '203.0.113.5', 'ttl': 3600, 'prio': 0}, records)
        self.assertIn('ns ns1.shop.in ns2.shop.in', [r['content'] for r in records])

    def test_dns_template_falls_back_to_the_fixed_records(self):
        """plogical.dnsUtilities.DNS.applySavedTemplate: False (fixed records) without a template or on error."""
        from plogical.dnsUtilities import DNS
        zone = SimpleNamespace(id=1)
        admin = SimpleNamespace(pk=3, owner=1)
        with mock.patch('universalAddons.dnstools.service.records_for_new_zone', return_value=None):
            self.assertFalse(DNS.applySavedTemplate(zone, 'shop.in', admin, '203.0.113.5'))
        with mock.patch('universalAddons.dnstools.service.records_for_new_zone', side_effect=sv.DNSToolsError('bad')):
            self.assertFalse(DNS.applySavedTemplate(zone, 'shop.in', admin, '203.0.113.5'))
        saved = []
        records = [{'name': 'shop.in', 'type': 'A', 'content': '203.0.113.5', 'ttl': 3600, 'prio': 0}]
        fake_records = mock.MagicMock()
        fake_records.objects.filter.return_value.exists.return_value = False
        fake_records.side_effect = lambda **kw: SimpleNamespace(save=lambda: saved.append(kw))
        with mock.patch('universalAddons.dnstools.service.records_for_new_zone', return_value=records), \
                mock.patch('plogical.dnsUtilities.Records', fake_records, create=True), \
                mock.patch.object(DNS, 'incrementSOASerial') as serial:
            self.assertTrue(DNS.applySavedTemplate(zone, 'shop.in', admin, '203.0.113.5'))
        self.assertEqual(saved[0]['content'], '203.0.113.5')
        serial.assert_called_once()

    def test_dns_template_calls_the_hook_before_the_fixed_records(self):
        import inspect
        from plogical.dnsUtilities import DNS
        source = inspect.getsource(DNS.dnsTemplate)
        self.assertEqual(source.count('if not DNS.applySavedTemplate(zone, topLevelDomain, admin, ipAddress):'), 2)


class ApplyPlan(SimpleTestCase):
    existing = [
        {'id': 1, 'name': 'shop.in', 'type': 'SOA', 'content': 'ns1 hostmaster 1', 'prio': 0},
        {'id': 2, 'name': 'shop.in', 'type': 'NS', 'content': 'ns1.host.net', 'prio': 0},
        {'id': 3, 'name': 'shop.in', 'type': 'A', 'content': '198.51.100.1', 'prio': 0},
        {'id': 4, 'name': 'www.shop.in', 'type': 'A', 'content': '198.51.100.1', 'prio': 0},
        {'id': 5, 'name': 'shop.in', 'type': 'TXT', 'content': 'keep me', 'prio': 0},
    ]
    rendered = [
        {'name': 'shop.in', 'type': 'A', 'content': '203.0.113.5', 'ttl': 3600, 'prio': 0},
        {'name': 'www.shop.in', 'type': 'CNAME', 'content': 'shop.in', 'ttl': 3600, 'prio': 0},
        {'name': 'shop.in', 'type': 'MX', 'content': 'shop.in', 'ttl': 3600, 'prio': 10},
    ]

    def test_add_only_never_removes(self):
        plan = sv.plan_apply(self.existing, self.rendered, 'add')
        self.assertEqual(plan['remove'], [])
        self.assertEqual([r['type'] for r in plan['add']], ['MX'])
        self.assertEqual(len(plan['skipped']), 2)                    # A exists; CNAME would clash with the A

    def test_replace_removes_clashes_but_never_soa_or_ns(self):
        plan = sv.plan_apply(self.existing, self.rendered, 'replace')
        self.assertEqual(sorted(r['id'] for r in plan['remove']), [3, 4])
        self.assertEqual(len(plan['add']), 3)
        with self.assertRaises(sv.DNSToolsError):
            sv.plan_apply(self.existing, self.rendered, 'wipe')


class Views(SimpleTestCase):
    def test_zone_ownership_uses_the_panel_dns_rule(self):
        with mock.patch('universalAddons.dnstools.views.ACLManager.checkOwnershipZone', return_value=0) as check, \
                mock.patch('universalAddons.dnstools.views.privileged.call') as call:
            status, body, _ = post(views.dnssec_enable, {'zone': 'other.net'}, policy=POLICY_ON)
        self.assertEqual(status, 403)
        call.assert_not_called()
        self.assertEqual(check.call_args[0][0], 'other.net')
        with mock.patch('universalAddons.dnstools.views.ACLManager.checkOwnershipZone', return_value=1), \
                mock.patch('universalAddons.dnstools.views.privileged.call', return_value={}) as call:
            status, body, _ = post(views.dnssec_enable, {'zone': 'mine.example.com'}, policy=POLICY_ON)
        self.assertEqual(status, 200)
        call.assert_called_once_with('dnstools', 'enable', zone='mine.example.com')

    def test_disable_needs_confirmation(self):
        with mock.patch('universalAddons.dnstools.views.ACLManager.checkOwnershipZone', return_value=1), \
                mock.patch('universalAddons.dnstools.views.privileged.call') as call:
            status, body, _ = post(views.dnssec_disable, {'zone': 'mine.example.com'}, policy=POLICY_ON)
        self.assertEqual(status, 400)
        call.assert_not_called()

    def test_plain_users_have_no_template_and_resellers_only_their_own(self):
        status, _, _ = post(views.template_save, {'template': TEMPLATE}, policy=POLICY_ON)
        self.assertEqual(status, 403)
        context = SimpleNamespace(is_admin=False, acl={'resellerCenter': 1}, user_id=7)
        self.assertEqual(views._scope_for(context, {'scope': 'default'}), 'reseller:7')
        with self.assertRaises(PermissionError):
            views._scope_for(SimpleNamespace(is_admin=False, acl={}, user_id=7), {})

    def test_admin_saves_the_default(self):
        with mock.patch('universalAddons.dnstools.views.privileged.call', return_value={}) as call:
            status, body, _ = post(views.template_save, {'template': TEMPLATE, 'ipv6': '2001:db8::1'}, admin=True)
        self.assertEqual(status, 200)
        self.assertEqual(call.call_args[1]['scope'], 'default')
        self.assertEqual(call.call_args[1]['ipv6'], '2001:db8::1')
