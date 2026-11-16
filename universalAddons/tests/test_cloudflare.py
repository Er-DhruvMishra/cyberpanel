"""Cloudflare add-on: tokens, access, validation, request building and GraphQL, against a mocked API."""
import datetime
import json
import os
import shutil
import stat
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons.cloudflare import client as cf
from universalAddons.cloudflare import service, views
from universalAddons.cloudflare.client import CloudflareError
from universalAddons.tests.helpers import page, post

TOKEN = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-xy'
ZONE = 'a' * 32
RECORD = 'b' * 32
ZONE_OBJ = {'id': ZONE, 'name': 'example.com', 'status': 'active', 'plan': {'name': 'Free Website'},
            'name_servers': ['ana.ns.cloudflare.com', 'bob.ns.cloudflare.com'], 'original_name_servers': ['ns1.host.com']}
USER = {'policy': {'cloudflare_for_users': True}, 'owned': ('mine.example.com',)}


class Response:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        if self._body is None:
            raise ValueError('no json')
        return self._body


class FakeHttp:
    """Records every request; answers from `routes` {(METHOD, path): body or Response}."""

    def __init__(self, routes=None):
        self.calls, self.routes = [], dict(routes or {})

    def request(self, method, url, **kwargs):
        self.calls.append(SimpleNamespace(method=method, url=url, **kwargs))
        path = url.replace(cf.API, '')
        answer = self.routes.get((method, path))
        if answer is None:
            answer = {'success': True, 'result': {'id': RECORD}}
        if isinstance(answer, Response):
            return answer
        return Response(200, answer)

    def body(self, index=-1):
        data = self.calls[index].data
        return json.loads(data) if data else None


def ok_result(result, info=None):
    body = {'success': True, 'errors': [], 'result': result}
    if info:
        body['result_info'] = info
    return body


DEFAULT_ROUTES = {
    ('GET', '/user/tokens/verify'): ok_result({'id': 'x', 'status': 'active', 'expires_on': None}),
    ('GET', '/zones'): ok_result([ZONE_OBJ], {'total_pages': 1}),
    ('GET', '/zones/%s' % ZONE): ok_result(ZONE_OBJ),
    ('GET', '/zones/%s/dns_records' % ZONE): ok_result([
        {'id': RECORD, 'type': 'A', 'name': 'example.com', 'content': '192.0.2.1', 'ttl': 1, 'proxied': True,
         'proxiable': True}], {'total_pages': 1}),
}


class Base(SimpleTestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.http = FakeHttp(DEFAULT_ROUTES)
        patches = [mock.patch.object(service, 'STATE_DIR', self.state),
                   mock.patch.object(cf, '_requests', return_value=self.http),
                   mock.patch.object(service, 'ns_check', return_value={'checked': False}),
                   mock.patch.object(service, 'server_ip', return_value='203.0.113.5')]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(shutil.rmtree, self.state, True)
        service._cache.clear()

    def save_token(self, **who):
        status, body, _ = post(views.token_save, {'input': {'token': TOKEN}}, **who)
        self.assertEqual(status, 200, body)
        return body


# ------------------------------------------------------------------------------------------ tokens

class Tokens(Base):
    def test_token_is_saved_private_and_never_returned(self):
        body = self.save_token(admin=True)
        self.assertNotIn(TOKEN, json.dumps(body))
        self.assertTrue(body['result']['token']['saved'])
        self.assertEqual(body['result']['token']['verify']['status'], 'active')
        path = os.path.join(self.state, 'tokens', 'user-7.token')
        self.assertEqual(open(path).read().strip(), TOKEN)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.state, 'tokens')).st_mode), 0o700)
        for view, data in ((views.state, {}), (views.zones, {}), (views.overview, {'zone': ZONE}),
                           (views.token_verify, {}), (views.audit_log, {})):
            _, out, _ = post(view, data, admin=True)
            self.assertEqual(out['status'], 1, out)
            self.assertNotIn(TOKEN, json.dumps(out), view.__name__)
        # verify used the Bearer token, and only server side
        verify = self.http.calls[0]
        self.assertEqual(verify.url, cf.API + '/user/tokens/verify')
        self.assertEqual(verify.headers['Authorization'], 'Bearer ' + TOKEN)

    def test_inactive_token_is_not_saved(self):
        self.http.routes[('GET', '/user/tokens/verify')] = ok_result({'status': 'disabled'})
        status, body, _ = post(views.token_save, {'input': {'token': TOKEN}}, admin=True)
        self.assertEqual(status, 400)
        self.assertFalse(os.path.exists(os.path.join(self.state, 'tokens', 'user-7.token')))

    def test_rejected_token_reports_invalid(self):
        self.http.routes[('GET', '/user/tokens/verify')] = Response(401, {'success': False, 'errors': [
            {'message': 'Invalid API Token'}]})
        status, body, _ = post(views.token_save, {'input': {'token': TOKEN}}, admin=True)
        self.assertEqual(status, 400)
        self.assertIn('invalid', body['error_message'])

    def test_malformed_token_rejected_before_any_call(self):
        status, body, _ = post(views.token_save, {'input': {'token': 'abc def'}}, admin=True)
        self.assertEqual(status, 400)
        self.assertEqual(self.http.calls, [])

    def test_each_account_has_its_own_token(self):
        self.save_token(**USER)
        self.assertTrue(service.token_state('user-7')['saved'])
        self.assertFalse(service.token_state('user-8')['saved'])
        self.assertFalse(service.token_state(service.SERVER_KEY)['saved'])

    def test_server_token_is_admin_only(self):
        status, body, _ = post(views.token_save, {'source': 'server', 'input': {'token': TOKEN}}, **USER)
        self.assertEqual(status, 403)
        status, body, _ = post(views.zones, {'source': 'server'}, **USER)
        self.assertEqual(status, 403)
        status, body, _ = post(views.token_save, {'source': 'server', 'input': {'token': TOKEN}}, admin=True)
        self.assertEqual(status, 200)
        self.assertTrue(os.path.exists(os.path.join(self.state, 'tokens', 'server.token')))
        _, state, _ = post(views.state, {}, admin=True)
        self.assertTrue(state['result']['server_token']['saved'])
        _, state, _ = post(views.state, {}, **USER)
        self.assertNotIn('server_token', state['result'])

    def test_forget(self):
        self.save_token(admin=True)
        post(views.token_forget, {}, admin=True)
        self.assertFalse(service.token_state('user-7')['saved'])

    def test_users_need_the_switch(self):
        status, body, _ = post(views.state, {}, owned=('mine.example.com',))
        self.assertEqual(status, 403)


# ------------------------------------------------------------------------------------------- links

class Links(Base):
    def setUp(self):
        super().setUp()
        self.save_token(**USER)

    def test_user_links_own_site(self):
        status, body, _ = post(views.link, {'zone': ZONE, 'input': {'site': 'mine.example.com'}}, **USER)
        self.assertEqual(status, 200, body)
        self.assertEqual(service.links(7), {ZONE: 'mine.example.com'})

    def test_user_cannot_link_someone_elses_site(self):
        status, body, _ = post(views.link, {'zone': ZONE, 'input': {'site': 'shop.example.com'}}, **USER)
        self.assertEqual(status, 403)
        self.assertEqual(service.links(7), {})

    def test_site_must_be_inside_the_zone(self):
        who = dict(USER, owned=('mine.example.com', 'other.example.net'))
        status, body, _ = post(views.link, {'zone': ZONE, 'input': {'site': 'other.example.net'}}, **who)
        self.assertEqual(status, 400)

    def test_import_and_origin_need_a_link_still_owned(self):
        service.set_link(7, ZONE, 'shop.example.com')   # linked once, no longer owned
        status, body, _ = post(views.dns_import_preview, {'zone': ZONE}, **USER)
        self.assertEqual(status, 403)
        status, body, _ = post(views.origin_cert, {'zone': ZONE}, **USER)
        self.assertEqual(status, 403)

    def test_user_point_here_only_below_linked_site(self):
        service.set_link(7, ZONE, 'mine.example.com')
        status, body, _ = post(views.point_here, {'zone': ZONE, 'input': {'name': '@'}}, **USER)
        self.assertEqual(status, 403)
        status, body, _ = post(views.point_here, {'zone': ZONE, 'input': {'name': 'mine'}, 'proxied': True}, **USER)
        self.assertEqual(status, 200, body)
        self.assertEqual(self.http.calls[-1].method, 'POST')
        self.assertEqual(self.http.body(), {'type': 'A', 'name': 'mine.example.com', 'content': '203.0.113.5',
                                            'ttl': 1, 'proxied': True})


# -------------------------------------------------------------------------------------- validation

class Validation(SimpleTestCase):
    def test_ids(self):
        self.assertEqual(cf.zone_id(ZONE.upper()), ZONE)
        for bad in ('', 'a' * 31, 'g' * 32, '../' + 'a' * 29, None):
            with self.assertRaises(CloudflareError):
                cf.zone_id(bad)
        with self.assertRaises(CloudflareError):
            cf.record_id('x/../y')

    def test_record_types_whitelisted(self):
        for bad in ('NS', 'SOA', 'PTR', 'a;b', ''):
            with self.assertRaises(CloudflareError):
                cf.validate_record({'type': bad, 'name': '@', 'content': 'x'}, 'example.com')

    def test_names(self):
        self.assertEqual(cf.record_name('@', 'example.com'), 'example.com')
        self.assertEqual(cf.record_name('www', 'example.com'), 'www.example.com')
        self.assertEqual(cf.record_name('WWW.Example.com.', 'example.com'), 'www.example.com')
        self.assertEqual(cf.record_name('*.dev', 'example.com'), '*.dev.example.com')
        self.assertEqual(cf.record_name('_dmarc', 'example.com'), '_dmarc.example.com')
        for bad in ('a b', 'x..y', '-a', 'a.*', 'a/b', 'a' * 70):
            with self.assertRaises(CloudflareError, msg=bad):
                cf.record_name(bad, 'example.com')
        # a name of another zone becomes a name inside this one, never another zone
        self.assertEqual(cf.record_name('evil.net', 'example.com'), 'evil.net.example.com')

    def test_contents(self):
        cases = [({'type': 'A', 'content': '1.2.3'}, 'IPv4'), ({'type': 'AAAA', 'content': '1.2.3.4'}, 'IPv6'),
                 ({'type': 'CNAME', 'content': 'bad host'}, 'CNAME'), ({'type': 'TXT', 'content': 'a\nb'}, 'TXT'),
                 ({'type': 'MX', 'content': 'mail.example.com', 'priority': 70000}, 'Priority'),
                 ({'type': 'SRV', 'name': 'sip', 'port': 5060, 'target': 'x.example.com'}, 'SRV'),
                 ({'type': 'CAA', 'tag': 'bogus', 'value': 'x'}, 'CAA'), ({'type': 'A', 'content': '1.2.3.4', 'ttl': 5}, 'TTL')]
        for raw, message in cases:
            raw.setdefault('name', '@')
            with self.assertRaisesRegex(CloudflareError, message):
                cf.validate_record(raw, 'example.com')

    def test_valid_records(self):
        self.assertEqual(cf.validate_record({'type': 'MX', 'name': '@', 'content': 'mail.example.com.', 'priority': '10'},
                                            'example.com'),
                         {'type': 'MX', 'name': 'example.com', 'ttl': 1, 'content': 'mail.example.com', 'priority': 10})
        srv = cf.validate_record({'type': 'SRV', 'name': '_sip._tcp', 'priority': 1, 'weight': 2, 'port': 5060,
                                  'target': 'sip.example.com'}, 'example.com')
        self.assertEqual(srv['data'], {'priority': 1, 'weight': 2, 'port': 5060, 'target': 'sip.example.com'})
        caa = cf.validate_record({'type': 'CAA', 'name': '@', 'tag': 'issue', 'value': 'letsencrypt.org'}, 'example.com')
        self.assertEqual(caa['data'], {'flags': 0, 'tag': 'issue', 'value': 'letsencrypt.org'})
        txt = cf.validate_record({'type': 'TXT', 'name': '@', 'content': 'v=spf1 a mx ~all', 'proxied': True}, 'example.com')
        self.assertNotIn('proxied', txt)
        aaaa = cf.validate_record({'type': 'AAAA', 'name': 'v6', 'content': '2001:DB8::1', 'proxied': True, 'ttl': 300},
                                  'example.com')
        self.assertEqual((aaaa['content'], aaaa['proxied'], aaaa['ttl']), ('2001:db8::1', True, 1))

    def test_settings(self):
        self.assertEqual(cf.validate_setting('ssl', 'strict'), 'strict')
        self.assertEqual(cf.validate_setting('browser_cache_ttl', '3600'), 3600)
        for key, value in (('ssl', 'loose'), ('browser_cache_ttl', 7), ('min_tls_version', '0.9'), ('waf', 'on'),
                           ('../zones', 'on')):
            with self.assertRaises(CloudflareError):
                cf.validate_setting(key, value)

    def test_purge_urls(self):
        self.assertEqual(cf.validate_purge_urls(['https://www.example.com/a.css'], 'example.com'),
                         ['https://www.example.com/a.css'])
        for bad in (['https://evil.com/x'], ['ftp://example.com/x'], ['https://example.com.evil.com/'],
                    ['https://u:p@example.com/'], [], 'https://example.com/', ['https://example.com/%d' % i for i in range(31)]):
            with self.assertRaises(CloudflareError):
                cf.validate_purge_urls(bad, 'example.com')

    def test_access_rules(self):
        self.assertEqual(cf.validate_access_rule({'mode': 'block', 'value': '198.51.100.7'})['configuration'],
                         {'target': 'ip', 'value': '198.51.100.7'})
        self.assertEqual(cf.validate_access_rule({'mode': 'allow', 'value': 'in'}),
                         {'mode': 'whitelist', 'configuration': {'target': 'country', 'value': 'IN'},
                          'notes': 'Added from IndiansCloud'})
        self.assertEqual(cf.validate_access_rule({'mode': 'challenge', 'value': '10.1.2.0/24'})['configuration'],
                         {'target': 'ip_range', 'value': '10.1.2.0/24'})
        self.assertEqual(cf.validate_access_rule({'mode': 'block', 'value': 'de'})['configuration']['target'], 'country')
        for bad in ({'mode': 'nuke', 'value': '1.2.3.4'}, {'mode': 'block', 'value': 'IND'},
                    {'mode': 'block', 'value': '10.0.0.0/8'}, {'mode': 'block', 'value': '1.2.3.4', 'notes': 'a\nb'}):
            with self.assertRaises(CloudflareError):
                cf.validate_access_rule(bad)

    def test_views_reject_bad_input_before_calling_cloudflare(self):
        http = FakeHttp(DEFAULT_ROUTES)
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, True)
        with mock.patch.object(service, 'STATE_DIR', state), mock.patch.object(cf, '_requests', return_value=http):
            service._write_private(os.path.join(state, 'tokens', 'user-7.token'), TOKEN)
            for view, data in ((views.overview, {'zone': 'nothex'}),
                               (views.dns_delete, {'zone': 'zz', 'record_id': RECORD}),
                               (views.setting_set, {'zone': 'x', 'setting': 'ssl', 'value': 'off'}),
                               (views.analytics, {'zone': ZONE, 'range': '1y'}),
                               (views.link, {'zone': ZONE, 'input': 'x'})):
                status, body, _ = post(view, data, admin=True)
                self.assertEqual(status, 400, (view.__name__, body))
            self.assertTrue(all(c.method == 'GET' for c in http.calls))


# -------------------------------------------------------------------------------- request building

class Requests(Base):
    def setUp(self):
        super().setUp()
        self.save_token(admin=True)
        self.http.calls.clear()

    def test_dns_create(self):
        status, body, _ = post(views.dns_save, {'zone': ZONE, 'input': {'record': {
            'type': 'CNAME', 'name': 'www', 'content': 'example.com', 'proxied': True}}}, admin=True)
        self.assertEqual(status, 200, body)
        call = self.http.calls[-1]
        self.assertEqual((call.method, call.url), ('POST', cf.API + '/zones/%s/dns_records' % ZONE))
        self.assertEqual(self.http.body(), {'type': 'CNAME', 'name': 'www.example.com', 'content': 'example.com',
                                            'ttl': 1, 'proxied': True})
        self.assertIs(call.allow_redirects, False)
        self.assertEqual(call.timeout, cf.API_TIMEOUT)
        self.assertEqual(call.headers['Authorization'], 'Bearer ' + TOKEN)

    def test_dns_update_delete_and_proxy(self):
        post(views.dns_save, {'zone': ZONE, 'record_id': RECORD, 'input': {'record': {
            'type': 'A', 'name': '@', 'content': '192.0.2.9'}}}, admin=True)
        self.assertEqual((self.http.calls[-1].method, self.http.calls[-1].url),
                         ('PUT', cf.API + '/zones/%s/dns_records/%s' % (ZONE, RECORD)))
        post(views.dns_proxied, {'zone': ZONE, 'record_id': RECORD, 'proxied': False}, admin=True)
        self.assertEqual(self.http.calls[-1].method, 'PATCH')
        self.assertEqual(self.http.body(), {'proxied': False})
        post(views.dns_delete, {'zone': ZONE, 'record_id': RECORD}, admin=True)
        self.assertEqual(self.http.calls[-1].method, 'DELETE')

    def test_purge(self):
        post(views.purge, {'zone': ZONE, 'everything': True}, admin=True)
        self.assertEqual(self.http.calls[-1].url, cf.API + '/zones/%s/purge_cache' % ZONE)
        self.assertEqual(self.http.body(), {'purge_everything': True})
        urls = ['https://example.com/a.css', 'https://www.example.com/b.js']
        post(views.purge, {'zone': ZONE, 'input': {'urls': urls}}, admin=True)
        self.assertEqual(self.http.body(), {'files': urls})

    def test_settings(self):
        status, body, _ = post(views.setting_set, {'zone': ZONE, 'setting': 'min_tls_version', 'value': '1.2'}, admin=True)
        self.assertEqual(status, 200, body)
        call = self.http.calls[-1]
        self.assertEqual((call.method, call.url), ('PATCH', cf.API + '/zones/%s/settings/min_tls_version' % ZONE))
        self.assertEqual(self.http.body(), {'value': '1.2'})
        post(views.setting_set, {'zone': ZONE, 'setting': 'browser_cache_ttl', 'value': 14400}, admin=True)
        self.assertEqual(self.http.body(), {'value': 14400})
        post(views.under_attack, {'zone': ZONE, 'enable': True}, admin=True)
        self.assertEqual(self.http.body(), {'value': 'under_attack'})
        post(views.under_attack, {'zone': ZONE, 'enable': False, 'restore': 'high'}, admin=True)
        self.assertEqual(self.http.body(), {'value': 'high'})

    def test_settings_read_filters_to_known_keys(self):
        self.http.routes[('GET', '/zones/%s/settings' % ZONE)] = ok_result([
            {'id': 'ssl', 'value': 'full', 'editable': True}, {'id': 'secret_thing', 'value': 'x'}])
        _, body, _ = post(views.settings, {'zone': ZONE}, admin=True)
        self.assertEqual(body['result']['values'], {'ssl': {'value': 'full', 'editable': True}})

    def test_access_rule_add(self):
        post(views.rule_add, {'zone': ZONE, 'input': {'rule': {'mode': 'block', 'value': '2001:db8::7'}}}, admin=True)
        self.assertEqual(self.http.calls[-1].url, cf.API + '/zones/%s/firewall/access_rules/rules' % ZONE)
        self.assertEqual(self.http.body()['configuration'], {'target': 'ip6', 'value': '2001:db8::7'})

    def test_point_here_updates_existing_a_record(self):
        status, body, _ = post(views.point_here, {'zone': ZONE, 'input': {'name': '@'}}, admin=True)
        self.assertEqual(status, 200, body)
        self.assertTrue(body['result']['updated'])
        self.assertEqual(self.http.calls[-1].method, 'PUT')
        self.assertEqual(self.http.body()['content'], '203.0.113.5')

    def test_changes_are_audited_per_account(self):
        post(views.purge, {'zone': ZONE, 'everything': True}, admin=True)
        entries = service.audit_entries(7)
        self.assertEqual(entries[0]['action'], 'purge cache')
        self.assertEqual((entries[0]['user'], entries[0]['zone']), ('bob', ZONE))
        self.assertEqual(service.audit_entries(8), [])
        self.assertNotIn(TOKEN, open(os.path.join(self.state, 'audit.log')).read())

    def test_get_results_are_cached(self):
        post(views.zones, {}, admin=True)
        post(views.zones, {}, admin=True)
        self.assertEqual(sum(1 for c in self.http.calls if c.url.endswith('/zones')), 1)

    def test_rate_limit(self):
        post(views.zones, {}, admin=True)
        service._cache[('user-7', 'zones')] = (0, service._cache[('user-7', 'zones')][1])   # expired
        self.http.routes[('GET', '/zones')] = Response(429, {'success': False}, {'Retry-After': '30'})
        status, body, _ = post(views.zones, {}, admin=True)
        self.assertEqual(status, 200)   # the stale copy is served
        service._cache.clear()
        status, body, _ = post(views.zones, {}, admin=True)
        self.assertEqual(status, 429)
        self.assertIn('30 seconds', body['error_message'])

    def test_origin_certificate(self):
        service.set_link(7, ZONE, 'example.com')
        self.http.routes[('POST', '/certificates')] = ok_result({'id': '1', 'certificate': '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n',
                                                                 'expires_on': '2041-01-01'})
        with mock.patch('universalAddons.privileged.call_private', return_value={'installed': 'example.com'}) as install:
            status, body, _ = post(views.origin_cert, {'zone': ZONE}, admin=True)
        self.assertEqual(status, 200, body)
        sent = self.http.body()
        self.assertEqual(sent['hostnames'], ['example.com', '*.example.com'])
        self.assertTrue(sent['csr'].startswith('-----BEGIN CERTIFICATE REQUEST-----'))
        self.assertEqual(install.call_args[1]['domain'], 'example.com')
        self.assertIn('PRIVATE KEY', install.call_args[1]['key_pem'])
        self.assertNotIn('PRIVATE KEY', json.dumps(body))


# ----------------------------------------------------------------------------------------- import

class Import(SimpleTestCase):
    def models(self, records):
        local = SimpleNamespace(name='example.com')

        class Query(list):
            def order_by(self, *args):
                return self

        domains = SimpleNamespace(objects=SimpleNamespace(filter=lambda name: SimpleNamespace(
            first=lambda: local if name == 'example.com' else None)))
        recs = SimpleNamespace(objects=SimpleNamespace(filter=lambda domainOwner: Query(
            SimpleNamespace(disabled=0, **r) for r in records)))
        return SimpleNamespace(Domains=domains, Records=recs)

    def test_preview(self):
        models = self.models([
            {'name': 'example.com', 'type': 'SOA', 'content': 'x', 'ttl': 3600, 'prio': 0},
            {'name': 'example.com', 'type': 'A', 'content': '192.0.2.1', 'ttl': 3600, 'prio': 0},
            {'name': 'www.example.com', 'type': 'CNAME', 'content': 'example.com', 'ttl': 3600, 'prio': 0},
            {'name': 'example.com', 'type': 'MX', 'content': 'mail.example.com', 'ttl': 3600, 'prio': 10},
            {'name': 'example.com', 'type': 'TXT', 'content': '"v=spf1 a mx ~all"', 'ttl': 3600, 'prio': 0},
            {'name': '_sip._tcp.example.com', 'type': 'SRV', 'content': '5 5060 sip.example.com', 'ttl': 3600, 'prio': 1},
            {'name': 'example.com', 'type': 'CAA', 'content': '0 issue "letsencrypt.org"', 'ttl': 3600, 'prio': 0},
            {'name': 'mail.example.com', 'type': 'A', 'content': 'not-an-ip', 'ttl': 3600, 'prio': 0},
        ])
        existing = [{'type': 'A', 'name': 'example.com', 'content': '192.0.2.1'},
                    {'type': 'A', 'name': 'www.example.com', 'content': '192.0.2.1'}]
        rows = service.import_preview('example.com', 'example.com', existing, models=models)
        actions = {(r['type'], r['name']): r['action'] for r in rows}
        self.assertEqual(actions, {('A', 'example.com'): 'exists', ('CNAME', 'www.example.com'): 'conflict',
                                   ('MX', 'example.com'): 'create', ('TXT', 'example.com'): 'create',
                                   ('SRV', '_sip._tcp.example.com'): 'create', ('CAA', 'example.com'): 'create',
                                   ('A', 'mail.example.com'): 'skip'})
        txt = [r for r in rows if r['type'] == 'TXT'][0]
        self.assertEqual(txt['body']['content'], 'v=spf1 a mx ~all')
        srv = [r for r in rows if r['type'] == 'SRV'][0]
        self.assertEqual(srv['body']['data'], {'priority': 1, 'weight': 5, 'port': 5060, 'target': 'sip.example.com'})

    def test_no_local_zone(self):
        with self.assertRaisesRegex(CloudflareError, 'no PowerDNS zone'):
            service.import_preview('nothere.org', 'nothere.org', [], models=self.models([]))


# ---------------------------------------------------------------------------------------- GraphQL

class GraphQL(SimpleTestCase):
    NOW = datetime.datetime(2026, 11, 16, 10, 25)

    def test_24h_uses_hourly_groups(self):
        query, variables = cf.analytics_query(ZONE, '24h', now=self.NOW)
        self.assertIn('httpRequests1hGroups(limit: 24', query)
        self.assertIn('datetime_geq: $start, datetime_lt: $end', query)
        self.assertIn('$start: Time', query)
        self.assertEqual(variables, {'zoneTag': ZONE, 'start': '2026-11-15T11:00:00Z', 'end': '2026-11-16T11:00:00Z'})

    def test_days_use_daily_groups(self):
        query, variables = cf.analytics_query(ZONE, '30d', now=self.NOW)
        self.assertIn('httpRequests1dGroups(limit: 30', query)
        self.assertIn('date_geq: $start, date_leq: $end', query)
        self.assertIn('countryMap { clientCountryName requests threats }', query)
        self.assertEqual(variables, {'zoneTag': ZONE, 'start': '2026-10-18', 'end': '2026-11-16'})
        _, week = cf.analytics_query(ZONE, '7d', now=self.NOW)
        self.assertEqual(week['start'], '2026-11-10')

    def test_zone_id_and_range_validated(self):
        with self.assertRaises(CloudflareError):
            cf.analytics_query('x" } evil', '24h')
        with self.assertRaises(CloudflareError):
            cf.analytics_query(ZONE, '90d')

    def test_request_and_summary(self):
        http = FakeHttp()
        answer = {'data': {'viewer': {'zones': [{'series': [
            {'dimensions': {'when': '2026-11-15'}, 'uniq': {'uniques': 5},
             'sum': {'requests': 100, 'cachedRequests': 60, 'bytes': 1000, 'cachedBytes': 700, 'threats': 2, 'pageViews': 40,
                     'countryMap': [{'clientCountryName': 'IN', 'requests': 80, 'threats': 1},
                                    {'clientCountryName': 'US', 'requests': 20, 'threats': 1}]}},
            {'dimensions': {'when': '2026-11-16'}, 'uniq': {'uniques': 3},
             'sum': {'requests': 50, 'cachedRequests': 10, 'bytes': 500, 'cachedBytes': 100, 'threats': 0, 'pageViews': 20,
                     'countryMap': [{'clientCountryName': 'US', 'requests': 50, 'threats': 0}]}}]}]}}, 'errors': None}
        http.request = mock.Mock(return_value=Response(200, answer))
        result = cf.Client(TOKEN, http).analytics(ZONE, '7d')
        args, kwargs = http.request.call_args
        self.assertEqual(args, ('POST', cf.GRAPHQL))
        self.assertIs(kwargs['allow_redirects'], False)
        sent = json.loads(kwargs['data'])
        self.assertIn('httpRequests1dGroups', sent['query'])
        self.assertEqual(sent['variables']['zoneTag'], ZONE)
        self.assertEqual(result['totals']['requests'], 150)
        self.assertEqual(result['totals']['uncachedRequests'], 80)
        self.assertEqual(result['totals']['uniques'], 8)
        self.assertEqual(result['countries'][0], {'country': 'IN', 'requests': 80, 'threats': 1})
        self.assertEqual(result['countries'][1]['requests'], 70)

    def test_graphql_errors_are_reported(self):
        http = FakeHttp()
        http.request = mock.Mock(return_value=Response(200, {'data': None, 'errors': [{'message': 'zone not authorized'}]}))
        with self.assertRaisesRegex(CloudflareError, 'not authorized'):
            cf.Client(TOKEN, http).analytics(ZONE, '24h')


# ------------------------------------------------------------------------------------------- pages

class Pages(SimpleTestCase):
    def test_admin_page(self):
        status, values = page(views.page, admin=True)
        self.assertEqual(status, 200)
        self.assertEqual(values['_template'], 'universalAddons/cloudflare.html')
        self.assertTrue(values['is_admin'])
        self.assertTrue(any(p[1] == 'DNS' and p[2] == 'Edit' for p in values['permissions']))

    def test_user_page_needs_switch(self):
        status, _ = page(views.page, owned=('mine.example.com',))
        self.assertEqual(status, 403)
        status, values = page(views.page, owned=('mine.example.com',), policy={'cloudflare_for_users': True})
        self.assertEqual(status, 200)
        self.assertFalse(values['is_admin'])

    def test_template_renders(self):
        request = RequestFactory().get('/addons/cloudflare/')
        request.session = {}
        html = render_to_string('universalAddons/cloudflare.html', {
            'request': request, 'is_admin': True, 'permissions': cf.TOKEN_PERMISSIONS})
        self.assertIn('ua-wrap', html)
        self.assertIn('Zone Settings', html)
        self.assertIn('Firewall Services', html)
        self.assertIn('cf-server-save', html)
        user = render_to_string('universalAddons/cloudflare.html', {'request': request, 'is_admin': False,
                                                                    'permissions': cf.TOKEN_PERMISSIONS})
        self.assertNotIn('cf-server-save', user)

    def test_registered(self):
        from django.urls import reverse
        from universalAddons import access, registry, runner
        self.assertEqual(reverse('ua-cloudflare'), '/addons/cloudflare/')
        self.assertEqual(reverse('ua-cloudflare-dns_save'), '/addons/cloudflare/ajax/dns_save')
        self.assertIn('cloudflare', [m.key for m in registry.MODULES])
        self.assertIn(('cloudflare', 'cloudflare_for_users'), access.USER_FEATURES)
        self.assertEqual(runner.MODULES['cloudflare'], 'universalAddons.cloudflare.actions')
