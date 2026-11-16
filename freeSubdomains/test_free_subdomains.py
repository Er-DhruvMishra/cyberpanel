"""Free subdomain service: label rules, ownership, storage, and the three DNS providers.

No live DNS: PowerDNS is exercised against an in-memory stand-in for the panel's dns models, and
Cloudflare/deSEC against a recorded fake HTTP client.
"""
import json
import os
import stat
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory, SimpleTestCase, TestCase

from freeSubdomains import providers, service
from freeSubdomains.models import FreeSubdomain
from freeSubdomains.providers import ProviderError
from freeSubdomains.service import FreeSubdomainError


# --------------------------------------------------------------------------- in-memory dns models

class _Query(list):
    def filter(self, **kw):
        def match(row):
            for key, value in kw.items():
                field, _, op = key.partition('__')
                actual = row.pk if field == 'pk' else getattr(row, field)
                if op == 'in':
                    if actual not in value:
                        return False
                elif actual != value:
                    return False
            return True
        return _Query(r for r in self if match(r))

    def exists(self):
        return bool(self)

    def first(self):
        return self[0] if self else None

    def delete(self):
        for row in list(self):
            row.store.remove(row)


class _Manager:
    def __init__(self, store):
        self.store = store

    def filter(self, **kw):
        return _Query(self.store).filter(**kw)


class FakeRecord:
    def __init__(self, store, pk, **fields):
        self.store, self.pk = store, pk
        self.__dict__.update(fields)

    def save(self, update_fields=None):
        pass


def fake_dns(zone_type='NATIVE'):
    domains, records = [], []
    zone = SimpleNamespace(pk=3, name='indianscloud.com', type=zone_type, store=domains)
    domains.append(zone)
    counter = iter(range(100, 1000))

    def add(name, rtype, content):
        records.append(FakeRecord(records, next(counter), domainOwner=zone, name=name, type=rtype, content=content))

    add('indianscloud.com', 'SOA', 'ns1.indianscloud.com hostmaster.indianscloud.com 1 10800 3600 604800 3600')
    add('indianscloud.com', 'NS', 'ns1.indianscloud.com')
    add('indianscloud.com', 'NS', 'ns2.indianscloud.com')
    add('mail.indianscloud.com', 'A', '150.241.245.94')
    models = SimpleNamespace(Domains=SimpleNamespace(objects=_Manager(domains)),
                             Records=SimpleNamespace(objects=_Manager(records)))

    class DNS:
        created, deleted = [], []

        @staticmethod
        def createDNSRecord(zone_, name, rtype, value, priority, ttl):
            DNS.created.append((zone_.name, name, rtype, value, ttl))
            add(name, rtype, value)

        @staticmethod
        def deleteDNSRecord(record_id):
            DNS.deleted.append(record_id)
            models.Records.objects.filter(pk=record_id).delete()

    return models, DNS, records, zone


def serial(records):
    soa = next(r for r in records if r.type == 'SOA')
    return int(soa.content.split()[2])


# ---------------------------------------------------------------------------------- fake HTTP

class FakeHTTP:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for (want_method, fragment), answer in self.routes.items():
            if want_method == method and fragment in url:
                status, body = answer(kwargs) if callable(answer) else answer
                return SimpleNamespace(status_code=status, headers={},
                                       json=(lambda b=body: b) if body is not None else (lambda: (_ for _ in ()).throw(ValueError())))
        return SimpleNamespace(status_code=404, headers={}, json=lambda: {'detail': 'Not found.'})


CONFIG = dict(service.DEFAULTS, ipv4='150.241.245.94', ipv6='off')


# ------------------------------------------------------------------------------------- labels

class LabelRules(SimpleTestCase):
    def test_valid_labels_are_lower_cased(self):
        self.assertEqual('my-site1', service.clean_label('  My-Site1 ', CONFIG))
        self.assertEqual('abc', service.clean_label('abc', CONFIG))
        self.assertEqual('a' * 40, service.clean_label('a' * 40, CONFIG))

    def test_invalid_labels(self):
        for label in ('ab', 'a' * 41, '-abc', 'abc-', 'a_bc', 'a.bc', 'ab c', 'a--b', 'xn--abc', 'ünï', '', None,
                      'abc;rm', '../x'):
            with self.subTest(label=label), self.assertRaises(FreeSubdomainError):
                service.clean_label(label, CONFIG)

    def test_reserved_and_extra_reserved(self):
        for label in ('www', 'mail', 'ns1', 'ns2', 'admin', 'webmail', 'cpanel', 'hostmaster', 'national', 'ncr'):
            with self.subTest(label=label), self.assertRaises(FreeSubdomainError):
                service.clean_label(label, CONFIG)
        with self.assertRaises(FreeSubdomainError):
            service.clean_label('shop', dict(CONFIG, extra_reserved=['shop']))

    def test_split_only_matches_names_directly_under_the_base(self):
        self.assertEqual(('blog', 'hostedon.indianscloud.com'), service.split('Blog.hostedon.indianscloud.com.', CONFIG))
        self.assertIsNone(service.split('hostedon.indianscloud.com', CONFIG))
        self.assertIsNone(service.split('blog.example.com', CONFIG))
        self.assertIsNone(service.split('evilhostedon.indianscloud.com', CONFIG))

    def test_creation_request(self):
        self.assertTrue(service.creation_request({}, 'blog.hostedon.indianscloud.com', CONFIG))
        self.assertTrue(service.creation_request({'freeSubdomain': 1}, 'blog.hostedon.indianscloud.com', CONFIG))
        self.assertFalse(service.creation_request({}, 'example.com', CONFIG))
        with self.assertRaises(FreeSubdomainError):
            service.creation_request({'freeSubdomain': 1}, 'example.com', CONFIG)
        with self.assertRaises(FreeSubdomainError):
            service.creation_request({}, 'www.hostedon.indianscloud.com', CONFIG)
        with self.assertRaises(FreeSubdomainError):
            service.creation_request({}, 'a.b.hostedon.indianscloud.com', CONFIG)
        off = dict(CONFIG, enabled=False)
        self.assertFalse(service.creation_request({}, 'blog.hostedon.indianscloud.com', off))
        with self.assertRaises(FreeSubdomainError):
            service.creation_request({'freeSubdomain': '1'}, 'blog.hostedon.indianscloud.com', off)


# ------------------------------------------------------------------------------------ storage

class Storage(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        patcher = mock.patch.object(service, 'STATE_DIR', os.path.join(self.dir, 'free-subdomains'))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_defaults_point_at_the_local_zone(self):
        config = service.load_config()
        self.assertEqual(('powerdns', 'hostedon.indianscloud.com'), (config['provider'], config['base']))

    def test_tokens_are_private_and_never_returned(self):
        config = service.validate_config({'provider': 'cloudflare', 'base': 'free.example.com',
                                          'cloudflare_zone_id': 'a' * 32, 'ttl': '120'})
        secrets = service.clean_secrets({'cloudflare': 'cf_' + 'T' * 37, 'desec': ''})
        shown = service.save(config, secrets)
        token_file = os.path.join(service.STATE_DIR, 'cloudflare.token')
        self.assertEqual(0o600, stat.S_IMODE(os.stat(token_file).st_mode))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(os.path.join(service.STATE_DIR, 'config.json')).st_mode))
        self.assertEqual(0o700, stat.S_IMODE(os.stat(service.STATE_DIR).st_mode))
        self.assertEqual(os.getuid(), os.stat(token_file).st_uid)
        self.assertNotIn('T' * 37, json.dumps(shown))
        self.assertEqual({'cloudflare': True, 'desec': False}, shown['tokens'])
        self.assertNotIn('T' * 37, open(os.path.join(service.STATE_DIR, 'config.json')).read())
        # A blank token keeps the saved one.
        service.save(service.validate_config({}), service.clean_secrets({'cloudflare': ''}))
        self.assertTrue(service.public_config()['tokens']['cloudflare'])
        service.forget_token('cloudflare')
        self.assertFalse(service.public_config()['tokens']['cloudflare'])

    def test_validation(self):
        for raw in ({'provider': 'nope'}, {'base': 'not a domain'}, {'ttl': 10}, {'ipv4': '::1'}, {'ipv6': '1.2.3.4'},
                    {'per_user_limit': -1}, {'cloudflare_zone_id': 'xyz'}, {'extra_reserved': ['bad label!']}):
            with self.subTest(raw=raw), self.assertRaises(FreeSubdomainError):
                service.validate_config(raw)
        for raw in ({'cloudflare': 'short'}, {'cloudflare': 'has space ' * 3}, {'other': 'x' * 30}):
            with self.subTest(raw=raw), self.assertRaises(FreeSubdomainError):
                service.clean_secrets(raw)
        self.assertEqual(['blog', 'shop'], service.validate_config({'extra_reserved': 'Shop, blog'})['extra_reserved'])


# --------------------------------------------------------------------------------- providers

class PowerDNSProvider(SimpleTestCase):
    def make(self, zone_type='NATIVE', base='hostedon.indianscloud.com'):
        models, dns, records, zone = fake_dns(zone_type)
        return providers.LocalPowerDNS(base, dns_models=models, dns_utilities=dns), dns, records

    def test_test_reports_zone_without_writing(self):
        provider, dns, records = self.make()
        before = [(r.name, r.type, r.content) for r in records]
        message = provider.test()
        self.assertIn('indianscloud.com', message)
        self.assertIn('NATIVE', message)
        self.assertEqual(before, [(r.name, r.type, r.content) for r in records])
        self.assertEqual([], dns.created)

    def test_missing_zone(self):
        provider, _, _ = self.make(base='hostedon.example.org')
        with self.assertRaises(ProviderError):
            provider.test()

    def test_create_and_delete_a_and_aaaa_and_bump_native_serial(self):
        provider, dns, records = self.make()
        refs = provider.create('blog.hostedon.indianscloud.com', '150.241.245.94', '2001:db8::5', 300)
        self.assertEqual([('indianscloud.com', 'blog.hostedon.indianscloud.com', 'A', '150.241.245.94', 300),
                          ('indianscloud.com', 'blog.hostedon.indianscloud.com', 'AAAA', '2001:db8::5', 300)],
                         dns.created)
        self.assertEqual(2, len(refs['record_ids']))
        self.assertEqual(2, serial(records))
        with self.assertRaises(ProviderError):  # the name is now taken in the zone
            provider.create('blog.hostedon.indianscloud.com', '150.241.245.94', '', 300)
        self.assertEqual(2, provider.delete('blog.hostedon.indianscloud.com', refs))
        self.assertFalse([r for r in records if r.name == 'blog.hostedon.indianscloud.com'])
        self.assertEqual(3, serial(records))
        self.assertTrue([r for r in records if r.name == 'mail.indianscloud.com'], 'other records untouched')

    def test_master_zone_serial_is_left_to_the_panel_helper(self):
        provider, dns, records = self.make('MASTER')
        provider.create('blog.hostedon.indianscloud.com', '150.241.245.94', '', 300)
        self.assertEqual(1, serial(records))

    def test_slave_zone_refused(self):
        provider, _, _ = self.make('SLAVE')
        with self.assertRaises(ProviderError):
            provider.zone()


class CloudflareProvider(SimpleTestCase):
    ZONE = 'f' * 32

    def make(self, routes):
        http = FakeHTTP(routes)
        return providers.Cloudflare('free.example.com', self.ZONE, 'secret-token', http=http), http

    def test_apply_reads_only(self):
        provider, http = self.make({
            ('GET', '/zones/%s/dns_records' % self.ZONE): (200, {'success': True, 'result': []}),
            ('GET', '/zones/%s' % self.ZONE): (200, {'success': True, 'result': {'name': 'example.com'}}),
        })
        self.assertIn('example.com', provider.test())
        self.assertEqual({'GET'}, {c[0] for c in http.calls})
        self.assertEqual('Bearer secret-token', http.calls[0][2]['headers']['Authorization'])

    def test_wrong_zone_and_bad_token(self):
        provider, _ = self.make({('GET', '/zones/'): (200, {'success': True, 'result': {'name': 'other.org'}})})
        with self.assertRaises(ProviderError):
            provider.test()
        provider, _ = self.make({('GET', '/zones/'): (403, {'success': False, 'errors': [{'message': 'Invalid'}]})})
        with self.assertRaises(ProviderError) as caught:
            provider.test()
        self.assertNotIn('secret-token', str(caught.exception))

    def test_create_and_delete(self):
        posted = []

        def post(kwargs):
            posted.append(json.loads(kwargs['data']))
            return 200, {'success': True, 'result': {'id': 'rec%d' % len(posted)}}
        provider, http = self.make({
            ('GET', '/dns_records'): (200, {'success': True, 'result': []}),
            ('POST', '/dns_records'): post,
            ('DELETE', '/dns_records/'): (200, {'success': True, 'result': {}}),
        })
        refs = provider.create('blog.free.example.com', '192.0.2.1', '2001:db8::1', 300)
        self.assertEqual(['rec1', 'rec2'], refs['record_ids'])
        self.assertEqual(['A', 'AAAA'], [p['type'] for p in posted])
        self.assertFalse(posted[0]['proxied'])
        provider.delete('blog.free.example.com', refs)
        self.assertEqual(2, len([c for c in http.calls if c[0] == 'DELETE']))

    def test_existing_name_is_not_overwritten(self):
        provider, http = self.make({('GET', '/dns_records'): (200, {'success': True, 'result': [{'id': 'x'}]})})
        with self.assertRaises(ProviderError):
            provider.create('blog.free.example.com', '192.0.2.1', '', 300)
        self.assertFalse([c for c in http.calls if c[0] == 'POST'])


class DesecProvider(SimpleTestCase):
    def make(self, base, zone, extra=None):
        routes = {  # most specific first: FakeHTTP matches URL fragments in order
            ('GET', '/domains/%s/rrsets/' % zone): (200, []),
            ('GET', '/domains/%s/' % zone): (200, {'name': zone, 'minimum_ttl': 3600}),
            ('GET', '/domains/'): (200, [{'name': zone}]),
            ('POST', '/domains/%s/rrsets/' % zone): (201, []),
            ('PATCH', '/domains/%s/rrsets/' % zone): (200, []),
        }
        routes.update(extra or {})
        http = FakeHTTP(routes)
        return providers.Desec(base, 'desec-secret', http=http), http

    def test_apply_on_dedyn_name_reads_only(self):
        provider, http = self.make('myname.dedyn.io', 'myname.dedyn.io')
        self.assertIn('myname.dedyn.io', provider.test())
        self.assertEqual({'GET'}, {c[0] for c in http.calls})
        self.assertEqual({'owns_qname': 'myname.dedyn.io'}, http.calls[0][2]['params'])
        self.assertEqual('Token desec-secret', http.calls[0][2]['headers']['Authorization'])

    def test_create_on_own_zone_uses_bulk_write_and_minimum_ttl(self):
        provider, http = self.make('hostedon.example.com', 'example.com')
        refs = provider.create('blog.hostedon.example.com', '192.0.2.1', '2001:db8::1', 300)
        post = next(c for c in http.calls if c[0] == 'POST')
        body = json.loads(post[2]['data'])
        self.assertEqual([{'subname': 'blog.hostedon', 'type': 'A', 'ttl': 3600, 'records': ['192.0.2.1']},
                          {'subname': 'blog.hostedon', 'type': 'AAAA', 'ttl': 3600, 'records': ['2001:db8::1']}], body)
        provider.delete('blog.hostedon.example.com', refs)
        patch = next(c for c in http.calls if c[0] == 'PATCH')
        self.assertEqual([{'subname': 'blog.hostedon', 'type': 'A', 'records': []},
                          {'subname': 'blog.hostedon', 'type': 'AAAA', 'records': []}], json.loads(patch[2]['data']))

    def test_no_matching_domain_or_bad_token(self):
        provider, _ = self.make('free.example.net', 'x', {('GET', '/domains/'): (200, [])})
        with self.assertRaises(ProviderError):
            provider.test()
        provider, _ = self.make('free.example.net', 'x', {('GET', '/domains/'): (401, {'detail': 'Invalid token.'})})
        with self.assertRaises(ProviderError) as caught:
            provider.test()
        self.assertNotIn('desec-secret', str(caught.exception))

    def test_existing_rrset_is_not_overwritten(self):
        provider, http = self.make('myname.dedyn.io', 'myname.dedyn.io', {
            ('GET', '/domains/myname.dedyn.io/rrsets/'): (200, [{'subname': 'blog', 'type': 'A'}])})
        with self.assertRaises(ProviderError):
            provider.create('blog.myname.dedyn.io', '192.0.2.1', '', 3600)
        self.assertFalse([c for c in http.calls if c[0] == 'POST'])


# --------------------------------------------------------------------- reservations (database)

class FakeProvider:
    def __init__(self, fail=False):
        self.fail, self.created, self.deleted = fail, [], []

    def create(self, fqdn, ipv4, ipv6, ttl):
        if self.fail:
            raise ProviderError('zone unavailable')
        self.created.append((fqdn, ipv4, ipv6, ttl))
        return {'record_ids': [1]}

    def delete(self, fqdn, refs):
        self.deleted.append((fqdn, refs))


class Reservations(TestCase):
    def setUp(self):
        self.provider = FakeProvider()
        self.sites = set()
        for target, kwargs in (('freeSubdomains.service.make_provider', {'side_effect': lambda *a, **k: self.provider}),
                               ('freeSubdomains.service.load_config', {'side_effect': lambda: dict(CONFIG)}),
                               ('freeSubdomains.service._site_exists', {'side_effect': lambda d: d in self.sites})):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def reserve(self, name='blog.hostedon.indianscloud.com', owner=7, admin=False):
        return service.reserve(name, owner, 'user%d' % owner, owner, is_admin=admin, config=dict(CONFIG))

    def test_reserve_creates_records_and_tracks_owner(self):
        row = self.reserve('Blog.hostedon.indianscloud.com')
        self.assertEqual(('blog', 'blog.hostedon.indianscloud.com', 7, 'user7'),
                         (row.label, row.fqdn, row.owner_id, row.owner_name))
        self.assertEqual([('blog.hostedon.indianscloud.com', '150.241.245.94', '', 300)], self.provider.created)
        self.assertEqual({'record_ids': [1]}, json.loads(row.refs))

    def test_unique_and_idempotent_retry(self):
        self.reserve()
        self.assertEqual(1, FreeSubdomain.objects.count())
        self.reserve()  # same owner retrying before the site exists
        self.assertEqual(1, len(self.provider.created))
        with self.assertRaises(FreeSubdomainError):
            self.reserve(owner=8)
        self.sites.add('blog.hostedon.indianscloud.com')
        with self.assertRaises(FreeSubdomainError):
            self.reserve()  # the site exists now: a second reservation is a duplicate

    def test_existing_site_name_is_taken(self):
        self.sites.add('shop.hostedon.indianscloud.com')
        with self.assertRaises(FreeSubdomainError):
            self.reserve('shop.hostedon.indianscloud.com')
        self.assertEqual([], self.provider.created)

    def test_per_user_limit_spares_administrators(self):
        config = dict(CONFIG, per_user_limit=1)
        service.reserve('one.hostedon.indianscloud.com', 7, 'u', 7, config=config)
        with self.assertRaises(FreeSubdomainError):
            service.reserve('two.hostedon.indianscloud.com', 7, 'u', 7, config=config)
        service.reserve('two.hostedon.indianscloud.com', 7, 'u', 1, is_admin=True, config=config)

    def test_provider_failure_leaves_no_reservation(self):
        self.provider.fail = True
        with self.assertRaises(FreeSubdomainError):
            self.reserve()
        self.assertFalse(FreeSubdomain.objects.exists())

    def test_disabled_service_and_foreign_names(self):
        with self.assertRaises(FreeSubdomainError):
            service.reserve('blog.hostedon.indianscloud.com', 7, 'u', 7, config=dict(CONFIG, enabled=False))
        with self.assertRaises(FreeSubdomainError):
            self.reserve('blog.example.com')

    def test_only_owner_creator_or_admin_may_release(self):
        self.reserve(owner=7)
        with self.assertRaises(PermissionError):
            service.release('blog.hostedon.indianscloud.com', 8)
        self.assertEqual([], self.provider.deleted)
        service.release('blog.hostedon.indianscloud.com', 7)
        self.assertEqual(1, len(self.provider.deleted))
        self.assertFalse(FreeSubdomain.objects.exists())
        self.reserve(owner=9)
        service.release('blog.hostedon.indianscloud.com', 1, is_admin=True)
        self.assertFalse(FreeSubdomain.objects.exists())

    def test_release_refused_while_a_site_uses_it(self):
        self.reserve()
        self.sites.add('blog.hostedon.indianscloud.com')
        with self.assertRaises(FreeSubdomainError):
            service.release('blog.hostedon.indianscloud.com', 7)

    def test_site_deletion_releases_records(self):
        self.reserve()
        self.assertFalse(service.site_deleted('other.example.com'))
        self.assertTrue(service.site_deleted('blog.hostedon.indianscloud.com'))
        self.assertFalse(FreeSubdomain.objects.exists())
        self.assertEqual(1, len(self.provider.deleted))


# ------------------------------------------------------------------------------------- views

class Views(SimpleTestCase):
    def post(self, view, body, admin=True, session=None):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 7} if session is None else session
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1 if admin else 0}):
            response = view(request)
        return response.status_code, json.loads(response.content)

    def test_settings_endpoints_are_admin_only(self):
        from freeSubdomains import views
        for name in ('overview', 'test', 'save', 'forget', 'release'):
            with self.subTest(view=name), mock.patch.object(service, 'save') as save:
                self.assertEqual(403, self.post(getattr(views, name), {}, admin=False)[0])
                save.assert_not_called()

    def test_overview_never_contains_a_token(self):
        from freeSubdomains import views
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory, \
                mock.patch.object(service, 'STATE_DIR', directory), \
                mock.patch.object(service, 'listing', return_value=[]):
            service.save(service.load_config(), {'desec': 'D' * 30})
            status, body = self.post(views.overview, {})
        self.assertEqual(200, status)
        self.assertNotIn('D' * 30, json.dumps(body))
        self.assertTrue(body['config']['tokens']['desec'])

    def test_apply_runs_provider_test_with_unsaved_settings(self):
        from freeSubdomains import views
        fake = mock.Mock()
        fake.test.return_value = 'Zone ok.'
        with mock.patch.object(service, 'make_provider', return_value=fake) as make, \
                mock.patch.object(service, 'server_ipv4', return_value='192.0.2.1'), \
                mock.patch.object(service, 'save') as save:
            status, body = self.post(views.test, {'config': {'provider': 'desec', 'base': 'me.dedyn.io'},
                                                  'secrets': {'desec': 'S' * 30}})
        self.assertEqual((200, 1), (status, body['status']), body)
        self.assertIn('Zone ok.', body['message'])
        self.assertEqual('S' * 30, make.call_args.args[1]['desec'])
        save.assert_not_called()

    def test_name_check_requires_create_website_permission(self):
        from freeSubdomains import views
        request = RequestFactory().post('/x', data=json.dumps({'label': 'blog'}), content_type='application/json')
        request.session = {'userID': 7}
        with mock.patch('plogical.acl.ACLManager.loadedACL', return_value={'admin': 0, 'createWebsite': 0}):
            self.assertEqual(403, views.check(request).status_code)
        with mock.patch('plogical.acl.ACLManager.loadedACL', return_value={'admin': 0, 'createWebsite': 1}), \
                mock.patch.object(service, 'load_config', return_value=dict(CONFIG)), \
                mock.patch.object(service, 'offered_base', return_value='hostedon.indianscloud.com'), \
                mock.patch.object(service, 'availability', return_value=('blog.hostedon.indianscloud.com', None)):
            body = json.loads(views.check(request).content)
        self.assertEqual((1, True), (body['status'], body['available']))

    def test_registry_lists_the_add_on(self):
        from django.urls import reverse
        from universalAddons import registry
        self.assertIn('freesub', [m.key for m in registry.MODULES])
        self.assertEqual('/addons/free-subdomains/', reverse('ua-freesub'))
