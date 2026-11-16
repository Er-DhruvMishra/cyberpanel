"""Uptime monitoring: SSRF guard (incl. DNS rebinding), checks, the down/up state machine, history,
ownership, limits, endpoints and the page."""
import json
import os
import socket
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from universalAddons.notify import netguard
from universalAddons.tests import helpers
from universalAddons.uptime import service, views


def resolver_for(*addresses, calls=None):
    def resolve(host, port, *args):
        if calls is not None:
            calls.append(host)
        return [(socket.AF_INET6 if ':' in a else socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port))
                for a in addresses]
    return resolve


PUBLIC = resolver_for('93.184.216.34')


class FakeResponse:
    def __init__(self, status=200, body=b'hello world', location=None):
        self.status, self._body, self._location = status, body, location

    def read(self, limit):
        return self._body[:limit]

    def getheader(self, name):
        return self._location if name == 'Location' else None

    def getheaders(self):
        return [('Location', self._location)] if self._location else []


class FakeConnection:
    def __init__(self, response, log, address):
        self.response, self.log, self.address, self.sock = response, log, address, None

    def request(self, method, path, body=None, headers=None):
        self.log.append((self.address, method, path))

    def getresponse(self):
        return self.response

    def close(self):
        pass


class SSRFGuard(SimpleTestCase):
    def test_blocked_addresses(self):
        for address in ('127.0.0.1', '127.8.9.1', '10.0.0.1', '10.255.1.2', '172.16.5.4', '192.168.1.1',
                        '169.254.169.254', '::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1',
                        '0.0.0.0', '100.64.0.1', '224.0.0.1', '64:ff9b::a00:1', '2002:a00:1::'):
            self.assertFalse(netguard.address_allowed(address), address)
        for address in ('93.184.216.34', '8.8.8.8', '2606:4700:4700::1111'):
            self.assertTrue(netguard.address_allowed(address), address)

    def test_admins_may_target_this_server_only(self):
        local = {netguard.ipaddress.ip_address('127.0.0.1'), netguard.ipaddress.ip_address('::1')}
        self.assertTrue(netguard.address_allowed('127.0.0.1', allow_local=True, local=local))
        self.assertTrue(netguard.address_allowed('::1', allow_local=True, local=local))
        self.assertFalse(netguard.address_allowed('10.0.0.1', allow_local=True, local=local))
        self.assertFalse(netguard.address_allowed('169.254.169.254', allow_local=True, local=local))
        self.assertFalse(netguard.address_allowed('127.0.0.1', allow_local=False, local=local))

    def test_any_private_answer_refuses_the_host(self):
        with self.assertRaises(netguard.GuardError):
            netguard.resolve('evil.example', 80, resolver=resolver_for('93.184.216.34', '10.1.1.1'))
        with self.assertRaises(netguard.GuardError):
            netguard.resolve('v6.example', 80, resolver=resolver_for('::1'))
        self.assertEqual(netguard.resolve('ok.example', 80, resolver=PUBLIC), '93.184.216.34')

    def test_dns_rebinding_resolves_once_and_connects_to_that_address(self):
        answers = iter([['93.184.216.34'], ['127.0.0.1']])
        calls, log = [], []

        def rebinding(host, port, *args):
            calls.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port)) for a in next(answers)]

        def factory(scheme, host, port, address, timeout):
            return FakeConnection(FakeResponse(), log, address)
        result = netguard.request('http://rebind.example/', resolver=rebinding, connection_factory=factory)
        self.assertEqual(result['status'], 200)
        self.assertEqual(calls, ['rebind.example'])           # resolved exactly once
        self.assertEqual(log, [('93.184.216.34', 'GET', '/')])  # and connected to the checked address

    def test_redirects_to_private_addresses_are_refused(self):
        log = []
        resolvers = {'public.example': '93.184.216.34', 'internal.example': '10.0.0.7'}

        def resolve(host, port, *args):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (resolvers[host], port))]

        def factory(scheme, host, port, address, timeout):
            return FakeConnection(FakeResponse(302, b'', 'http://internal.example/admin'), log, address)
        with self.assertRaisesRegex(netguard.GuardError, 'private'):
            netguard.request('http://public.example/', resolver=resolve, connection_factory=factory, max_redirects=2)
        with self.assertRaises(netguard.GuardError):
            netguard.request('http://127.0.0.1/', resolver=resolver_for('127.0.0.1'))
        with self.assertRaises(netguard.GuardError):
            netguard.request('http://user:pw@public.example/', resolver=resolve)

    def test_tcp(self):
        with self.assertRaises(netguard.GuardError):
            netguard.tcp_check('db.internal', 3306, resolver=resolver_for('192.168.0.2'), connect=mock.Mock())
        connect = mock.Mock()
        netguard.tcp_check('mail.example', 25, resolver=PUBLIC, connect=connect)
        self.assertEqual(connect.call_args[0][0], ('93.184.216.34', 25))


class StateMachine(SimpleTestCase):
    def test_two_failures_mean_down_one_success_up(self):
        state, fails = 'unknown', 0
        events = []
        for ok in (True, False, True, False, False, False, True, True):
            state, fails, change = service.transition(state, fails, ok)
            events.append((state, change))
        self.assertEqual(events, [('up', None), ('up', None), ('up', None), ('up', None), ('down', 'down'),
                                  ('down', None), ('up', 'up'), ('up', None)])
        self.assertEqual(service.transition('unknown', 1, False), ('down', 2, 'down'))


class Checks(SimpleTestCase):
    def test_http_status_and_keyword(self):
        monitor = {'kind': 'http', 'target': 'https://a.example/', 'keyword': 'hello', 'keyword_mode': 'present',
                   'allow_local': 0}
        ok = lambda status=200, body=b'hello': (lambda url, **kw: {'status': status, 'body': body, 'ms': 12,
                                                                    'cert_expires': 99})
        self.assertTrue(service.run_check(monitor, http=ok())['ok'])
        self.assertEqual(service.run_check(monitor, http=ok(500))['error'], 'HTTP 500')
        self.assertIn('not found', service.run_check(monitor, http=ok(body=b'bye'))['error'])
        self.assertFalse(service.run_check(dict(monitor, keyword_mode='absent'), http=ok())['ok'])

        def guarded(url, **kw):
            self.assertFalse(kw['allow_local'])
            raise netguard.GuardError('resolves to 10.0.0.1')
        self.assertFalse(service.run_check(monitor, http=guarded)['ok'])

    def test_validation(self):
        for spec in ({'url': 'ftp://x'}, {'url': 'https://a.example', 'interval': 2}, {'kind': 'tcp', 'host': 'a.example'},
                     {'kind': 'tcp', 'host': 'bad host', 'port': 22}, {'url': 'https://a.example', 'keyword_mode': 'absent'}):
            with self.assertRaises(service.UptimeError, msg=spec):
                service.validate(spec)
        clean = service.validate({'url': 'https://a.example/x', 'keyword': 'ok', 'interval': 1})
        self.assertEqual((clean['name'], clean['keyword_mode'], clean['interval']), ('a.example', 'present', 1))


class History(SimpleTestCase):
    def setUp(self):
        self.db = service.connect(':memory:')
        self.addCleanup(self.db.close)
        self.monitor = service.save(self.db, 7, {'url': 'https://a.example/', 'interval': 1}, resolver=PUBLIC, now=0)

    def test_incidents_and_alerts(self):
        notifier = mock.Mock()
        fail = {'ok': False, 'ms': None, 'error': 'HTTP 503', 'cert_expires': None}
        good = {'ok': True, 'ms': 80, 'error': '', 'cert_expires': None}
        for now, result in ((60, good), (120, fail), (180, fail), (240, fail), (300, good)):
            service.apply_result(self.db, service.get(self.db, self.monitor['id']), result, now, notifier)
        states = [(c[0][1], c[1]['state']) for c in notifier.call_args_list]
        self.assertEqual(states, [('uptime', 'down'), ('uptime', 'up')])
        self.assertTrue(notifier.call_args_list[1][1]['recovery'])
        incidents = service.incidents(self.db, self.monitor['id'])
        self.assertEqual((incidents[0]['started'], incidents[0]['ended'], incidents[0]['reason']), (180, 300, 'HTTP 503'))
        self.assertEqual(service.uptime_percent(self.db, self.monitor['id'], 0), 40.0)

    def test_certificate_expiry_alert(self):
        notifier = mock.Mock()
        result = {'ok': True, 'ms': 50, 'error': '', 'cert_expires': 1000 + 5 * 86400}
        service.apply_result(self.db, service.get(self.db, self.monitor['id']), result, 1000, notifier)
        self.assertEqual(notifier.call_args[0][1], 'ssl_expiry')
        self.assertEqual(notifier.call_args[1]['window'], 86400)

    def test_due_and_concurrent_run(self):
        notifier = mock.Mock()
        checker = mock.Mock(return_value={'ok': True, 'ms': 5, 'error': '', 'cert_expires': None})
        self.assertEqual(service.run_due(self.db, 100, checker, notifier, local=set()), 1)
        self.assertEqual(service.run_due(self.db, 120, checker, notifier, local=set()), 0)   # not due yet
        self.assertEqual(service.run_due(self.db, 170, checker, notifier, local=set()), 1)

    def test_prune_keeps_30_days(self):
        self.db.execute('INSERT INTO results VALUES (?, ?, 1, 5)', (self.monitor['id'], 10))
        self.db.execute('INSERT INTO results VALUES (?, ?, 1, 5)', (self.monitor['id'], 31 * 86400))
        service.prune(self.db, now=31 * 86400 + 1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM results').fetchone()[0], 1)

    def test_sparkline_and_summary(self):
        for index in range(10):
            self.db.execute('INSERT INTO results VALUES (?, ?, ?, ?)', (self.monitor['id'], 86400 + index * 600,
                                                                        int(index != 4), 100 + index))
        row = service.summary(self.db, self.monitor, now=86400 + 6000)
        self.assertTrue(row['sparkline'].startswith('<svg'))
        self.assertIn('<polyline', row['sparkline'])
        self.assertIn('#ef4444', row['sparkline'])   # the failed check
        self.assertEqual(row['uptime_24h'], 90.0)

    def test_ownership_and_limit(self):
        with self.assertRaises(PermissionError):
            service.owned(self.db, self.monitor['id'], 8)
        self.assertEqual(service.owned(self.db, self.monitor['id'], 8, is_admin=True)['id'], self.monitor['id'])
        for index in range(9):
            service.save(self.db, 7, {'url': 'https://a.example/%d' % index}, resolver=PUBLIC)
        with self.assertRaisesRegex(service.UptimeError, 'at most 10'):
            service.save(self.db, 7, {'url': 'https://a.example/x'}, resolver=PUBLIC)
        service.save(self.db, 1, {'url': 'https://a.example/x'}, is_admin=True, resolver=PUBLIC)

    def test_private_targets_refused_at_save_admins_may_check_this_server(self):
        with self.assertRaises(service.UptimeError):
            service.save(self.db, 7, {'url': 'http://169.254.169.254/latest/meta-data/'}, resolver=resolver_for('169.254.169.254'))
        local = {netguard.ipaddress.ip_address('127.0.0.1')}
        with self.assertRaises(service.UptimeError):
            service.save(self.db, 7, {'kind': 'tcp', 'host': '127.0.0.1', 'port': 3306}, resolver=resolver_for('127.0.0.1'),
                         local=local)
        saved = service.save(self.db, 1, {'kind': 'tcp', 'host': '127.0.0.1', 'port': 3306}, is_admin=True,
                             resolver=resolver_for('127.0.0.1'), local=local)
        self.assertEqual(saved['allow_local'], 1)


class Endpoints(SimpleTestCase):
    def setUp(self):
        directory = tempfile.mkdtemp()
        patcher = mock.patch.object(service, 'DB_PATH', os.path.join(directory, 'db', 'uptime.sqlite3'))
        patcher.start()
        self.addCleanup(patcher.stop)
        resolve = mock.patch('universalAddons.notify.netguard.socket.getaddrinfo', side_effect=PUBLIC)
        resolve.start()
        self.addCleanup(resolve.stop)

    def test_users_manage_only_their_monitors(self):
        status, body, _ = helpers.post(views.save, {'monitor': {'url': 'https://mine.example.com/'}})
        self.assertEqual(status, 200, body)
        monitor_id = body['result']['id']
        self.assertEqual(body['result']['owner_id'], 7)
        self.assertEqual(oct(os.stat(service.DB_PATH).st_mode & 0o777), '0o600')
        status, body, _ = helpers.post(views.overview, {})
        self.assertEqual([m['id'] for m in body['result']['monitors']], [monitor_id])
        self.assertEqual(body['result']['limit'], 10)
        with service.opened() as db:
            db.execute('UPDATE monitors SET owner_id = 99 WHERE id = ?', (monitor_id,))
        for view in (views.detail, views.delete, views.check_now):
            self.assertEqual(helpers.post(view, {'id': monitor_id})[0], 403, view.__name__)
        self.assertEqual(helpers.post(views.save, {'id': monitor_id, 'monitor': {'url': 'https://x.example/'}})[0], 403)
        self.assertEqual(helpers.post(views.overview, {})[1]['result']['monitors'], [])
        self.assertEqual(helpers.post(views.detail, {'id': monitor_id}, admin=True)[0], 200)

    def test_private_url_is_400_and_switch_off_is_403(self):
        with mock.patch('universalAddons.notify.netguard.socket.getaddrinfo', side_effect=resolver_for('10.0.0.2')):
            status, body, _ = helpers.post(views.save, {'monitor': {'url': 'http://intranet.example/'}})
        self.assertEqual(status, 400)
        self.assertIn('private', body['error_message'])
        self.assertEqual(helpers.post(views.overview, {}, policy={'uptime_for_users': False})[0], 403)

    def test_page_renders(self):
        from django.template.loader import render_to_string
        html = render_to_string('universalAddons/uptime.html', {'is_admin': False, 'site': 'mine.example.com',
                                                                'panel_brand': 'IndiansCloud'})
        self.assertIn('ua-uptime', html)
        self.assertIn('data-site="mine.example.com"', html)
        status, values = helpers.page(views.page)
        self.assertEqual((status, values['limit']), (200, 10))
        self.assertEqual(helpers.page(views.page, policy={'uptime_for_users': False})[0], 403)
