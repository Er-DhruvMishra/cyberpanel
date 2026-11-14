import json
import os
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons.webterm import actions, service, shell, tickets, views


class Tickets(SimpleTestCase):
    def setUp(self):
        self.dir = os.path.join(tempfile.mkdtemp(), 't')

    def record(self, **kw):
        return dict({'user_id': 7, 'username': 'u', 'is_admin': False, 'domain': 'shop.example.com',
                     'system_user': 'shop1234', 'root': False, 'ip': '203.0.113.9', 'host': 'panel.example.com:8090'}, **kw)

    def test_consumed_once(self):
        token = tickets.issue(self.record(), self.dir)
        self.assertEqual(tickets.consume(token, '203.0.113.9', self.dir)['system_user'], 'shop1234')
        with self.assertRaisesRegex(tickets.TicketError, 'already used'):
            tickets.consume(token, '203.0.113.9', self.dir)

    def test_expiry_and_address(self):
        token = tickets.issue(self.record(), self.dir, now=time.time() - 120)
        with self.assertRaisesRegex(tickets.TicketError, 'expired'):
            tickets.consume(token, '203.0.113.9', self.dir)
        token = tickets.issue(self.record(), self.dir)
        with self.assertRaisesRegex(tickets.TicketError, 'different address'):
            tickets.consume(token, '198.51.100.1', self.dir)
        token = tickets.issue(self.record(), self.dir)
        self.assertEqual(tickets.consume(token, None, self.dir)['domain'], 'shop.example.com')

    def test_token_never_stored_and_files_private(self):
        token = tickets.issue(self.record(), self.dir)
        names = os.listdir(self.dir)
        self.assertNotIn(token, ''.join(names))
        self.assertEqual(oct(os.stat(os.path.join(self.dir, names[0])).st_mode & 0o777), '0o600')

    def test_outstanding_cap(self):
        for _ in range(tickets.MAX_OUTSTANDING_PER_USER):
            tickets.issue(self.record(), self.dir)
        with self.assertRaisesRegex(tickets.TicketError, 'Too many'):
            tickets.issue(self.record(), self.dir)


class Spawn(SimpleTestCase):
    def pw(self, name, uid=5001, gid=5001, home='/home/shop.example.com', shell_='/bin/bash'):
        return SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid, pw_dir=home, pw_shell=shell_)

    def build(self, record, policy=None, entry=None, groups=(5001,), names=None):
        names = names or {5001: 'shop1234'}
        return shell.build_spawn(record, policy or {'terminal_for_users': True, 'terminal_root_for_admins': False},
                                 getpwnam=lambda n: entry or self.pw(n), getgrouplist=lambda n, g: list(groups),
                                 getgrgid=lambda g: SimpleNamespace(gr_name=names.get(g, 'g%d' % g)),
                                 shells={'/bin/bash'}, exists=lambda p: True)

    def test_site_user_shell(self):
        spec = self.build({'system_user': 'shop1234', 'is_admin': False})
        self.assertEqual((spec.user, spec.uid, spec.home, spec.argv), ('shop1234', 5001, '/home/shop.example.com', ['-bash']))
        self.assertNotIn('LD_PRELOAD', spec.env)

    def test_refusals(self):
        with self.assertRaisesRegex(shell.ShellError, 'not enabled'):
            self.build({'system_user': 'shop1234', 'is_admin': False}, policy={'terminal_for_users': False})
        with self.assertRaisesRegex(shell.ShellError, 'Root shells'):
            self.build({'root': True, 'is_admin': True})
        with self.assertRaisesRegex(shell.ShellError, 'system account'):
            self.build({'system_user': 'shop1234', 'is_admin': True}, entry=self.pw('shop1234', uid=48))
        with self.assertRaisesRegex(shell.ShellError, 'wheel'):
            self.build({'system_user': 'shop1234', 'is_admin': True}, groups=(5001, 10), names={10: 'wheel'})
        with self.assertRaisesRegex(shell.ShellError, 'usable'):
            self.build({'system_user': 'cyberpanel', 'is_admin': True})
        with self.assertRaisesRegex(shell.ShellError, 'home'):
            self.build({'system_user': 'shop1234', 'is_admin': True}, entry=self.pw('shop1234', home='/etc'))

    def test_root_only_with_policy_and_admin(self):
        policy = {'terminal_for_users': False, 'terminal_root_for_admins': True}
        spec = shell.build_spawn({'root': True, 'is_admin': True}, policy,
                                 getpwnam=lambda n: SimpleNamespace(pw_dir='/root'), shells={'/bin/bash'})
        self.assertEqual(spec.uid, 0)
        with self.assertRaises(shell.ShellError):
            shell.build_spawn({'root': True, 'is_admin': False}, policy)

    def test_limits(self):
        limits = shell.SessionLimits(per_user=1, total=2)
        limits.acquire('a')
        with self.assertRaises(shell.ShellError):
            limits.acquire('a')
        limits.release('a')
        limits.acquire('a')


class Proxy(SimpleTestCase):
    VHOST = 'docRoot $VH_ROOT/public_html\n\nrewrite  {\n enable 1\n}\n\nvhssl  {\n  keyFile x\n}\n'

    def test_block_idempotent_before_vhssl_and_removable(self):
        once = actions.apply_block(self.VHOST, 8095)
        self.assertEqual(actions.apply_block(once, 8095), once)
        self.assertLess(once.index(actions.MARK_END), once.index('vhssl'))
        self.assertIn('websocket /cp-webterm/ws {\n  address                 127.0.0.1:8095\n}', once)
        self.assertEqual(once.count('{'), once.count('}'))
        self.assertNotIn(actions.MARK_BEGIN, actions.strip_block(once))

    def test_refuses_foreign_websocket_context(self):
        with self.assertRaises(actions.SetupError):
            actions.apply_block(self.VHOST + 'websocket /cp-webterm/ws {\n address 1.2.3.4:1\n}\n', 8095)

    def test_origin_and_proxy_address(self):
        self.assertTrue(service.origin_allowed('https://panel.example.com:8090', 'panel.example.com:8090'))
        self.assertFalse(service.origin_allowed('https://evil.example', 'panel.example.com:8090'))
        self.assertEqual(service.client_address('127.0.0.1', '203.0.113.9', True), '203.0.113.9')
        self.assertEqual(service.client_address('198.51.100.7', '203.0.113.9', True), '198.51.100.7')
        self.assertEqual(service.client_address('127.0.0.1', '10.0.0.1', True, '203.0.113.5'), '203.0.113.5')
        self.assertIsNone(service.client_address('127.0.0.1', '', True))
        self.assertEqual(service.client_address('127.0.0.1', '203.0.113.9', False), '127.0.0.1')

    def test_unit_is_hardened(self):
        unit = service.render_unit(service.DEFAULT_CONFIG)
        for line in ('NoNewPrivileges=yes', 'OOMScoreAdjust=300', 'MemoryLimit=1024M', 'KillMode=control-group'):
            self.assertIn(line, unit.splitlines())


class Views(SimpleTestCase):
    def post(self, body, admin=0, owns=True, policy=None):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json',
                                        REMOTE_ADDR='203.0.113.9', HTTP_HOST='panel.example.com:8090')
        request.session = {'userID': 3}
        from universalAddons import access
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('loginSystem.models.Administrator.objects.get', return_value=SimpleNamespace(userName='bob')), \
                mock.patch('universalAddons.access.ACLManager.checkOwnership', return_value=1 if owns else 0), \
                mock.patch('universalAddons.access.load_policy', return_value=dict(access.DEFAULT_POLICY, **(policy or {}))), \
                mock.patch('websiteFunctions.models.Websites.objects.get', return_value=SimpleNamespace(externalApp='shop1234')), \
                mock.patch('universalAddons.privileged.call', return_value={'ticket': 't'}) as call:
            response = views.ticket(request)
        return response.status_code, call

    def test_users_need_policy_and_ownership(self):
        self.assertEqual(self.post({'domain': 'shop.example.com'})[0], 403)
        status, call = self.post({'domain': 'other.com'}, owns=False, policy={'terminal_for_users': True})
        self.assertEqual(status, 403)
        call.assert_not_called()
        status, call = self.post({'domain': 'shop.example.com'}, policy={'terminal_for_users': True})
        self.assertEqual(status, 200)
        record = call.call_args[1]['record']
        self.assertEqual((record['system_user'], record['root'], record['ip'], record['host']),
                         ('shop1234', False, '203.0.113.9', 'panel.example.com:8090'))

    def test_root_only_for_admins(self):
        status, call = self.post({'domain': '', 'root': True}, policy={'terminal_for_users': True})
        self.assertEqual(status, 403)
        call.assert_not_called()
        status, call = self.post({'root': True}, admin=1)
        self.assertEqual(call.call_args[1]['record']['system_user'], 'root')


class Probe(SimpleTestCase):
    def test_probe_key_is_a_valid_websocket_key(self):
        import base64
        import inspect
        import re
        key = re.search(r"Sec-WebSocket-Key: ([A-Za-z0-9+/=]+)", inspect.getsource(actions._ws_probe)).group(1)
        self.assertEqual(len(base64.b64decode(key)), 16, 'servers reject keys that are not 16 random bytes')
