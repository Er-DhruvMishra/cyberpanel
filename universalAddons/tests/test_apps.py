import json
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons import access
from universalAddons.apps import service as svc, views

SITE = {'domain': 'shop.example.com', 'user': 'shop1234', 'home': '/home/shop.example.com'}
POLICY = dict(access.DEFAULT_POLICY)
RUNTIMES = {'node': [{'version': '24.22.3', 'path': '/opt/cp-runtimes/node/24.22.3/bin/node',
                      'npm': '/opt/cp-runtimes/node/24.22.3/bin/npm'}],
            'python': [{'version': '3.9.6', 'path': '/usr/bin/python3.9'}],
            'dotnet': [{'version': '10.0.15', 'path': '/opt/cp-runtimes/dotnet/dotnet'}]}


def spec(**kw):
    base = {'id': 'api', 'kind': 'node', 'runtime': '24.22.3', 'entry': 'server.js', 'prefix': '/api'}
    base.update(kw)
    return base


class Validation(SimpleTestCase):
    def test_valid_node_app_defaults(self):
        app = svc.validate(spec(), SITE, POLICY, {}, RUNTIMES)
        self.assertEqual((app['dir'], app['prefix'], app['memory_mb']), ('/home/shop.example.com/apps/api', '/api/', 256))

    def test_rejections(self):
        cases = [
            (spec(id='Bad Name'), 'App name'), (spec(kind='ruby'), 'Node.js, Python'),
            (spec(runtime='99.0.0'), 'not installed'), (spec(dir='/etc/evil'), 'inside'),
            (spec(dir='/home/shop.example.com/../other.com/x'), 'inside'), (spec(entry='../../etc/passwd'), 'relative'),
            (spec(entry='server.js;rm'), 'relative'), (spec(prefix='/api?x'), 'URL path'),
            (spec(prefix='/.well-known/acme/'), 'URL path'), (spec(memory_mb=999999), 'Memory'), (spec(cpu_percent=1), 'CPU'),
            (spec(kind='python', runtime='3.9.6', mode='wsgi', entry='app; import os'), 'module:callable'),
            (spec(kind='dotnet', runtime='10.0.15', entry='app.exe'), '.dll'),
        ]
        for bad, message in cases:
            with self.assertRaisesRegex(svc.AppError, message, msg=bad):
                svc.validate(bad, SITE, POLICY, {}, RUNTIMES)

    def test_name_owned_by_another_site_cannot_be_taken(self):
        existing = {'api': dict(svc.validate(spec(), SITE, POLICY, {}, RUNTIMES), domain='other.com', port=20001)}
        with self.assertRaisesRegex(svc.AppError, 'another site'):
            svc.validate(spec(), SITE, POLICY, existing, RUNTIMES)

    def test_per_site_limit_and_prefix_clash(self):
        first = dict(svc.validate(spec(), SITE, POLICY, {}, RUNTIMES), port=20000)
        with self.assertRaisesRegex(svc.AppError, 'already serves /api/'):
            svc.validate(spec(id='api2'), SITE, POLICY, {'api': first}, RUNTIMES)
        with self.assertRaisesRegex(svc.AppError, 'maximum of 1'):
            svc.validate(spec(id='web', prefix='/'), SITE, dict(POLICY, max_apps_per_site=1), {'api': first}, RUNTIMES)

    def test_env_validation(self):
        self.assertEqual(svc.validate_env({'DATABASE_URL': 'mssql://u:p@x;y=$z'}), {'DATABASE_URL': 'mssql://u:p@x;y=$z'})
        for bad in ({'PORT': '1'}, {'LD_PRELOAD': '/x.so'}, {'lower': 'x'}, {'A': 'line\nbreak'}):
            with self.assertRaises(svc.AppError, msg=bad):
                svc.validate_env(bad)

    def test_env_file_quoting(self):
        text = svc.render_env_file({'A': 'say "hi" \\ there', 'B': '$HOME'})
        self.assertEqual(text, 'A="say \\"hi\\" \\\\ there"\nB="$HOME"\n')

    def test_port_allocation_skips_used_and_busy(self):
        apps = {'a': {'port': 20000}}
        self.assertEqual(svc.allocate_port(apps, is_free=lambda p: p != 20001), 20002)


class Units(SimpleTestCase):
    def app(self, **kw):
        app = svc.validate(spec(**kw), SITE, POLICY, {}, RUNTIMES)
        app['port'] = 20005
        return app

    def test_sandbox_and_identity(self):
        unit = svc.render_unit(self.app(), RUNTIMES['node'][0], 239, False)
        for line in ('User=shop1234', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'ProtectSystem=strict',
                     'ReadWritePaths=/home/shop.example.com/apps/api', 'PrivateTmp=yes', 'MemoryLimit=256M',
                     'CPUQuota=100%', 'Environment="PORT=20005"', 'Environment="HOST=127.0.0.1"',
                     'ExecStart=/opt/cp-runtimes/node/24.22.3/bin/node /home/shop.example.com/apps/api/server.js'):
            self.assertIn(line, unit.splitlines())
        self.assertIn('-/usr/local/CyberCP', unit)
        self.assertNotIn('RestrictSUIDSGID', unit, 'not supported by systemd 239')
        self.assertNotIn('User=root', unit)

    def test_newer_systemd_and_cgroup_v2(self):
        unit = svc.render_unit(self.app(), RUNTIMES['node'][0], 252, True)
        for line in ('RestrictSUIDSGID=yes', 'ProtectKernelLogs=yes', 'MemoryMax=256M'):
            self.assertIn(line, unit.splitlines())

    def test_python_and_dotnet_commands(self):
        py = self.app(kind='python', runtime='3.9.6', mode='asgi', entry='main:app', workers=3)
        self.assertEqual(svc.exec_argv(py, RUNTIMES['python'][0]),
                         ['/home/shop.example.com/apps/api/.venv/bin/uvicorn', '--host', '127.0.0.1', '--port', '20005',
                          '--workers', '3', '--proxy-headers', '--root-path', '/api', 'main:app'])
        net = self.app(kind='dotnet', runtime='10.0.15', entry='Shop.Api.dll')
        unit = svc.render_unit(net, RUNTIMES['dotnet'][0], 239, False)
        self.assertIn('Environment="ASPNETCORE_URLS=http://127.0.0.1:20005"', unit)
        self.assertIn('ExecStart=/opt/cp-runtimes/dotnet/dotnet /home/shop.example.com/apps/api/Shop.Api.dll', unit)

    def test_unsafe_tokens_never_reach_execstart(self):
        app = self.app()
        app['entry'] = 'server.js --inspect=0.0.0.0'
        with self.assertRaisesRegex(svc.AppError, 'Unsafe'):
            svc.render_unit(app, RUNTIMES['node'][0])


class Vhost(SimpleTestCase):
    VHOST = 'docRoot $VH_ROOT/public_html\n\nrewrite  {\n enable 1\n}\n\nvhssl  {\n  keyFile x\n}\n'

    def apps(self):
        a = dict(svc.validate(spec(), SITE, POLICY, {}, RUNTIMES), port=20001, enabled=True, websocket='/ws')
        b = dict(svc.validate(spec(id='web', prefix='/'), SITE, POLICY, {}, RUNTIMES), port=20002, enabled=True)
        return [a, b]

    def test_proxy_block_longest_prefix_first_and_idempotent(self):
        once = svc.apply_to_vhost(self.VHOST, self.apps())
        self.assertEqual(svc.apply_to_vhost(once, self.apps()), once)
        block = once.split(svc.MARK_BEGIN)[1]
        self.assertLess(block.index('context /api/'), block.index('context / {'))
        self.assertIn('address                 127.0.0.1:20001', block)
        self.assertIn('websocket /ws {', block)
        self.assertLess(once.index(svc.MARK_END), once.index('vhssl'))
        self.assertEqual(once.count('{'), once.count('}'))

    def test_removing_last_app_restores_vhost(self):
        once = svc.apply_to_vhost(self.VHOST, self.apps())
        self.assertEqual(svc.apply_to_vhost(once, []), self.VHOST)

    def test_conflicts_with_hand_written_contexts(self):
        vhost = self.VHOST + '\ncontext /api/ {\n  location $DOC_ROOT/api/\n}\n'
        self.assertEqual(svc.vhost_conflicts(vhost, self.apps()), ['context /api/'])


class AccessControl(SimpleTestCase):
    def post(self, view, body, admin=0, owns=True, policy=None):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 7}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('loginSystem.models.Administrator.objects.get', return_value=object()), \
                mock.patch('universalAddons.access.ACLManager.checkOwnership', return_value=1 if owns else 0), \
                mock.patch('universalAddons.access.load_policy', return_value=dict(POLICY, **(policy or {}))), \
                mock.patch('universalAddons.apps.views.ACLManager.findAllSites', return_value=['shop.example.com']), \
                mock.patch('universalAddons.privileged.call', return_value={'ok': 1}) as call:
            response = view(request)
        return response.status_code, json.loads(response.content), call

    def test_users_blocked_until_admin_enables(self):
        status, body, call = self.post(views.apps, {})
        self.assertEqual(status, 403)
        call.assert_not_called()
        status, body, call = self.post(views.apps, {}, policy={'apps_for_users': True})
        self.assertEqual(status, 200)
        call.assert_called_once_with('apps', 'list', domains=['shop.example.com'])

    def test_admin_sees_everything(self):
        status, body, call = self.post(views.apps, {}, admin=1)
        call.assert_called_once_with('apps', 'list', domains=None)

    def test_user_cannot_touch_another_users_site(self):
        for view, body in ((views.save, {'domain': 'other.com', 'id': 'x'}),
                           (views.deploy, {'domain': 'other.com', 'app': 'api'}),
                           (views.delete, {'domain': 'other.com', 'app': 'api'}),
                           (views.logs, {'domain': 'other.com', 'app': 'api'})):
            status, body_, call = self.post(view, body, owns=False, policy={'apps_for_users': True})
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()

    def test_user_cannot_choose_app_directory(self):
        status, body, call = self.post(views.save, {'domain': 'shop.example.com', 'id': 'api', 'dir': '/home'},
                                       policy={'apps_for_users': True})
        self.assertEqual(status, 400)
        call.assert_not_called()

    def test_runtime_and_policy_endpoints_are_admin_only(self):
        for view in (views.runtimes, views.runtime_install, views.runtime_uninstall, views.policy):
            status, body, call = self.post(view, {'kind': 'node', 'version': '24.22.3'},
                                           policy={'apps_for_users': True})
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()

    def test_env_passed_as_dict(self):
        status, body, call = self.post(views.save, {'domain': 'shop.example.com', 'id': 'api', 'kind': 'node',
                                                    'env': [{'key': 'DB', 'value': 'a;b'}]}, admin=1)
        self.assertEqual(call.call_args[1]['spec']['env'], {'DB': 'a;b'})


class BasePath(SimpleTestCase):
    def app(self, **kw):
        app = svc.validate(spec(**kw), SITE, POLICY, {}, RUNTIMES)
        app['port'] = 20005
        return app

    def test_prefix_reaches_every_runtime(self):
        unit = svc.render_unit(self.app(kind='dotnet', runtime='10.0.15', entry='Shop.dll'), RUNTIMES['dotnet'][0])
        self.assertIn('Environment="APP_BASE_PATH=/api"', unit)
        self.assertIn('Environment="ASPNETCORE_FORWARDEDHEADERS_ENABLED=true"', unit)
        wsgi = svc.render_unit(self.app(kind='python', runtime='3.9.6', mode='wsgi', entry='app:app'), RUNTIMES['python'][0])
        self.assertIn('Environment="SCRIPT_NAME=/api"', wsgi)
        asgi = self.app(kind='python', runtime='3.9.6', mode='asgi', entry='main:app')
        self.assertEqual(svc.exec_argv(asgi, RUNTIMES['python'][0])[-3:], ['--root-path', '/api', 'main:app'])

    def test_site_root_has_no_prefix(self):
        root = self.app(prefix='/')
        self.assertIn('Environment="APP_BASE_PATH="', svc.render_unit(root, RUNTIMES['node'][0]))
        asgi = self.app(kind='python', runtime='3.9.6', mode='asgi', entry='main:app', prefix='/')
        self.assertNotIn('--root-path', svc.exec_argv(asgi, RUNTIMES['python'][0]))
        self.assertNotIn('SCRIPT_NAME', svc.render_unit(self.app(kind='python', runtime='3.9.6', mode='wsgi',
                                                                 entry='app:app', prefix='/'), RUNTIMES['python'][0]))

    def test_users_cannot_override_the_prefix(self):
        for key in ('APP_BASE_PATH', 'SCRIPT_NAME'):
            with self.assertRaises(svc.AppError):
                svc.validate_env({key: '/x'})


class ActionKeyword(SimpleTestCase):
    """start/stop/restart travel as an 'action' argument; it must not collide with the helper's own."""

    def test_control_passes_action_through(self):
        request = RequestFactory().post('/x', data=json.dumps({'domain': 'shop.example.com', 'app': 'api', 'action': 'restart'}),
                                        content_type='application/json')
        request.session = {'userID': 7}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1}), \
                mock.patch('loginSystem.models.Administrator.objects.get', return_value=object()), \
                mock.patch('universalAddons.privileged.ProcessUtilities', create=True), \
                mock.patch('plogical.processUtilities.ProcessUtilities.outputExecutioner',
                           return_value='@@UA-RESULT@@{"ok": true, "result": {"state": "active"}}') as run:
            response = views.control(request)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn(' apps control ', run.call_args[0][0])

    def test_privileged_call_accepts_action_keyword(self):
        from universalAddons import privileged
        seen = {}
        privileged.call('apps', 'control', executor=lambda cmd, *a, **k: seen.setdefault('cmd', cmd) and
                        '@@UA-RESULT@@{"ok": true, "result": 1}', action='stop', app_id='api', domain='shop.example.com')
        token = seen['cmd'].split()[-1]
        self.assertEqual(privileged.decode_args(token)['action'], 'stop')
