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
        self.assertEqual(svc.validate_env({'JwtSettings__SecretKey': ''}), {'JwtSettings__SecretKey': ''})
        for bad in ({'PORT': '1'}, {'LD_PRELOAD': '/x.so'}, {'ld_preload': '/x.so'}, {'1BAD': 'x'}, {'A-B': 'x'},
                    {'A': 'line\nbreak'}):
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


class SystemNode(SimpleTestCase):
    def test_system_node_detected_with_npm_and_eol_flag(self):
        from types import SimpleNamespace
        from universalAddons.apps import runtimes as rt
        runner = lambda argv, **k: SimpleNamespace(returncode=0, stdout='v16.13.1\n')
        with mock.patch('universalAddons.apps.runtimes.os.path.exists', return_value=True), \
                mock.patch('universalAddons.apps.runtimes.os.path.realpath', side_effect=lambda p: p):
            found = rt.system_nodes(('/usr/bin/node',), runner=runner)
        self.assertEqual(found[0]['version'], '16.13.1')
        self.assertEqual(found[0]['npm'], '/usr/bin/npm')
        self.assertTrue(found[0]['eol'])
        self.assertIn('end-of-life', found[0]['label'])


# ----------------------------------------------------------------------------- Java

JAVA8 = {'version': '8.0.312', 'path': '/usr/bin/java', 'source': 'system'}
JAVA21 = {'version': '21.0.13', 'path': '/opt/cp-runtimes/java/21.0.13/bin/java', 'source': 'Temurin'}
JAVA_RUNTIMES = dict(RUNTIMES, java=[JAVA8, JAVA21])
RUNNER_JAR = '/opt/cp-runtimes/java-tools/webapp-runner-9.0.123.0.jar'


def java_spec(**kw):
    base = {'id': 'shop', 'kind': 'java', 'runtime': '21.0.13', 'entry': 'shop.jar', 'prefix': '/', 'memory_mb': 512}
    base.update(kw)
    return base


def java_app(**kw):
    app = svc.validate(java_spec(**kw), SITE, POLICY, {}, JAVA_RUNTIMES)
    app['port'] = 20007
    return app


class JavaValidation(SimpleTestCase):
    def test_defaults(self):
        app = svc.validate(java_spec(entry=None), SITE, POLICY, {}, JAVA_RUNTIMES)
        self.assertEqual((app['mode'], app['entry'], app['jvm_opts']), ('jar', 'app.jar', []))
        war = svc.validate(java_spec(mode='war', entry=None), SITE, POLICY, {}, JAVA_RUNTIMES)
        self.assertEqual(war['entry'], 'app.war')

    def test_entry_and_mode(self):
        cases = [(java_spec(entry='shop.war'), r'\.jar'), (java_spec(mode='war', entry='shop.jar'), r'\.war'),
                 (java_spec(mode='ear', entry='x.ear'), 'JAR or a WAR'), (java_spec(entry='../x.jar'), 'relative'),
                 (java_spec(entry='/home/x/shop.jar'), 'relative'), (java_spec(entry='a b.jar'), 'relative'),
                 (java_spec(runtime='11.0.2'), 'not installed')]
        for bad, message in cases:
            with self.assertRaisesRegex(svc.AppError, message, msg=bad):
                svc.validate(bad, SITE, POLICY, {}, JAVA_RUNTIMES)
        self.assertEqual(svc.validate(java_spec(entry='target/shop-1.0.0.jar'), SITE, POLICY, {}, JAVA_RUNTIMES)['entry'],
                         'target/shop-1.0.0.jar')

    def test_jvm_options_accepted(self):
        good = '-Xss512k -Xmx300m -Xlog:gc -XX:+UseG1GC -XX:-UseCompressedOops -XX:MaxRAMPercentage=70.0 ' \
               '-Dspring.profiles.active=prod -Duser.timezone=Europe/Berlin -Dfile.encoding=UTF-8 -Dempty='
        self.assertEqual(svc.validate_jvm_opts(good), good.split())
        self.assertEqual(svc.validate_jvm_opts(['-Xss1m']), ['-Xss1m'])
        self.assertEqual(svc.validate_jvm_opts(''), [])

    def test_jvm_options_refused(self):
        for bad in ('-Dx=1;rm', ['-Dx=a b'], '-Dx=a b', '-Dx=$HOME', '-Dx=%n', '-Dx=`id`', '-javaagent:/x.jar',
                    '-agentlib:jdwp=transport=dt_socket', '-agentpath:/x.so', '-Xrunjdwp:transport=dt_socket',
                    '-Xbootclasspath/a:/x.jar', '-Xdebug', '-XX:OnOutOfMemoryError=/home/x/run.sh',
                    '-XX:OnError=/bin/sh', '-XX:Flags=/x', '-XX:VMOptionsFile=/x', '-cp', '/x.jar',
                    '-Dserver.port=80', '-Dserver.address=0.0.0.0', '-DSERVER.PORT=80',
                    '-Dserver.servlet.context-path=/x', '-jar', ' '.join(['-Xss1m'] * 11), {'a': 1}):
            with self.assertRaises(svc.AppError, msg=bad):
                svc.validate_jvm_opts(bad)

    def test_java_overrides_through_env_refused(self):
        for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'SERVER_PORT', 'SERVER_ADDRESS',
                    'SERVER_SERVLET_CONTEXT_PATH'):
            with self.assertRaises(svc.AppError, msg=key):
                svc.validate_env({key: '-javaagent:/x.jar'})

    def test_options_kept_on_edit_when_not_sent(self):
        current = dict(java_app(jvm_opts=['-Xss1m']))
        again = svc.validate({k: v for k, v in java_spec().items()}, SITE, POLICY, {'shop': current}, JAVA_RUNTIMES)
        self.assertEqual(again['jvm_opts'], ['-Xss1m'])


class JavaUnits(SimpleTestCase):
    def test_normal_jvm_stop_is_not_a_failure(self):
        unit = svc.render_unit(java_app(), JAVA8, 239, False)
        service = unit.split('[Install]')[0]
        self.assertIn('SuccessExitStatus=143', service.splitlines())

    def test_jar_command(self):
        self.assertEqual(svc.exec_argv(java_app(), JAVA21),
                         ['/opt/cp-runtimes/java/21.0.13/bin/java', '-Xmx384m', '-XX:+UseSerialGC', '-Djava.io.tmpdir=/tmp',
                          '-jar', '/home/shop.example.com/apps/shop/shop.jar'])

    def test_user_options_replace_heap_and_gc_defaults(self):
        argv = svc.exec_argv(java_app(jvm_opts=['-Xmx200m', '-XX:+UseG1GC', '-Dspring.profiles.active=prod']), JAVA8)
        self.assertEqual(argv, ['/usr/bin/java', '-Djava.io.tmpdir=/tmp', '-Xmx200m', '-XX:+UseG1GC',
                                '-Dspring.profiles.active=prod', '-jar', '/home/shop.example.com/apps/shop/shop.jar'])

    def test_war_command_at_root_and_under_prefix(self):
        root = svc.exec_argv(java_app(mode='war', entry='shop.war'), JAVA8)
        self.assertEqual(root, ['/usr/bin/java', '-Xmx384m', '-XX:+UseSerialGC', '-Djava.io.tmpdir=/tmp', '-jar', RUNNER_JAR,
                                '--port', '20007', '-Aaddress=127.0.0.1', '--temp-directory', '/tmp/webapp-runner',
                                '/home/shop.example.com/apps/shop/shop.war'])
        sub = svc.exec_argv(java_app(mode='war', entry='shop.war', prefix='/store'), JAVA8)
        self.assertEqual(sub[-3:], ['--path', '/store', '/home/shop.example.com/apps/shop/shop.war'])

    def test_jar_unit_environment(self):
        unit = svc.render_unit(java_app(prefix='/store'), JAVA21, 239, False).splitlines()
        for line in ('Environment="SERVER_PORT=20007"', 'Environment="SERVER_ADDRESS=127.0.0.1"',
                     'Environment="PORT=20007"', 'Environment="HOST=127.0.0.1"', 'Environment="APP_BASE_PATH=/store"',
                     'Environment="SERVER_SERVLET_CONTEXT_PATH=/store"', 'User=shop1234', 'ProtectSystem=strict',
                     'PrivateTmp=yes', 'ReadWritePaths=/home/shop.example.com/apps/shop', 'MemoryLimit=512M', 'TasksMax=512',
                     'ExecStart=/opt/cp-runtimes/java/21.0.13/bin/java -Xmx384m -XX:+UseSerialGC -Djava.io.tmpdir=/tmp '
                     '-jar /home/shop.example.com/apps/shop/shop.jar'):
            self.assertIn(line, unit)

    def test_context_path_only_for_a_sub_path(self):
        unit = svc.render_unit(java_app(), JAVA21, 252, True)
        self.assertNotIn('SERVER_SERVLET_CONTEXT_PATH', unit)
        self.assertIn('MemoryMax=512M', unit.splitlines())
        war = svc.render_unit(java_app(mode='war', entry='shop.war', prefix='/store'), JAVA8)
        self.assertNotIn('SERVER_', war, 'Spring Boot variables are for executable jars')
        self.assertIn('ExecStart=/usr/bin/java -Xmx384m -XX:+UseSerialGC -Djava.io.tmpdir=/tmp -jar %s --port 20007 '
                      '-Aaddress=127.0.0.1 --temp-directory /tmp/webapp-runner --path /store '
                      '/home/shop.example.com/apps/shop/shop.war' % RUNNER_JAR, war.splitlines())

    def test_systemd_prefixes_cannot_reach_execstart(self):
        for path in ('+/usr/bin/java', '!/usr/bin/java', 'java'):
            with self.assertRaisesRegex(svc.AppError, 'Unsafe', msg=path):
                svc.render_unit(java_app(), dict(JAVA8, path=path))
        app = java_app()
        app['jvm_opts'] = ['-Dx=$(id)']  # a record edited behind validate()'s back
        with self.assertRaisesRegex(svc.AppError, 'Unsafe'):
            svc.render_unit(app, JAVA8)


class JavaDeploy(SimpleTestCase):
    def setUp(self):
        import tempfile
        self.home = tempfile.mkdtemp()
        self.app = dict(java_app(), dir=self.home, user='shop1234')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.home)

    def test_missing_entry(self):
        with self.assertRaisesRegex(svc.AppError, 'shop.jar was not found'):
            svc.install_dependencies(self.app, JAVA21, runner=lambda *a, **k: self.fail('nothing to run'))

    def test_entry_must_be_readable_by_the_site_user(self):
        from types import SimpleNamespace
        import os
        with open(os.path.join(self.home, 'shop.jar'), 'wb') as handle:
            handle.write(b'PK')
        calls = []

        def runner(argv, **kw):
            calls.append(argv)
            return SimpleNamespace(returncode=self.code, stdout='')
        self.code = 1
        with self.assertRaisesRegex(svc.AppError, 'not readable by shop1234'):
            svc.install_dependencies(self.app, JAVA21, runner=runner)
        self.code = 0
        self.assertTrue(svc.install_dependencies(self.app, JAVA21, runner=runner))
        self.assertEqual(calls[-1], ['sudo', '-u', 'shop1234', '--', 'test', '-r', os.path.join(self.home, 'shop.jar')])

    def test_admin_can_install_java_runtimes(self):
        status, body, call = AccessControl.post(self, views.runtime_install, {'kind': 'java', 'version': '21.0.13'}, admin=1)
        self.assertEqual(status, 200)
        call.assert_called_once_with('apps', 'runtime_install', kind='java', version='21.0.13')
        status, body, call = AccessControl.post(self, views.save, {'domain': 'shop.example.com', 'id': 'shop', 'kind': 'java',
                                                                   'mode': 'war', 'jvm_opts': ['-Xss1m']}, admin=1)
        self.assertEqual(call.call_args[1]['spec']['jvm_opts'], ['-Xss1m'])


JAVA8_OUT = ('openjdk version "1.8.0_312"\nOpenJDK Runtime Environment (build 1.8.0_312-b07)\n'
             'OpenJDK 64-Bit Server VM (build 25.312-b07, mixed mode)\n')
JAVA21_OUT = ('openjdk version "21.0.13" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-21.0.13+9 (build 21.0.13+9-LTS)\n'
              'OpenJDK 64-Bit Server VM Temurin-21.0.13+9 (build 21.0.13+9-LTS, mixed mode, sharing)\n')
ADOPTIUM_21 = [{
    'binary': {'architecture': 'x64', 'heap_size': 'normal', 'image_type': 'jre', 'jvm_impl': 'hotspot', 'os': 'linux',
               'package': {'checksum': 'a535a1df9c6284d9618872984e026ae0352d1f7e9e0605425c0e6114f47351dd',
                           'link': 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/'
                                   'OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz',
                           'name': 'OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz', 'size': 52181297}},
    'release_name': 'jdk-21.0.13+9', 'vendor': 'eclipse',
    'version': {'build': 9, 'major': 21, 'minor': 0, 'openjdk_version': '21.0.13+9-LTS', 'security': 13}}]


class JavaRuntimes(SimpleTestCase):
    def test_parse_java_version(self):
        from universalAddons.apps import runtimes as rt
        self.assertEqual(rt.parse_java_version(JAVA8_OUT), {'feature': 8, 'version': '8.0.312', 'java_version': '1.8.0_312',
                                                            'vendor': 'OpenJDK'})
        self.assertEqual(rt.parse_java_version(JAVA21_OUT), {'feature': 21, 'version': '21.0.13', 'java_version': '21.0.13',
                                                             'vendor': 'Temurin'})
        self.assertEqual(rt.parse_java_version('Picked up JAVA_TOOL_OPTIONS: -Xss1m\nopenjdk version "25" 2025-09-16 LTS\n')
                         ['version'], '25.0.0')
        self.assertEqual(rt.parse_java_version('java version "1.8.0_202"\nJava(TM) SE Runtime Environment')['vendor'], 'Java')
        self.assertIsNone(rt.parse_java_version('bash: java: command not found'))

    def test_system_java_detected_once_per_binary(self):
        from types import SimpleNamespace
        from universalAddons.apps import runtimes as rt
        seen = []

        def runner(argv, **kw):
            seen.append(argv)
            self.assertEqual(kw.get('stderr'), __import__('subprocess').STDOUT, 'java -version prints to stderr')
            return SimpleNamespace(returncode=0, stdout=JAVA8_OUT)
        real = '/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.312.b07-2.el8_5.x86_64/jre/bin/java'
        with mock.patch('universalAddons.apps.runtimes.os.path.exists', return_value=True), \
                mock.patch('glob.glob', return_value=['/usr/lib/jvm/jre-1.8.0/bin/java', '/usr/lib/jvm/jre/bin/java']), \
                mock.patch('universalAddons.apps.runtimes.os.path.realpath', return_value=real):
            found = rt.system_javas(runner=runner)
        self.assertEqual(len(found), 1)
        self.assertEqual(seen, [['/usr/bin/java', '-version']])
        self.assertEqual((found[0]['version'], found[0]['path'], found[0]['source'], found[0]['label']),
                         ('8.0.312', '/usr/bin/java', 'system', 'Java 8 (system, OpenJDK 1.8.0_312)'))

    def test_adoptium_catalogue(self):
        from universalAddons.apps import runtimes as rt
        entry = rt.java_catalogue(ADOPTIUM_21, 'x64')[0]
        self.assertEqual((entry['version'], entry['feature'], entry['sha256'][:8], entry['label']),
                         ('21.0.13', 21, 'a535a1df', 'Java 21 (Temurin JRE 21.0.13+9-LTS)'))
        self.assertEqual(rt.java_catalogue(ADOPTIUM_21, 'arm64'), [])
        jdk = json.loads(json.dumps(ADOPTIUM_21))
        jdk[0]['binary']['image_type'] = 'jdk'
        self.assertEqual(rt.java_catalogue(jdk), [])
        no_sum = json.loads(json.dumps(ADOPTIUM_21))
        no_sum[0]['binary']['package']['checksum'] = ''
        self.assertEqual(rt.java_catalogue(no_sum), [])
        self.assertEqual(rt.java_features({'available_lts_releases': [8, 11, 17, 21, 25]}), [25, 21, 17])

    def test_catalogue_queries_each_lts_feature(self):
        from universalAddons.apps import runtimes as rt
        urls = []

        def fetcher(url):
            urls.append(url)
            if 'available_releases' in url:
                return json.dumps({'available_lts_releases': [8, 11, 17, 21]}).encode()
            if 'adoptium' in url:
                return json.dumps(ADOPTIUM_21 if '/21/' in url else []).encode()
            raise OSError('offline')
        with mock.patch('universalAddons.apps.runtimes.arch', return_value='x64'):
            cat = rt.catalogue(fetcher)
        self.assertEqual([e['version'] for e in cat['java']], ['21.0.13'])
        self.assertNotIn('java', cat['errors'])
        self.assertIn('/assets/latest/17/hotspot?architecture=x64&image_type=jre&os=linux&vendor=eclipse', ' '.join(urls))


class JavaInstall(SimpleTestCase):
    def setUp(self):
        import tempfile
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root)

    @staticmethod
    def tarball(entries):
        import io
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as bundle:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o755
                bundle.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    def install(self, data, checksum):
        from types import SimpleNamespace
        from universalAddons.apps import runtimes as rt
        assets = json.loads(json.dumps(ADOPTIUM_21))
        assets[0]['binary']['package']['checksum'] = checksum
        ran = []

        def fetch_file(url, target):
            self.assertTrue(url.startswith('https://github.com/adoptium/'))
            with open(target, 'wb') as handle:
                handle.write(data)

        def runner(argv, **kw):
            ran.append(argv)
            return SimpleNamespace(returncode=0, stdout=JAVA21_OUT if argv[-1] == '-version' else '')
        with mock.patch('universalAddons.apps.runtimes.arch', return_value='x64'), \
                mock.patch('universalAddons.apps.runtimes.system_javas', return_value=[]):
            return rt.install('java', '21.0.13', self.root, fetcher=lambda url: json.dumps(assets).encode(),
                              fetch_file=fetch_file, runner=runner), ran

    def test_install_verifies_extracts_and_smoke_tests(self):
        import hashlib
        import os
        data = self.tarball([('jdk-21.0.13+9-jre/bin/java', b'#!/bin/sh\n'), ('jdk-21.0.13+9-jre/man/man1/java.1', b'x'),
                             ('jdk-21.0.13+9-jre/legal/java.base/LICENSE', b'GPLv2+CPE')])
        entry, ran = self.install(data, hashlib.sha256(data).hexdigest())
        self.assertEqual((entry['version'], entry['path']), ('21.0.13', os.path.join(self.root, 'java', '21.0.13', 'bin', 'java')))
        self.assertEqual(ran[0][-1], '-version')
        self.assertTrue(ran[0][0].endswith('/tree/bin/java'), 'smoke test runs the staged binary')
        self.assertFalse(os.path.exists(os.path.join(self.root, 'java', '21.0.13', 'man')))
        self.assertTrue(os.path.exists(os.path.join(self.root, 'java', '21.0.13', 'legal', 'java.base', 'LICENSE')))

    def test_checksum_mismatch_refused(self):
        import os
        from universalAddons.apps import runtimes as rt
        data = self.tarball([('jdk-21.0.13+9-jre/bin/java', b'#!/bin/sh\n')])
        with self.assertRaisesRegex(rt.RuntimeError_, 'Checksum mismatch'):
            self.install(data, '0' * 64)
        self.assertFalse(os.path.exists(os.path.join(self.root, 'java')))
        self.assertEqual([n for n in os.listdir(self.root) if n.startswith('cp-runtime-')], [])

    def test_outdated_version_refused(self):
        from universalAddons.apps import runtimes as rt
        with mock.patch('universalAddons.apps.runtimes.arch', return_value='x64'), \
                self.assertRaisesRegex(rt.RuntimeError_, 'refresh the list'):
            rt.install('java', '21.0.12', self.root, fetcher=lambda url: json.dumps(ADOPTIUM_21).encode())


class WebappRunner(SimpleTestCase):
    def setUp(self):
        import tempfile
        self.root = tempfile.mkdtemp()
        self.jar = b'PK\x03\x04 pretend webapp-runner'

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root)

    def ensure(self, sha1=None, pinned=None):
        import hashlib
        from universalAddons.apps import runtimes as rt
        urls = []

        def fetcher(url):
            urls.append(url)
            return ((sha1 or hashlib.sha1(self.jar).hexdigest()) + '\n').encode()

        def fetch_file(url, target):
            urls.append(url)
            with open(target, 'wb') as handle:
                handle.write(self.jar)
        with mock.patch.object(rt, 'WEBAPP_RUNNER_SHA256', pinned or hashlib.sha256(self.jar).hexdigest()):
            return rt.ensure_webapp_runner(self.root, fetcher=fetcher, fetch_file=fetch_file), urls

    def test_pinned_version(self):
        from universalAddons.apps import runtimes as rt
        self.assertEqual(rt.webapp_runner_path(), RUNNER_JAR)
        self.assertRegex(rt.WEBAPP_RUNNER_SHA256, r'^[0-9a-f]{64}$')

    def test_download_verified_once(self):
        import os
        path, urls = self.ensure()
        self.assertEqual(path, os.path.join(self.root, 'java-tools', 'webapp-runner-9.0.123.0.jar'))
        self.assertEqual(urls, ['https://repo1.maven.org/maven2/com/heroku/webapp-runner/9.0.123.0/webapp-runner-9.0.123.0.jar.sha1',
                                'https://repo1.maven.org/maven2/com/heroku/webapp-runner/9.0.123.0/webapp-runner-9.0.123.0.jar'])
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o644')
        self.assertEqual(self.ensure()[1], [], 'already present and matching: no download')

    def test_sha1_mismatch_refused(self):
        import os
        from universalAddons.apps import runtimes as rt
        with self.assertRaisesRegex(rt.RuntimeError_, 'Checksum mismatch'):
            self.ensure(sha1='0' * 40)
        self.assertEqual(os.listdir(os.path.join(self.root, 'java-tools')), [])

    def test_pinned_sha256_mismatch_refused(self):
        import os
        from universalAddons.apps import runtimes as rt
        with self.assertRaisesRegex(rt.RuntimeError_, 'pinned SHA-256'):
            self.ensure(pinned='1' * 64)
        self.assertEqual(os.listdir(os.path.join(self.root, 'java-tools')), [])
