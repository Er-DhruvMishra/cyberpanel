import json
import os
import shutil
import tempfile
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import include, path

from universalAddons.limits import actions, service as sv, views

# The module is not in universalAddons/urls.py yet: give the page test its own URLconf.
from CyberCP.urls import urlpatterns as _project_urls  # noqa: E402

urlpatterns = [path('addons/limits/', include('universalAddons.limits.urls'))] + list(_project_urls)

USER = 'examp1234'
SITE = {'domain': 'example.com', 'user': USER, 'package': 'Default', 'state': 1}

# A real vhost.conf from the production server (CyberPanel 3.0.8, OpenLiteSpeed 1.9.4), with the
# domain and user replaced. Note the trailing spaces after keepDays and the whitespace-only line.
VHOST = """docRoot                   $VH_ROOT/public_html
vhDomain                  $VH_NAME
vhAliases                 www.$VH_NAME
adminEmails               info@example.com
enableGzip                1
enableIpGeo               1

index  {
  useServer               0
  indexFiles              index.php, index.html
}

errorlog $VH_ROOT/logs/$VH_NAME.error_log {
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}

accesslog $VH_ROOT/logs/$VH_NAME.access_log {
  useServer               0
  logFormat               "%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i""
  logHeaders              5
  rollingSize             10M
  keepDays                10  
  compressArchive         1
}

scripthandler  {
  add                     lsapi:examp1234 php
}

extprocessor examp1234 {
  type                    lsapi
  address                 UDS://tmp/lshttpd/examp1234.sock
  maxConns                10
  env                     LSAPI_CHILDREN=10
  initTimeout             600
  retryTimeout            0
  persistConn             1
  pcKeepAliveTimeout      1
  respBuffer              0
  autoStart               1
  path                    /usr/local/lsws/lsphp72/bin/lsphp
  extUser                 examp1234
  extGroup                examp1234
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           400
  procHardLimit           500
}

phpIniOverride  {
php_admin_value open_basedir "/tmp:$VH_ROOT"
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}

vhssl  {
  keyFile                 /etc/letsencrypt/live/example.com/privkey.pem
  certFile                /etc/letsencrypt/live/example.com/fullchain.pem
  certChain               1
  sslProtocol             24
  ciphers                 EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4
  enableECDHE             1
  renegProtection         1
  sslSessionCache         1
  enableSpdy              15
  enableStapling           1
  ocspRespMaxAge           86400
}
                    
context /.well-known/acme-challenge {
  location                /usr/local/lsws/Example/html/.well-known/acme-challenge
  allowBrowse             1

  rewrite  {
     enable                  0
  }
  addDefaultCharset       off
  phpIniOverride  {

  }
}
"""

EXTRA_APP = """
extprocessor cpapp_api {
  type                    proxy
  address                 127.0.0.1:20000
  maxConns                100
  initTimeout             60
  retryTimeout            0
}
"""

NEW = {'mem_soft_mb': 960, 'mem_hard_mb': 1088, 'proc_soft': 100, 'proc_hard': 150, 'max_conns': 4, 'children': 4}


def changed_lines(before, after):
    a, b = before.splitlines(), after.splitlines()
    return [(x, y) for x, y in zip(a, b) if x != y], len(a), len(b)


class Parsing(SimpleTestCase):
    def test_parse_live_fixture(self):
        current = sv.parse_extprocessor(VHOST, USER)
        self.assertEqual(current['type'], 'lsapi')
        self.assertEqual(current['ext_user'], USER)
        self.assertEqual(current['path'], '/usr/local/lsws/lsphp72/bin/lsphp')
        self.assertEqual(current['limits'], {'mem_soft_mb': 2047, 'mem_hard_mb': 2047, 'proc_soft': 400, 'proc_hard': 500,
                                             'max_conns': 10, 'children': 10, 'init_timeout': 600, 'retry_timeout': 0})

    def test_structural_blocks_ignore_inline_braces(self):
        kinds = [(b['kind'], b['name']) for b in sv.blocks(VHOST)]
        self.assertIn(('accesslog', '$VH_ROOT/logs/$VH_NAME.access_log'), kinds)  # logFormat holds "%{Referer}i"
        self.assertIn(('extprocessor', USER), kinds)
        self.assertIn(('vhssl', ''), kinds)
        self.assertTrue(sv.braces_balanced(VHOST))

    def test_unbalanced_and_missing_handler(self):
        for broken in (VHOST.replace('phpIniOverride  {\nphp_admin', 'phpIniOverride\nphp_admin', 1), VHOST + '}\n'):
            self.assertFalse(sv.braces_balanced(broken))
            with self.assertRaises(sv.LimitsError):
                sv.edit_extprocessor(broken, USER, NEW)
        with self.assertRaisesRegex(sv.LimitsError, 'no extprocessor other1234'):
            sv.parse_extprocessor(VHOST, 'other1234')
        duplicated = VHOST + VHOST[VHOST.index('extprocessor'):VHOST.index('phpIniOverride')]
        with self.assertRaisesRegex(sv.LimitsError, 'more than once'):
            sv.parse_extprocessor(duplicated, USER)

    def test_memory_units(self):
        self.assertEqual([sv.parse_mem_mb(v) for v in ('2047M', '2G', '524288K', '1073741824', 'lots')],
                         [2047, 2048, 512, 1024, None])


class Editing(SimpleTestCase):
    def test_only_target_keys_change(self):
        after = sv.edit_extprocessor(VHOST, USER, NEW)
        pairs, before_count, after_count = changed_lines(VHOST, after)
        self.assertEqual(before_count, after_count)
        self.assertEqual(sorted(y.split()[0] if not y.strip().startswith('env') else 'env' for x, y in pairs),
                         ['env', 'maxConns', 'memHardLimit', 'memSoftLimit', 'procHardLimit', 'procSoftLimit'])
        for x, y in pairs:  # indentation and column alignment kept
            self.assertEqual(len(x) - len(x.lstrip()), len(y) - len(y.lstrip()))
        self.assertIn('  memSoftLimit            960M\n', after)
        self.assertIn('  env                     LSAPI_CHILDREN=4\n', after)
        self.assertIn('  keepDays                10  \n', after)  # trailing spaces elsewhere preserved
        self.assertIn('\n                    \ncontext', after)
        original = sv.parse_extprocessor(VHOST, USER)['limits']
        self.assertEqual(sv.edit_extprocessor(after, USER, original), VHOST, 'round trip restores every byte')

    def test_other_extprocessors_untouched(self):
        text = VHOST + EXTRA_APP
        after = sv.edit_extprocessor(text, USER, NEW)
        self.assertTrue(after.endswith(EXTRA_APP))
        self.assertEqual(sv.parse_extprocessor(after, 'cpapp_api')['limits']['max_conns'], 100)

    def test_idempotent_and_noop(self):
        once = sv.edit_extprocessor(VHOST, USER, NEW)
        self.assertEqual(sv.edit_extprocessor(once, USER, NEW), once)
        current = sv.parse_extprocessor(VHOST, USER)['limits']
        self.assertEqual(sv.edit_extprocessor(VHOST, USER, current), VHOST)
        self.assertEqual(sv.edit_extprocessor(VHOST, USER, {}), VHOST)
        gig = VHOST.replace('memHardLimit            2047M', 'memHardLimit            2G')
        self.assertEqual(sv.edit_extprocessor(gig, USER, {'mem_hard_mb': 2048}), gig, 'same value in other units kept')

    def test_missing_keys_inserted_inside_block(self):
        after = sv.edit_extprocessor(VHOST, USER, {'instances': 1, 'priority': 5})
        block = sv.find_extprocessor(after, USER)
        lines = after.splitlines()
        self.assertEqual(lines[block['end'] - 2:block['end'] + 1],
                         ['  instances               1', '  priority                5', '}'])
        self.assertTrue(sv.braces_balanced(after))
        self.assertEqual(sv.parse_extprocessor(after, USER)['limits']['priority'], 5)
        no_env = VHOST.replace('  env                     LSAPI_CHILDREN=10\n', '')
        self.assertIn('  env                     LSAPI_CHILDREN=3\n}', sv.edit_extprocessor(no_env, USER, {'children': 3}))
        php_env = VHOST.replace('env                     LSAPI_CHILDREN=10', 'env                     PHP_LSAPI_CHILDREN=10')
        self.assertIn('PHP_LSAPI_CHILDREN=6', sv.edit_extprocessor(php_env, USER, {'children': 6}))

    def test_line_endings_and_missing_final_newline(self):
        crlf = VHOST.replace('\n', '\r\n')
        after = sv.edit_extprocessor(crlf, USER, dict(NEW, instances=1))
        self.assertNotIn('\n', after.replace('\r\n', ''))
        self.assertIn('  instances               1\r\n}', after)
        bare = VHOST.rstrip('\n')
        self.assertTrue(sv.edit_extprocessor(bare, USER, NEW).endswith('}'))
        self.assertFalse(sv.edit_extprocessor(bare, USER, NEW).endswith('\n'))

    def test_diff_shows_only_changes(self):
        diff = sv.unified_diff(VHOST, sv.edit_extprocessor(VHOST, USER, {'max_conns': 4, 'children': 4}), 'vhost.conf')
        self.assertEqual([l for l in diff.splitlines() if l[:1] in '+-' and not l.startswith(('+++', '---'))],
                         ['-  maxConns                10', '-  env                     LSAPI_CHILDREN=10',
                          '+  maxConns                4', '+  env                     LSAPI_CHILDREN=4'])


class Validation(SimpleTestCase):
    def test_bounds(self):
        self.assertEqual(sv.validate_limits({'mem_soft_mb': 256, 'mem_hard_mb': '512', 'proc_soft': 10, 'children': None,
                                             'priority': ''}), {'mem_soft_mb': 256, 'mem_hard_mb': 512, 'proc_soft': 10})
        bad = [({'mem_soft_mb': 255}, 'between 256'), ({'mem_hard_mb': 100}, 'between 256'), ({'proc_soft': 9}, 'between 10'),
               ({'proc_hard': 5}, 'between 10'), ({'max_conns': 0}, 'between 1'), ({'priority': -5}, 'between 0'),
               ({'children': True}, 'whole number'), ({'children': 2.5}, 'whole number'), ({'children': '4; rm'}, 'whole number'),
               ({'cpu_quota': 50}, 'Unknown'), ({'mem_soft_mb': 1024, 'mem_hard_mb': 512}, 'soft limit'),
               ({'proc_soft': 200, 'proc_hard': 100}, 'soft limit'), ({'max_conns': 8, 'children': 4}, 'workers'), ([], 'object')]
        for data, message in bad:
            with self.assertRaisesRegex(sv.LimitsError, message, msg=data):
                sv.validate_limits(data)

    def test_defaults_for_this_host_and_floors(self):
        self.assertEqual(sv.default_limits(3736, 2), {'mem_soft_mb': 960, 'mem_hard_mb': 1088, 'proc_soft': 100,
                                                      'proc_hard': 150, 'max_conns': 4, 'children': 4})
        for total, cores in ((256, 1), (512, 1), (65536, 64)):
            limits = sv.default_limits(total, cores)
            sv.validate_limits(limits)
            self.assertGreaterEqual(limits['mem_soft_mb'], 256)
            self.assertGreaterEqual(limits['proc_soft'], 10)
            self.assertLessEqual(limits['mem_hard_mb'], 2047)

    def test_store_format_and_layering(self):
        directory = tempfile.mkdtemp()
        try:
            target = os.path.join(directory, 'limits.json')
            store = sv.load_store(target)
            sv.set_profile(store, 'package', 'Default', {'children': 6, 'max_conns': 6})
            sv.set_profile(store, 'site', 'example.com', {'max_conns': 2})
            with self.assertRaises(sv.LimitsError):
                sv.set_profile(store, 'package', 'overrides', {'children': 2})
            sv.save_store(store, target)
            with open(target) as handle:
                self.assertEqual(json.load(handle), {'Default': {'max_conns': 6, 'children': 6},
                                                     'overrides': {'example.com': {'max_conns': 2}}})
            self.assertEqual(oct(os.stat(target).st_mode & 0o777), '0o600')
            again = sv.load_store(target)
            limits, source = sv.effective('Default', 'example.com', again, sv.default_limits(3736, 2))
            self.assertEqual((limits['max_conns'], limits['children'], limits['mem_hard_mb']), (2, 6, 1088))
            self.assertEqual((source['max_conns'], source['children'], source['mem_hard_mb']), ('site', 'package', 'default'))
            sv.set_profile(again, 'site', 'example.com', {})
            self.assertNotIn('example.com', again['overrides'])
        finally:
            shutil.rmtree(directory)


class Plans(SimpleTestCase):
    def setUp(self):
        self.vhosts = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.vhosts, 'example.com'))
        self.path = os.path.join(self.vhosts, 'example.com', 'vhost.conf')
        with open(self.path, 'w') as handle:
            handle.write(VHOST)

    def tearDown(self):
        shutil.rmtree(self.vhosts)

    def test_plan_and_warnings(self):
        plan = sv.plan_site(SITE, NEW, self.vhosts, usage={'vsz_max_kb': 626848, 'tasks': 3})
        self.assertTrue(plan['changed'])
        self.assertEqual(plan['error'], '')
        self.assertEqual(plan['warnings'], [])
        low = sv.plan_site(SITE, dict(NEW, mem_soft_mb=512, mem_hard_mb=512), self.vhosts, usage={'vsz_max_kb': 626848})
        self.assertIn('RLIMIT_AS', low['warnings'][0])
        busy = sv.plan_site(SITE, NEW, self.vhosts, usage={'tasks': 140})
        self.assertIn('140 tasks', busy['warnings'][0])
        # merged with what vhost.conf has (conns 10 > workers 4 would be inconsistent)
        self.assertIn('workers', sv.plan_site(SITE, {'children': 4}, self.vhosts)['error'])

    def test_plan_refuses_foreign_handlers(self):
        self.assertIn('no extprocessor', sv.plan_site(dict(SITE, user='other1234'), NEW, self.vhosts)['error'])
        with open(self.path, 'w') as handle:
            handle.write(VHOST.replace('extUser                 examp1234', 'extUser                 nobody'))
        self.assertIn('runs as nobody', sv.plan_site(SITE, NEW, self.vhosts)['error'])
        self.assertIn('No OpenLiteSpeed', sv.plan_site(dict(SITE, domain='missing.com'), NEW, self.vhosts)['error'])

    def run_apply(self, statuses, restart_ok=True):
        plan = sv.plan_site(SITE, NEW, self.vhosts)
        answers = iter(statuses)
        restarts = []
        backups = tempfile.mkdtemp()
        try:
            result = sv.apply_plans([plan], status_of=lambda domain: next(answers),
                                    do_restart=lambda: restarts.append(1) or restart_ok,
                                    backup_root=backups, sleep=lambda s: None)
        finally:
            shutil.rmtree(backups)
        return result, restarts

    def test_apply_success(self):
        result, restarts = self.run_apply([['https', '200'], ['https', '503'], ['https', '200']])
        self.assertEqual(result['applied'], ['example.com'])
        self.assertEqual(len(restarts), 1)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), sv.edit_extprocessor(VHOST, USER, NEW))

    def test_rollback_on_changed_status(self):
        with self.assertRaisesRegex(sv.LimitsError, 'answered https 503 instead of https 200.*restored'):
            self.run_apply([['https', '200']] + [['https', '503']] * 3)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), VHOST, 'byte-identical after rollback')

    def test_rollback_when_status_code_changes_even_without_5xx(self):
        with self.assertRaises(sv.LimitsError):
            self.run_apply([['https', '301']] + [['https', '200']] * 3)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), VHOST)

    def test_rollback_on_failed_restart(self):
        with self.assertRaisesRegex(sv.LimitsError, 'did not come back'):
            self.run_apply([['https', '200']], restart_ok=False)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), VHOST)

    def test_refuses_if_file_changed_since_preview(self):
        plan = sv.plan_site(SITE, NEW, self.vhosts)
        with open(self.path, 'a') as handle:
            handle.write('# edited by hand\n')
        restarts = []
        with self.assertRaisesRegex(sv.LimitsError, 'changed since the preview'):
            sv.apply_plans([plan], status_of=lambda d: ['https', '200'], do_restart=lambda: restarts.append(1))
        self.assertEqual(restarts, [])

    def test_token_tracks_content(self):
        plan = sv.plan_site(SITE, NEW, self.vhosts)
        other = sv.plan_site(SITE, dict(NEW, children=5, max_conns=5), self.vhosts)
        self.assertNotEqual(sv.plan_token([plan]), sv.plan_token([other]))
        self.assertNotIn('before', sv.public_plan(plan))

    def test_apply_action_checks_token(self):
        plan = sv.plan_site(SITE, NEW, self.vhosts)
        with mock.patch.object(actions, '_plans', return_value=[plan]), \
                mock.patch.object(actions.jobs, 'spawn', return_value={'job_id': 'x'}) as spawn:
            with self.assertRaisesRegex(sv.LimitsError, 'changed since the preview'):
                actions.apply('site', 'example.com', '0' * 32)
            spawn.assert_not_called()
            actions.apply('site', 'example.com', sv.plan_token([plan]))
            spawn.assert_called_once_with('limits', 'apply_run', {'scope': 'site', 'name': 'example.com',
                                                                  'token': sv.plan_token([plan])})

    def test_targets_skip_suspended_and_unknown(self):
        sites = [SITE, dict(SITE, domain='b.com', state=0), dict(SITE, domain='c.com', package='Other')]
        self.assertEqual([s['domain'] for s in actions._targets('package', 'Default', sites)], ['example.com'])
        for scope, name in (('site', 'nope.com'), ('package', 'Missing'), ('everything', 'x'), ('site', 'b.com')):
            with self.assertRaises(sv.LimitsError):
                actions._targets(scope, name, sites)


class Usage(SimpleTestCase):
    def test_proc_usage(self):
        proc = tempfile.mkdtemp()
        try:
            for pid, name, uid, rss, vsz, threads in (('10', 'lsphp', 5001, 46000, 626000, 1), ('11', 'lsphp', 5001, 30000, 600000, 1),
                                                      ('12', 'bash', 5001, 3000, 12000, 1), ('13', 'node', 5002, 50000, 900000, 11)):
                os.makedirs(os.path.join(proc, pid))
                with open(os.path.join(proc, pid, 'status'), 'w') as handle:
                    handle.write('Name:\t%s\nUid:\t%d\t%d\t%d\t%d\nVmSize:\t%d kB\nVmRSS:\t%d kB\nThreads:\t%d\n' % (
                        name, uid, uid, uid, uid, vsz, rss, threads))
            os.makedirs(os.path.join(proc, 'self'))
            usage = sv.proc_usage(proc)
            self.assertEqual(usage[5001], {'lsphp': 2, 'rss_kb': 76000, 'vsz_max_kb': 626000, 'tasks': 3})
            self.assertEqual(usage[5002], {'lsphp': 0, 'rss_kb': 0, 'vsz_max_kb': 0, 'tasks': 11})
            fake = mock.Mock(side_effect=lambda u: mock.Mock(pw_uid={'examp1234': 5001}[u]) if u == 'examp1234' else (_ for _ in ()).throw(KeyError(u)))
            self.assertEqual(sv.usage_by_user(['examp1234', 'gone'], proc, fake), {'examp1234': usage[5001]})
        finally:
            shutil.rmtree(proc)

    def test_quota_report_is_read_only(self):
        directory = tempfile.mkdtemp()
        try:
            mounts, fstab = os.path.join(directory, 'mounts'), os.path.join(directory, 'fstab')
            with open(mounts, 'w') as handle:
                handle.write('/dev/vda1 / ext4 rw,relatime,quota,usrquota,grpquota 0 0\nproc /proc proc rw,hidepid=2 0 0\n')
            with open(fstab, 'w') as handle:
                handle.write('# comment\nLABEL=root\t/\text4\tdefaults,usrquota,grpquota\t1 1\n')
            calls = []

            def runner(argv, **kwargs):
                calls.append(argv)
                if 'csv' in argv:
                    return mock.Mock(returncode=0, stdout='User,BlockStatus,FileStatus,BlockUsed,BlockSoftLimit,BlockHardLimit,'
                                     'BlockGrace,FileUsed,FileSoftLimit,FileHardLimit,FileGrace\nexamp1234,ok,ok,172356,0,'
                                     '1048576,,3189,0,0,\nbroken,row\n')
                return mock.Mock(returncode=0, stdout='user quota on / (/dev/vda1) is on\n')
            report = sv.quota_report(mounts, fstab, which=lambda b: '/usr/sbin/' + b, runner=runner)
            self.assertTrue(report['usrquota'] and report['grpquota'])
            self.assertEqual(report['fstab_options'], ['defaults', 'usrquota', 'grpquota'])
            self.assertEqual(report['users'], {'examp1234': {'kb': 172356, 'kb_soft': 0, 'kb_hard': 1048576, 'files': 3189,
                                                             'files_soft': 0, 'files_hard': 0}})
            self.assertEqual([c[0] for c in calls], ['/usr/sbin/repquota', '/usr/sbin/quotaon'])
            self.assertIn('-p', calls[1])  # print state only
            with open(mounts, 'w') as handle:
                handle.write('/dev/vda1 / ext4 rw,relatime 0 0\n')
            calls.clear()
            self.assertEqual(sv.quota_report(mounts, fstab, which=lambda b: None, runner=runner)['users'], {})
            self.assertEqual(calls, [])
        finally:
            shutil.rmtree(directory)

    def test_du_argv_and_parse(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return mock.Mock(returncode=0, stdout='123456\t/home/example.com\n')
        self.assertEqual(sv.du_kb('/home/example.com', runner), 123456)
        self.assertEqual(calls[0], ['nice', '-n', '19', 'ionice', '-c3', 'du', '-sk', '--one-file-system', '/home/example.com'])
        with self.assertRaises(sv.LimitsError):
            sv.du_kb('/home/x', lambda argv, **kw: mock.Mock(returncode=1, stdout='du: cannot access\n'))

    def test_cgroup_facts(self):
        self.assertFalse(sv.cgroup_facts(exists=lambda p: False)['cgroup_v2'])


class AccessControl(SimpleTestCase):
    def post(self, view, body, admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'job_id': 'j'}) as call:
            response = view(request)
        return response.status_code, call

    def test_admin_only(self):
        for view in (views.overview, views.save, views.preview, views.apply, views.du_scan, views.job):
            status, call = self.post(view, {'scope': 'site', 'name': 'example.com', 'token': 'a' * 32, 'job': 'b' * 24}, admin=0)
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()
        request = RequestFactory().post('/x', data='{}', content_type='application/json')
        request.session = {}
        self.assertEqual(views.overview(request).status_code, 401)

    def test_input_validation(self):
        bad = [(views.save, {'scope': 'server', 'name': 'x'}), (views.save, {'scope': 'site', 'name': 'not a domain'}),
               (views.save, {'scope': 'package', 'name': 'overrides', 'limits': {}}),
               (views.save, {'scope': 'package', 'name': 'a/b', 'limits': {}}),
               (views.save, {'scope': 'site', 'name': 'example.com', 'limits': {'mem_hard_mb': 128}}),
               (views.save, {'scope': 'site', 'name': 'example.com', 'limits': {'proc_hard': 3}}),
               (views.save, {'scope': 'site', 'name': 'example.com', 'limits': 'mem=1'}),
               (views.preview, {'scope': 'site', 'name': ['example.com']}),
               (views.apply, {'scope': 'site', 'name': 'example.com', 'token': 'xyz'}),
               (views.job, {'job': '../../etc/passwd'})]
        for view, body in bad:
            status, call = self.post(view, body)
            self.assertEqual(status, 400, body)
            call.assert_not_called()

    def test_calls_pass_through(self):
        status, call = self.post(views.save, {'scope': 'package', 'name': 'zennit_full', 'limits': {'children': '4', 'max_conns': 4}})
        self.assertEqual(status, 200)
        call.assert_called_once_with('limits', 'save', scope='package', name='zennit_full', limits={'children': 4, 'max_conns': 4})
        status, call = self.post(views.preview, {'scope': 'site', 'name': 'Example.COM'})
        call.assert_called_once_with('limits', 'preview', scope='site', name='example.com')
        status, call = self.post(views.apply, {'scope': 'site', 'name': 'example.com', 'token': 'a' * 32})
        call.assert_called_once_with('limits', 'apply', scope='site', name='example.com', token='a' * 32)
        status, call = self.post(views.du_scan, {})
        call.assert_called_once_with('limits', 'du_scan')


@override_settings(ROOT_URLCONF=__name__)
class PageRenders(SimpleTestCase):
    def test_page_renders(self):
        request = RequestFactory().get('/addons/limits/')
        request.session = {}
        html = render_to_string('universalAddons/limits.html', {'request': request, 'admin': 1})
        self.assertIn('ua-wrap', html)
        self.assertIn('data-base="/addons/limits/"', html)
        self.assertIn('limits.js', html)
