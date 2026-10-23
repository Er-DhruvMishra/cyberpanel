import json
import os
import shutil
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons.htaccess import service as hs, translator as tr, views
from universalAddons.htaccess.service import HtaccessError

VHOST = """docRoot                   $VH_ROOT/public_html

phpIniOverride  {

}

rewrite  {
 enable                  1
  autoLoadHtaccess        1
}

vhssl  {
  keyFile                 /etc/letsencrypt/live/example.com/privkey.pem
}
"""


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.home = os.path.join(self.root, 'home', 'example.com')
        self.docroot = os.path.join(self.home, 'public_html')
        os.makedirs(os.path.join(self.docroot, 'admin'))
        self.vhosts = os.path.join(self.root, 'vhosts')
        os.makedirs(os.path.join(self.vhosts, 'example.com'))
        self.vhost = os.path.join(self.vhosts, 'example.com', 'vhost.conf')
        with open(self.vhost, 'w') as handle:
            handle.write(VHOST)
        self.write('.htaccess', 'php_value upload_max_filesize 64M\nRedirect 301 /old /new\n'
                                '# BEGIN WordPress\nRewriteRule . /index.php [L]\n# END WordPress\n')
        self.write('admin/.htaccess', 'Require ip 10.0.0.0/8\n')

    def tearDown(self):
        shutil.rmtree(self.root)

    def write(self, rel, text):
        with open(os.path.join(self.docroot, rel), 'w') as handle:
            handle.write(text)

    def plan(self):
        return hs.plan('example.com', self.docroot, self.home, vhosts=self.vhosts)


class Collect(Fixture):
    def test_collect_limits_and_strips_managed_block(self):
        os.makedirs(os.path.join(self.docroot, 'node_modules', 'x'))
        with open(os.path.join(self.docroot, 'node_modules', 'x', '.htaccess'), 'w') as handle:
            handle.write('Header set X y\n')
        self.write('.htaccess', tr.apply_redirects('php_value a b\n', ['RewriteRule ^x$ /y [R=301,L]']))
        files = hs.collect(self.docroot)
        self.assertEqual(sorted(files), ['', 'admin'])
        self.assertNotIn('cp-ua redirects', files[''])
        self.assertEqual(hs.fingerprint(files), hs.fingerprint(hs.collect(self.docroot)))


class PlanAndApply(Fixture):
    def test_plan_is_side_effect_free(self):
        before = open(self.vhost).read()
        plan = self.plan()
        self.assertTrue(plan['changed'])
        self.assertEqual(open(self.vhost).read(), before)
        self.assertIn('context /admin/ {', plan['vhost_after'])
        self.assertTrue(plan['htaccess_after'].startswith(tr.HT_BEGIN))
        self.assertIn('# BEGIN WordPress', plan['htaccess_after'])

    def test_apply_success_then_idempotent(self):
        result = hs.apply_plans([self.plan()], backup_root=os.path.join(self.root, 'b'),
                                healthy=lambda d: (True, '200'), do_restart=lambda: True)
        self.assertEqual(result['applied'], ['example.com'])
        self.assertIn(tr.MARK_BEGIN, open(self.vhost).read())
        self.assertFalse(self.plan()['changed'], 'second plan has nothing to do')

    def test_failed_health_check_rolls_back(self):
        before_vhost = open(self.vhost).read()
        before_ht = open(os.path.join(self.docroot, '.htaccess')).read()
        restarts = []
        with self.assertRaisesRegex(HtaccessError, 'HTTP 503.*restored'):
            hs.apply_plans([self.plan()], backup_root=os.path.join(self.root, 'b'),
                           healthy=lambda d: (False, '503'), do_restart=lambda: restarts.append(1) or True)
        self.assertEqual(open(self.vhost).read(), before_vhost)
        self.assertEqual(open(os.path.join(self.docroot, '.htaccess')).read(), before_ht)
        self.assertEqual(len(restarts), 2, 'restart with new config, then again with the restored one')

    def test_failed_restart_rolls_back(self):
        before = open(self.vhost).read()
        with self.assertRaisesRegex(HtaccessError, 'did not come back'):
            hs.apply_plans([self.plan()], backup_root=os.path.join(self.root, 'b'),
                           healthy=lambda d: (True, '200'), do_restart=lambda: False)
        self.assertEqual(open(self.vhost).read(), before)

    def test_conflicting_blocks_are_skipped(self):
        with open(self.vhost, 'a') as handle:
            handle.write('\ncontext /admin/ {\n  location $DOC_ROOT/admin/\n}\n')
        plan = self.plan()
        self.assertEqual(plan['conflicts'], ['context /admin/'])
        self.assertEqual(plan['vhost_after'].count('context /admin/ {'), 1)

    def test_missing_vhost(self):
        with self.assertRaises(HtaccessError):
            hs.plan('other.com', self.docroot, self.home, vhosts=self.vhosts)


def log_line(ip, when, method='POST', path='/wp-login.php', status=200):
    return '%s - - [%s] "%s %s HTTP/1.1" %d 512 "-" "x"' % (ip, time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime(when)),
                                                           method, path, status)


class Guard(unittest.TestCase):
    def test_scan_counts_posts_in_window_and_honours_whitelist(self):
        now = 1_800_000_000
        lines = [log_line('198.51.100.7', now - 10) for _ in range(12)] + \
                [log_line('198.51.100.7', now - 4000)] + \
                [log_line('198.51.100.8', now - 5, method='GET') for _ in range(50)] + \
                [log_line('10.1.2.3', now - 5) for _ in range(50)] + \
                [log_line('203.0.113.4', now - 5, path='/xmlrpc.php') for _ in range(3)]
        config = {'attempts': 10, 'window': 300, 'whitelist': ['10.0.0.0/8'], 'paths': ['/wp-login.php', '/xmlrpc.php']}
        counts = hs.scan_log(lines, config, now)
        self.assertEqual(counts, {'198.51.100.7': 12, '203.0.113.4': 3})
        self.assertEqual(hs.offenders(counts, config), ['198.51.100.7'])

    def test_guard_blocks_once_and_records(self):
        now = 1_800_000_000
        directory = tempfile.mkdtemp()
        log = os.path.join(directory, 'access.log')
        with open(log, 'w') as handle:
            handle.write('\n'.join(log_line('198.51.100.7', now - 5) for _ in range(20)) + '\n')
        state = {'sites': {}, 'blocks': []}
        blocked = []
        config = {'example.com': {'enabled': True, 'attempts': 10, 'window': 300, 'action': 'block'}}
        events = hs.guard(config, state, now=now, log_path=lambda d: log,
                          blocker=lambda ip, s: blocked.append((ip, s)) or 'firewalld')
        self.assertEqual([(e['ip'], e['via']) for e in events], [('198.51.100.7', 'firewalld')])
        self.assertEqual(blocked, [('198.51.100.7', 3600)])
        self.assertEqual(hs.guard(config, state, now=now + 60, log_path=lambda d: log, blocker=lambda ip, s: 'x'), [],
                         'still blocked: no duplicate rule')
        log_only = hs.guard({'example.com': dict(config['example.com'], action='log')}, {'sites': {}, 'blocks': []},
                            now=now, log_path=lambda d: log, blocker=lambda ip, s: self.fail('log must not block'))
        self.assertNotIn('until', log_only[0])
        shutil.rmtree(directory)

    def test_block_ip_backends(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout='running\n' if argv[:2] == ['firewall-cmd', '--state'] else '')
        self.assertEqual(hs.block_ip('198.51.100.7', 3600, runner, which=lambda n: '/usr/bin/' + n), 'firewalld')
        self.assertIn(['firewall-cmd', '--add-rich-rule=rule family="ipv4" source address="198.51.100.7" reject',
                       '--timeout=3600'], calls)
        calls.clear()
        self.assertEqual(hs.block_ip('2001:db8::1', 60, runner, which=lambda n: '/usr/sbin/csf' if n == 'csf' else None),
                         'csf')
        self.assertEqual(calls[0][:4], ['csf', '-td', '2001:db8::1', '60'])
        with self.assertRaises(HtaccessError):
            hs.block_ip('198.51.100.7', 60, runner, which=lambda n: None)


class HtaccessViews(SimpleTestCase):
    def post(self, view, body, is_admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': is_admin}):
            response = view(request)
        return response.status_code, json.loads(response.content)

    def test_admin_only_and_validation(self):
        for name in ('overview', 'preview', 'enable', 'disable'):
            with mock.patch('universalAddons.privileged.call') as call:
                self.assertEqual(self.post(getattr(views, name), {'domain': 'a.com'}, is_admin=0)[0], 403)
            call.assert_not_called()
        with mock.patch('universalAddons.privileged.call') as call:
            self.assertEqual(self.post(views.enable, {'domain': '../etc'})[0], 400)
        call.assert_not_called()
