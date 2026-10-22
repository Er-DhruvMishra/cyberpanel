import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from universalAddons import jobs
from universalAddons.rspamd import service as rs
from universalAddons.rspamd.service import RspamdError


class FakeRunner:
    """Scripted subprocess.run: maps argv prefixes to (returncode, output) and records calls."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        for prefix, (code, out) in self.responses.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return SimpleNamespace(returncode=code, stdout=out)
        return SimpleNamespace(returncode=0, stdout='')


class Milters(unittest.TestCase):
    def test_enable_appends_after_opendkim_once(self):
        self.assertEqual(rs.plan_milters('inet:127.0.0.1:8891', True), ['inet:127.0.0.1:8891', rs.RSPAMD_MILTER])
        self.assertEqual(rs.plan_milters('inet:127.0.0.1:8891, inet:localhost:11332', True),
                         ['inet:127.0.0.1:8891', rs.RSPAMD_MILTER])

    def test_disable_removes_every_rspamd_form(self):
        self.assertEqual(rs.plan_milters('inet:127.0.0.1:8891 inet:localhost:11332 inet:[::1]:11332', False),
                         ['inet:127.0.0.1:8891'])

    def test_postfix_plan_sets_accept_on_enable_and_follows_smtpd(self):
        plan = rs.postfix_plan({'smtpd_milters': 'inet:127.0.0.1:8891', 'non_smtpd_milters': '$smtpd_milters',
                                'milter_default_action': 'tempfail'}, True)
        self.assertEqual(plan['smtpd_milters'], 'inet:127.0.0.1:8891 ' + rs.RSPAMD_MILTER)
        self.assertEqual(plan['milter_default_action'], 'accept')
        self.assertNotIn('non_smtpd_milters', plan)
        plan = rs.postfix_plan({'smtpd_milters': 'inet:127.0.0.1:8891 ' + rs.RSPAMD_MILTER,
                                'non_smtpd_milters': 'inet:127.0.0.1:8891 ' + rs.RSPAMD_MILTER}, False)
        self.assertEqual(plan, {'smtpd_milters': 'inet:127.0.0.1:8891', 'non_smtpd_milters': 'inet:127.0.0.1:8891'})

    def test_read_postconf(self):
        runner = FakeRunner({('postconf',): (0, 'smtpd_milters = inet:127.0.0.1:8891\ncontent_filter =\n')})
        self.assertEqual(rs.read_postconf(['smtpd_milters', 'content_filter'], runner),
                         {'smtpd_milters': 'inet:127.0.0.1:8891', 'content_filter': ''})


class Settings(unittest.TestCase):
    def test_defaults_valid(self):
        self.assertEqual(rs.validate_settings({}), rs.DEFAULT_SETTINGS)

    def test_threshold_order_and_types(self):
        with self.assertRaisesRegex(RspamdError, 'greylist < add header < reject'):
            rs.validate_settings({'reject': 5, 'add_header': 6})
        with self.assertRaises(RspamdError):
            rs.validate_settings({'reject': 'lots'})
        with self.assertRaises(RspamdError):
            rs.validate_settings({'greylisting': 'yes'})

    def test_lists_validated_and_normalised(self):
        s = rs.validate_settings({'allow_list': 'Partner.com boss@Example.com\n*.trusted.org',
                                  'deny_list': ['spam@bad.net']})
        self.assertEqual(s['allow_list'], ['*.trusted.org', 'boss@example.com', 'partner.com'])
        for bad in ('x";\ninclude "/etc/shadow', 'not an address', '../../etc', 'a@b'):
            with self.assertRaises(RspamdError, msg=bad):
                rs.validate_settings({'deny_list': [bad]})
        with self.assertRaisesRegex(RspamdError, 'both lists'):
            rs.validate_settings({'allow_list': ['a.com'], 'deny_list': ['a.com']})

    def test_render_files(self):
        files = rs.render_files({'allow_list': ['ok@a.com', 'b.com'], 'dkim_signing': True})
        self.assertIn('reject = 15.0;', files['/etc/rspamd/local.d/actions.conf'])
        self.assertEqual(files['/etc/rspamd/local.d/maps/ua_allow_from.map'], 'ok@a.com\n')
        self.assertEqual(files['/etc/rspamd/local.d/maps/ua_allow_from_domain.map'], 'b.com\n')
        self.assertIn('enabled = true;', files['/etc/rspamd/local.d/dkim_signing.conf'])
        self.assertIn('bind_socket = "127.0.0.1:11332"', files['/etc/rspamd/local.d/worker-proxy.inc'])
        self.assertIn('127.0.0.1:11334', files['/etc/rspamd/local.d/worker-controller.inc'])
        for path, content in files.items():
            if path.endswith(('.conf', '.inc')):
                self.assertTrue(content.startswith(rs.MANAGED_HEADER), path)


class ApplyAndRollback(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.local_d = os.path.join(self.root, 'local.d')
        os.makedirs(self.local_d)
        patches = [mock.patch.object(rs, 'LOCAL_D', self.local_d),
                   mock.patch.object(rs, 'MAPS_DIR', os.path.join(self.local_d, 'maps'))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        with open(os.path.join(self.local_d, 'actions.conf'), 'w') as handle:
            handle.write('reject = 99;\n')

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_configtest_failure_restores_previous_files(self):
        runner = FakeRunner({('rspamadm', 'configtest'): (1, 'syntax error')})
        with self.assertRaisesRegex(RspamdError, 'configtest failed'):
            rs.apply_settings({}, runner=runner, backup_root=os.path.join(self.root, 'b'))
        with open(os.path.join(self.local_d, 'actions.conf')) as handle:
            self.assertEqual(handle.read(), 'reject = 99;\n')
        self.assertFalse(os.path.exists(os.path.join(self.local_d, 'greylist.conf')))

    def test_success_writes_and_reloads(self):
        runner = FakeRunner()
        result = rs.apply_settings({'reject': 20}, runner=runner, backup_root=os.path.join(self.root, 'b'))
        self.assertEqual(result['settings']['reject'], 20.0)
        self.assertIn(['systemctl', 'reload-or-restart', 'rspamd'], runner.calls)
        self.assertEqual(rs.read_settings(os.path.join(self.local_d, 'ua-settings.json'))['reject'], 20.0)


class Filtering(unittest.TestCase):
    def runner(self, sa_wired=True):
        master_p = 'smtp/inet/content_filter = spamassassin\n' if sa_wired else ''
        return FakeRunner({
            ('postconf', '-P'): (0, master_p),
            ('postconf', '-M'): (0, 'spamassassin unix - n n - - pipe user=spamd argv=/usr/bin/spamc\n' if sa_wired else ''),
            ('postconf', '-e'): (0, ''),
            ('postconf', 'smtpd_milters'): (0, 'smtpd_milters = inet:127.0.0.1:8891\nnon_smtpd_milters = $smtpd_milters\n'),
            ('systemctl', 'is-active', 'mailscanner'): (3, 'inactive'),
            ('systemctl', 'is-active'): (0, 'active'),
        })

    def test_dry_run_changes_nothing(self):
        runner = self.runner()
        plan = rs.set_filtering(True, replace_spamassassin=True, dry_run=True, runner=runner)
        self.assertEqual(plan['remove_master_params'], ['smtp/inet/content_filter'])
        self.assertFalse(any(c[:2] == ['postconf', '-e'] for c in runner.calls))

    def test_refuses_to_double_filter_with_spamassassin(self):
        runner = self.runner()
        with mock.patch.object(rs, 'detect', return_value={'installed': True, 'conflicts': [{'id': 'spamassassin'}]}):
            with self.assertRaisesRegex(RspamdError, 'SpamAssassin'):
                rs.set_filtering(True, runner=runner, backup_root=tempfile.mkdtemp())

    def test_enable_with_replace_uses_postconf_argv(self):
        runner = self.runner()
        with mock.patch.object(rs, 'detect', return_value={'installed': True, 'conflicts': [{'id': 'spamassassin'}]}), \
                mock.patch.object(rs, '_backup', return_value=('', {})):
            rs.set_filtering(True, replace_spamassassin=True, runner=runner)
        self.assertIn(['postconf', '-e', 'smtpd_milters=inet:127.0.0.1:8891 ' + rs.RSPAMD_MILTER], runner.calls)
        self.assertIn(['postconf', '-e', 'milter_default_action=accept'], runner.calls)
        self.assertIn(['postconf', '-PX', 'smtp/inet/content_filter'], runner.calls)
        self.assertIn(['postfix', 'check'], runner.calls)

    def test_mailscanner_blocks_enable(self):
        with mock.patch.object(rs, 'detect', return_value={'installed': True, 'conflicts': [{'id': 'mailscanner'}]}), \
                self.assertRaisesRegex(RspamdError, 'MailScanner'):
            rs.set_filtering(True, runner=self.runner(sa_wired=False), backup_root=tempfile.mkdtemp())


class StatsLearnInstall(unittest.TestCase):
    def test_parse_stat(self):
        text = ('Messages scanned: 120\nMessages with action reject: 10, 8.33%\n'
                'Messages with action no action: 100, 83%\nMessages treated as spam: 12, 10%\n'
                'Messages treated as ham: 108, 90%\nMessages learned: 40\n')
        stats = rs.parse_stat(text)
        self.assertEqual((stats['scanned'], stats['learned'], stats['spam_count']), (120, 40, 12))
        self.assertEqual(stats['actions'], {'reject': 10, 'no action': 100})

    def test_maildir_folder_confined(self):
        vmail = tempfile.mkdtemp()
        os.makedirs(os.path.join(vmail, 'example.com', 'bob', 'Maildir', '.Junk', 'cur'))
        self.assertTrue(rs.maildir_folder('example.com', 'bob', 'Junk', vmail).endswith('Maildir/.Junk'))
        for args in (('../etc', 'bob', 'Junk'), ('example.com', '../../root', 'Junk'),
                     ('example.com', 'bob', '../../x')):
            with self.assertRaises(RspamdError):
                rs.maildir_folder(*args, vmail=vmail)

    def test_learn_batches(self):
        vmail = tempfile.mkdtemp()
        cur = os.path.join(vmail, 'example.com', 'bob', 'Maildir', '.Junk', 'cur')
        os.makedirs(cur)
        for i in range(150):
            open(os.path.join(cur, 'm%03d' % i), 'w').close()
        runner = FakeRunner({('rspamc',): (0, 'success = true\n' * 100)})
        result = rs.learn('spam', 'example.com', 'bob', 'Junk', runner=runner, vmail=vmail)
        self.assertEqual(result['messages'], 150)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[0][:2], ['rspamc', 'learn_spam'])

    def test_install_commands(self):
        rhel = rs.install_commands('rhel', 8)
        self.assertIn('centos-8', rhel[0][-1])
        self.assertIn(['dnf', '-y', 'install', 'redis', 'rspamd'], rhel)
        self.assertIn('centos-9', rs.install_commands('rhel', 10)[0][-1])
        self.assertTrue(any('bookworm' in ' '.join(c) for c in rs.install_commands('debian', 0, 'bookworm')))
        with self.assertRaises(RspamdError):
            rs.install_commands('debian', 0, 'x; rm -rf /')


class Jobs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.patch = mock.patch.object(jobs, 'JOB_DIR', self.dir)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.dir)

    def test_run_job_records_steps_and_failure(self):
        job_id = 'a' * 24
        data = jobs.run_job(job_id, [('one', lambda job: job.log('hello') or 1),
                                     ('two', lambda job: (_ for _ in ()).throw(RuntimeError('broke')))])
        self.assertEqual(data['state'], 'failed')
        self.assertIn('broke', data['error'])
        status = jobs.status(job_id)
        self.assertIn('==> one', status['log'])
        self.assertIn('hello', status['log'])
        with self.assertRaises(ValueError):
            jobs.status('../etc/passwd')

    def test_spawn_runs_detached_runner(self):
        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        result = jobs.spawn('rspamd', 'job', {}, python=sys.executable,
                            runner_path=os.path.join(repo, 'universalAddons', 'runner.py'))
        self.assertRegex(result['job_id'], r'^[0-9a-f]{24}$')
        deadline = time.time() + 10
        while time.time() < deadline and not os.path.exists(os.path.join(self.dir, result['job_id'] + '.json.out')):
            time.sleep(0.1)
        self.assertTrue(os.path.exists(os.path.join(self.dir, result['job_id'] + '.json')))


if __name__ == '__main__':
    unittest.main()
