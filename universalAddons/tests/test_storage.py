import gzip
import json
import os
import shutil
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons.storage import service as st, views


def make(path, size=1024, age_days=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(b'x' * size)
    if age_days:
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))


class Guards(unittest.TestCase):
    def test_path_guard(self):
        for bad in ('/', '/etc', '/home', '/var/lib/mysql', '/home/example.com', '/usr/local/CyberCP', 'relative',
                    '/var/log/../etc', '', None, '/tmp'):
            self.assertFalse(st.path_is_sane(bad), bad)
        for ok in ('/var/cache/dnf', '/home/example.com/.trash', '/usr/lib/debug', '/root/.npm/_cacache'):
            self.assertTrue(st.path_is_sane(ok), ok)
        with self.assertRaises(st.CleanError):
            st.safe_rm('/etc')

    def test_truncate_keeps_the_file(self):
        root = tempfile.mkdtemp()
        log = os.path.join(root, 'server.log')
        make(log, 4096)
        handle = open(log, 'ab')  # a running process holding the file open
        self.assertGreater(st.safe_truncate(log), 0)
        self.assertTrue(os.path.exists(log))
        self.assertEqual(os.path.getsize(log), 0)
        handle.write(b'still works\n')
        handle.close()
        shutil.rmtree(root)

    def test_old_files_age_patterns_symlinks_excludes(self):
        root = tempfile.mkdtemp()
        make(os.path.join(root, 'sess_old'), age_days=10)
        make(os.path.join(root, 'sess_new'), age_days=1)
        make(os.path.join(root, 'other_old'), age_days=10)
        make(os.path.join(root, 'keep', 'sess_old2'), age_days=10)
        target = os.path.join(root, 'outside')
        make(target, age_days=10)
        os.symlink(target, os.path.join(root, 'sess_link'))
        found = sorted(os.path.basename(p) for p, _ in st.old_files([root], 7, ('sess_*',), exclude=('keep',)))
        self.assertEqual(found, ['sess_old'])
        shutil.rmtree(root)

    def test_dry_run_changes_nothing(self):
        root = tempfile.mkdtemp()
        make(os.path.join(root, 'a.gz'), age_days=40)
        count, kb = st.delete_files(st.old_files([root], 30, ('*.gz',)), dry_run=True)
        self.assertEqual(count, 1)
        self.assertTrue(os.path.exists(os.path.join(root, 'a.gz')))
        shutil.rmtree(root)


class Categories(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_cli_versions_keep_newest_and_active(self):
        home = os.path.join(self.root, 'home', 'u')
        base = os.path.join(home, '.local/share/claude/versions')
        for version in ('2.1.9', '2.1.10', '2.1.316', '2.1.325'):
            make(os.path.join(base, version, 'claude'), 2048)
        os.makedirs(os.path.join(home, '.local/bin'))
        os.symlink(os.path.join(base, '2.1.316', 'claude'), os.path.join(home, '.local/bin/claude'))
        with mock.patch.object(st, 'user_homes', return_value=[home]):
            removable = sorted(os.path.basename(i['path']) for i in st._claude_versions())
        self.assertEqual(removable, ['2.1.10', '2.1.9'], 'newest (2.1.325) and active (2.1.316) kept; numeric sort')

    def test_public_archives_need_explicit_selection(self):
        site = os.path.join(self.root, 'example.com')
        make(os.path.join(site, 'public_html', 'site-backup.zip'), (st.PUBLIC_ARCHIVE_MIN_MB + 1) * 1048576)
        make(os.path.join(site, 'public_html', 'small.zip'), 1024)
        with mock.patch.object(st, 'site_homes', return_value=[site]):
            items = st._public_archives()
            self.assertEqual([os.path.basename(i['path']) for i in items], ['site-backup.zip'])
            log = []
            st.run_public_archives(False, log.append, items=None)
            self.assertTrue(os.path.exists(items[0]['path']), '"all" never deletes archives')
            st.run_public_archives(False, log.append, items=['/etc/passwd', items[0]['path']])
            self.assertFalse(os.path.exists(items[0]['path']))
            self.assertTrue(os.path.exists('/etc/passwd'))

    def test_big_logs_only_truncates_discovered_files(self):
        site = os.path.join(self.root, 'example.com')
        log_path = os.path.join(site, 'server.log')
        make(log_path, 1024)
        with mock.patch.object(st, 'site_homes', return_value=[site]), mock.patch.object(st, 'ACTIVE_LOG_MAX_MB', 0), \
                mock.patch.object(st, 'ACTIVE_LOG_CANDIDATES', ()):
            self.assertEqual([i['path'] for i in st.big_logs()], [log_path])
            st.run_big_logs(False, lambda t: None, items=[log_path, '/etc/hosts'])
        self.assertEqual(os.path.getsize(log_path), 0)
        self.assertGreater(os.path.getsize('/etc/hosts'), 0)

    def test_docker_installed_is_conservative(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ['docker', 'images']:
                return SimpleNamespace(returncode=0, stdout='120MB\n1.5GB\n')
            if argv[:3] == ['docker', 'system', 'df']:
                return SimpleNamespace(returncode=0, stdout='Images|0B (0%)\nBuild Cache|300MB\nContainers|1kB (3%)\n')
            return SimpleNamespace(returncode=0, stdout='')
        with mock.patch.object(st, 'have', return_value=True), mock.patch.object(st, 'docker_is_absent', return_value=False):
            probe = st.probe_docker(runner)
            self.assertEqual(probe['kb'], 120 * 1024 + int(1.5 * 1048576) + 300 * 1024)
            st.run_docker(False, lambda t: None, runner=runner)
        flat = [' '.join(c) for c in calls]
        self.assertIn('docker image prune -f', flat)
        self.assertFalse(any('system prune' in c or 'container prune' in c or 'volume prune' in c for c in flat))


class InnoDB(unittest.TestCase):
    def setUp(self):
        self.backup = tempfile.mkdtemp()
        self.datadir = tempfile.mkdtemp()
        make(os.path.join(self.datadir, 'shop', 'cache.ibd'), 4096)

    def tearDown(self):
        shutil.rmtree(self.backup)
        shutil.rmtree(self.datadir)

    def fake(self, dump_body, rows_after='21'):
        state = {'optimized': False}

        def runner(argv, **kwargs):
            sql = argv[-1]
            if sql.startswith('SELECT COUNT(*)'):
                return SimpleNamespace(returncode=0, stdout=(rows_after if state['optimized'] else '21') + '\n')
            if sql.startswith('OPTIMIZE'):
                state['optimized'] = True
                return SimpleNamespace(returncode=0, stdout='ok\n')
            return SimpleNamespace(returncode=0, stdout='')

        class Popen:
            def __init__(self, argv, **kwargs):
                import io
                self.stdout = io.BytesIO(dump_body)
                self.returncode = 0

            def wait(self):
                return 0
        return runner, Popen, state

    def test_unverified_backup_blocks_rebuild(self):
        runner, popen, state = self.fake(b'-- partial dump without footer\n')
        log = []
        freed = st.rebuild_table('shop', 'cache', '/dev/null', self.backup, log.append, runner, popen, self.datadir)
        self.assertEqual(freed, 0)
        self.assertFalse(state['optimized'])
        self.assertIn('NOT rebuilding', log[0])

    def test_verified_backup_then_optimize_and_row_check(self):
        runner, popen, state = self.fake(b'INSERT ...;\n-- Dump completed on 2026-11-14\n')
        log = []
        st.rebuild_table('shop', 'cache', '/dev/null', self.backup, log.append, runner, popen, self.datadir)
        self.assertTrue(state['optimized'])
        with gzip.open(os.path.join(self.backup, 'shop.cache.sql.gz')) as handle:
            self.assertIn(b'Dump completed', handle.read())
        self.assertIn('rows intact', log[-1])

    def test_row_count_change_is_reported(self):
        runner, popen, state = self.fake(b'-- Dump completed\n', rows_after='20')
        log = []
        self.assertEqual(st.rebuild_table('shop', 'cache', '/dev/null', self.backup, log.append, runner, popen,
                                          self.datadir), 0)
        self.assertIn('ROW COUNT CHANGED', log[-1])

    def test_identifiers_validated(self):
        with self.assertRaises(st.CleanError):
            st.rebuild_table('shop', 'cache`; DROP TABLE x; --', '/dev/null', self.backup, print)


class StorageViews(SimpleTestCase):
    def post(self, body, admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'job_id': 'j'}) as call:
            response = views.clean(request)
        return response.status_code, call

    def test_admin_only_and_selection_validation(self):
        status, call = self.post({'sel_tmp_files': True}, admin=0)
        self.assertEqual(status, 403)
        for body in ({'sel_rm_everything': True}, {'sel_trash': 'yes'}, {'sel_trash': ['/home/a/.trash\n/etc']}, {}):
            status, call = self.post(body)
            self.assertEqual(status, 400, body)
            call.assert_not_called()
        status, call = self.post({'sel_tmp_files': True, 'sel_mysql_bloat': ['shop.cache'], 'dryRun': True})
        call.assert_called_once_with('storage', 'clean', selection={'tmp_files': True, 'mysql_bloat': ['shop.cache']},
                                     dry_run=True)


if __name__ == '__main__':
    unittest.main()
