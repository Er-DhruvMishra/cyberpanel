import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from universalAddons.backupv2 import service as bk
from universalAddons.backupv2.service import BackupError

HAVE_RESTIC = shutil.which('restic') is not None


class Validation(unittest.TestCase):
    def test_repo_types(self):
        self.assertEqual(bk.repository_url(bk.validate_repo({'id': 'loc', 'type': 'local', 'path': '/backup/r/'})),
                         '/backup/r')
        sftp = bk.validate_repo({'id': 'off', 'type': 'sftp', 'host': 'b.example.net', 'user': 'u1', 'port': '2222',
                                 'path': '/srv/restic'})
        self.assertEqual(bk.repository_url(sftp), 'sftp:u1@b.example.net:/srv/restic')
        s3 = bk.validate_repo({'id': 's3', 'type': 's3', 'endpoint': 'https://s3.eu.wasabisys.com/', 'bucket': 'my-bkt',
                               'prefix': 'srv1'})
        self.assertEqual(bk.repository_url(s3), 's3:https://s3.eu.wasabisys.com/my-bkt/srv1')
        self.assertEqual(bk.repository_url(bk.validate_repo({'id': 'g', 'type': 'rclone', 'remote': 'gdrive',
                                                             'path': 'backups'})), 'rclone:gdrive:backups')

    def test_repo_rejections(self):
        bad = [{'id': 'X Y', 'type': 'local', 'path': '/b'}, {'id': 'a', 'type': 'local', 'path': '/etc/x'},
               {'id': 'a', 'type': 'local', 'path': '/'}, {'id': 'a', 'type': 'local', 'path': '/home'},
               {'id': 'a', 'type': 'sftp', 'host': 'h;id', 'user': 'u', 'path': '/p'},
               {'id': 'a', 'type': 'sftp', 'host': 'h', 'user': 'u', 'path': 'rel'},
               {'id': 'a', 'type': 's3', 'endpoint': 'x', 'bucket': 'B@D'},
               {'id': 'a', 'type': 'rclone', 'remote': 'g d', 'path': 'x'}, {'id': 'a', 'type': 'ftp'}]
        for spec in bad:
            with self.assertRaises(BackupError, msg=spec):
                bk.validate_repo(spec)

    def test_policy(self):
        repos = {'r1': {}}
        p = bk.validate_policy({'id': 'nightly', 'repo': 'r1', 'units': ['db', 'files'], 'schedule': 'daily',
                                'hour': '3', 'keep': {'daily': '7', 'bogus': 1}}, repos)
        self.assertEqual((p['units'], p['hour'], p['keep']), (['files', 'db'], 3, {'daily': 7}))
        for spec in ({'id': 'p', 'repo': 'nope'}, {'id': 'p', 'repo': 'r1', 'units': ['all']},
                     {'id': 'p', 'repo': 'r1', 'schedule': 'every minute'}, {'id': 'p', 'repo': 'r1', 'hour': 24},
                     {'id': 'p', 'repo': 'r1', 'sites': ['bad domain']}):
            with self.assertRaises(BackupError, msg=spec):
                bk.validate_policy(spec, repos)

    def test_retention_and_cron(self):
        self.assertEqual(bk.retention_args({'keep': {'daily': 7, 'monthly': 3}}),
                         ['--keep-daily', '7', '--keep-monthly', '3'])
        self.assertEqual(bk.retention_args({}), ['--keep-last', '7'])
        cron = bk.cron_lines([{'id': 'n', 'schedule': 'daily', 'hour': 4}, {'id': 'm', 'schedule': 'manual', 'hour': 0}])
        lines = [l for l in cron.splitlines() if not l.startswith('#')]
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r'^\d+ 4 \* \* \* root .* backupv2 run_policy [A-Za-z0-9_=-]+ >/dev/null 2>&1$')


class Secrets(unittest.TestCase):
    def test_key_and_s3_secrets_are_private(self):
        config = tempfile.mkdtemp()
        repo = bk.save_repo({'id': 'w', 'type': 's3', 'endpoint': 's3.example.com', 'bucket': 'bkt'},
                            'AKIAEXAMPLEKEY1', 'secret/Key+123=', config_dir=config)
        for path in (os.path.join(config, 'keys', 'w.key'), os.path.join(config, 'env', 'w.json'),
                     os.path.join(config, 'repos.json')):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600, path)
        with open(os.path.join(config, 'repos.json')) as handle:
            self.assertNotIn('secret', handle.read())
        argv, env = bk.restic_base(repo, config_dir=config)
        self.assertEqual(env['AWS_SECRET_ACCESS_KEY'], 'secret/Key+123=')
        self.assertNotIn('secret/Key+123=', ' '.join(argv))
        key = bk.export_key('w', config_dir=config)
        bk.save_repo({'id': 'w', 'type': 's3', 'endpoint': 's3.example.com', 'bucket': 'bkt'}, config_dir=config)
        self.assertEqual(bk.export_key('w', config_dir=config), key, 'key must never be regenerated')
        with self.assertRaises(BackupError):
            bk.save_repo({'id': 'v', 'type': 's3', 'endpoint': 's3.example.com', 'bucket': 'bkt'}, 'k', '',
                         config_dir=config)

    def test_mysql_defaults_file(self):
        cases = (('pa"ss\\word\n', 'password="pa\\"ss\\\\word"'),
                 (json.dumps({'mysqluser': 'root', 'mysqlpassword': 'p@ss', 'mysqlhost': 'db', 'mysqlport': '3307'}),
                  'password="p@ss"\nhost=db\nport=3307'))
        for content, expected in cases:
            with tempfile.NamedTemporaryFile('w', delete=False) as handle:
                handle.write(content)
            path = bk.mysql_defaults_file(handle.name)
            try:
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                with open(path) as cnf:
                    text = cnf.read()
                self.assertTrue(text.startswith('[client]\n'))
                self.assertIn(expected, text)
            finally:
                os.unlink(path)
                os.unlink(handle.name)

    def test_lock_prevents_overlap(self):
        lock_dir = tempfile.mkdtemp()
        with bk.repo_lock('r', lock_dir):
            with self.assertRaisesRegex(BackupError, 'Another backup'):
                with bk.repo_lock('r', lock_dir):
                    pass
        with bk.repo_lock('r', lock_dir):
            pass


@unittest.skipUnless(HAVE_RESTIC, 'restic not installed')
class RealRestic(unittest.TestCase):
    """End-to-end against a local repository with the real restic binary."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.config = os.path.join(self.root, 'config')
        self.sites = os.path.join(self.root, 'home')
        self.site = os.path.join(self.sites, 'example.com')
        os.makedirs(os.path.join(self.site, 'public_html'))
        with open(os.path.join(self.site, 'public_html', 'index.php'), 'w') as handle:
            handle.write('<?php echo "v1";')
        self.patches = [mock.patch.object(bk, 'SITES_ROOT', self.sites),
                        mock.patch.dict(os.environ, {'RESTIC_CACHE_DIR': os.path.join(self.root, 'cache')})]
        for patch in self.patches:
            patch.start()
        self.repo = bk.save_repo({'id': 'local', 'type': 'local', 'path': os.path.join(self.root, 'repo')},
                                 config_dir=self.config)
        self.assertTrue(bk.init_repo(self.repo, config_dir=self.config)['initialised'])
        self.assertFalse(bk.init_repo(self.repo, config_dir=self.config)['initialised'])
        # fake mysqldump/mysql on PATH
        self.bin = os.path.join(self.root, 'bin')
        os.makedirs(self.bin)
        self.imported = os.path.join(self.root, 'imported.sql')
        self._script('mysqldump', '#!/bin/sh\necho "-- dump of $(eval echo \\${$#})"\necho "INSERT 1;"\n')
        self._script('mysql', '#!/bin/sh\ncat > %s\n' % self.imported)
        os.environ['PATH'] = self.bin + os.pathsep + os.environ['PATH']

    def _script(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, 'w') as handle:
            handle.write(body)
        os.chmod(path, 0o755)

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        os.environ['PATH'] = os.environ['PATH'].replace(self.bin + os.pathsep, '')
        shutil.rmtree(self.root)

    def test_backup_snapshots_restore_and_db_roundtrip(self):
        defaults = os.path.join(self.root, 'my.cnf')
        open(defaults, 'w').close()
        result = bk.backup_site(self.repo, 'example.com', ['files', 'db', 'mail'], ['wp_db'], 'host1',
                                config_dir=self.config, defaults_file=defaults)
        self.assertTrue(result['files'].startswith('snapshot '))
        self.assertTrue(result['db:wp_db'].startswith('snapshot '))
        self.assertEqual(result['mail'], 'skipped (nothing to back up)')

        snaps = bk.snapshots(self.repo, 'example.com', config_dir=self.config)
        self.assertEqual(sorted(s['unit'] for s in snaps), ['db', 'files'])
        files_snap = next(s for s in snaps if s['unit'] == 'files')['id']
        top = bk.list_files(self.repo, files_snap, '/', config_dir=self.config)
        self.assertFalse(any(e['path'].endswith('index.php') for e in top), 'listing is one level at a time')
        listing = bk.list_files(self.repo, files_snap, os.path.join(self.site, 'public_html'), config_dir=self.config)
        self.assertTrue(any(e['path'].endswith('index.php') for e in listing))

        # alternate-location restore leaves the live site alone
        target = os.path.join(self.root, 'restore-alt')
        bk.restore_files(self.repo, files_snap, 'example.com', target=target, config_dir=self.config)
        restored = os.path.join(target, self.site.lstrip('/'), 'public_html', 'index.php')
        with open(restored) as handle:
            self.assertEqual(handle.read(), '<?php echo "v1";')

        # in-place restore takes a safety snapshot of the current (changed) state first
        with open(os.path.join(self.site, 'public_html', 'index.php'), 'w') as handle:
            handle.write('<?php echo "broken";')
        bk.restore_files(self.repo, files_snap, 'example.com', config_dir=self.config,
                         include=os.path.join(self.site, 'public_html', 'index.php'))
        with open(os.path.join(self.site, 'public_html', 'index.php')) as handle:
            self.assertEqual(handle.read(), '<?php echo "v1";')
        tags = [s['tags'] for s in bk.snapshots(self.repo, 'example.com', config_dir=self.config)]
        self.assertTrue(any('pre-restore' in t for t in tags))

        # database: restore streams the stored dump into mysql, after a pre-restore dump
        db_snap = next(s for s in snaps if s['unit'] == 'db')['id']
        bk.restore_database(self.repo, db_snap, 'wp_db', config_dir=self.config, defaults_file=defaults,
                            site='example.com')
        with open(self.imported) as handle:
            self.assertEqual(handle.read(), '-- dump of wp_db\nINSERT 1;\n')

        # retention and verification
        self.assertEqual(bk.apply_retention(self.repo, 'example.com', {'keep': {'last': 1}}, config_dir=self.config),
                         'retention applied')
        self.assertTrue(bk.check_repo(self.repo, config_dir=self.config, subset='100%')['ok'])

    def test_rejects_bad_input_before_restic(self):
        with self.assertRaises(BackupError):
            bk.backup_site(self.repo, 'bad domain', ['files'], [], 'h', config_dir=self.config)
        with self.assertRaises(BackupError):
            bk.backup_site(self.repo, 'example.com', ['db'], ['x; DROP'], 'h', config_dir=self.config,
                           defaults_file='/dev/null')
        with self.assertRaises(BackupError):
            bk.restore_files(self.repo, 'zzz', 'example.com', config_dir=self.config)
        with self.assertRaises(BackupError):
            bk.restore_files(self.repo, 'abcdef12', 'example.com', target='/etc/x', config_dir=self.config)


if __name__ == '__main__':
    unittest.main()
