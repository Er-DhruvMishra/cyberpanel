import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile

from universalAddons.rootfm import service as fm
from universalAddons.rootfm.service import FMError


class Policy(unittest.TestCase):
    def test_clean_path(self):
        self.assertEqual(fm.clean_path('/var//log/../log/'), '/var/log')
        for bad in ('', 'relative/path', '/a\x00b', None, 5):
            with self.assertRaises(FMError):
                fm.clean_path(bad)

    def test_read_only_and_credentials_never_writable(self):
        for path in ('/proc/sys/kernel/x', '/sys/x', '/dev/sda', '/etc/shadow', '/etc/sudoers', '/'):
            with self.assertRaises(FMError):
                fm.check_writable(path, unlock=True)

    def test_protected_needs_unlock(self):
        for path in ('/etc/postfix/main.cf', '/usr/local/CyberCP/CyberCP/settings.py', '/root/.ssh/authorized_keys',
                     '/home'):
            with self.assertRaisesRegex(FMError, '^PROTECTED:'):
                fm.check_writable(path)
            self.assertEqual(fm.check_writable(path, unlock=True), path)

    def test_traversal_is_normalised_before_policy(self):
        with self.assertRaisesRegex(FMError, 'credential'):
            fm.check_writable('/home/site/../../etc/shadow', unlock=True)

    def test_symlink_into_protected_tree_is_caught(self):
        directory = tempfile.mkdtemp()
        try:
            link = os.path.join(directory, 'shadow')
            os.symlink('/etc/shadow', link)
            with self.assertRaises(FMError):
                fm.check_writable(link, unlock=True)
        finally:
            shutil.rmtree(directory)


class Operations(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.trash = os.path.join(self.root, '.trash')
        self.log = os.path.join(self.root, 'audit.log')
        self._audit = fm.AUDIT_LOG
        fm.AUDIT_LOG = self.log

    def tearDown(self):
        fm.AUDIT_LOG = self._audit
        shutil.rmtree(self.root)

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def test_create_list_read_write(self):
        fm.create(self.root, 'dir', 'dir')
        fm.create(self.p('dir'), 'a.txt', 'file')
        listing = fm.list_dir(self.root)
        self.assertEqual([e['name'] for e in listing['entries']], ['dir', 'audit.log'][:len(listing['entries'])])
        first = fm.read_file(self.p('dir', 'a.txt'))
        saved = fm.write_file(self.p('dir', 'a.txt'), 'hello\n', expected_sha256=first['sha256'])
        self.assertEqual(fm.read_file(self.p('dir', 'a.txt'))['content'], 'hello\n')
        with self.assertRaisesRegex(FMError, 'changed on disk'):
            fm.write_file(self.p('dir', 'a.txt'), 'stale', expected_sha256=first['sha256'])
        fm.write_file(self.p('dir', 'a.txt'), 'ok', expected_sha256=saved['sha256'])

    def test_write_preserves_mode_and_is_atomic(self):
        path = self.p('conf')
        with open(path, 'w') as handle:
            handle.write('x')
        os.chmod(path, 0o640)
        fm.write_file(path, 'y')
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o640')
        self.assertEqual([n for n in os.listdir(self.root) if 'cp-rootfm' in n], [])

    def test_binary_and_large_files_refused_in_editor(self):
        with open(self.p('bin'), 'wb') as handle:
            handle.write(b'\x00\x01\x02')
        with self.assertRaisesRegex(FMError, 'Binary'):
            fm.read_file(self.p('bin'))
        with open(self.p('big'), 'wb') as handle:
            handle.truncate(fm.MAX_EDIT_BYTES + 1)
        with self.assertRaisesRegex(FMError, 'up to'):
            fm.read_file(self.p('big'))

    def test_names_validated(self):
        for bad in ('', '.', '..', 'a/b', 'x\x00'):
            with self.assertRaises(FMError):
                fm.create(self.root, bad, 'file')

    def test_rename_copy_move(self):
        fm.create(self.root, 'src', 'dir')
        fm.create(self.p('src'), 'f', 'file')
        fm.create(self.root, 'dst', 'dir')
        fm.copy([self.p('src')], self.p('dst'))
        self.assertTrue(os.path.isfile(self.p('dst', 'src', 'f')))
        with self.assertRaisesRegex(FMError, 'already exists'):
            fm.copy([self.p('src')], self.p('dst'))
        with self.assertRaisesRegex(FMError, 'into itself'):
            fm.copy([self.p('src')], self.p('src'))
        fm.rename(self.p('src', 'f'), 'g')
        fm.move([self.p('src', 'g')], self.p('dst'))
        self.assertTrue(os.path.isfile(self.p('dst', 'g')))

    def test_trash_restore_purge(self):
        fm.create(self.root, 'doomed', 'file')
        item = fm.trash([self.p('doomed')], trash_dir=self.trash)['trashed'][0]
        self.assertFalse(os.path.exists(self.p('doomed')))
        listed = fm.list_trash(trash_dir=self.trash)['items']
        self.assertEqual((listed[0]['id'], listed[0]['path']), (item['id'], self.p('doomed')))
        fm.restore(item['id'], trash_dir=self.trash)
        self.assertTrue(os.path.exists(self.p('doomed')))
        item = fm.trash([self.p('doomed')], trash_dir=self.trash)['trashed'][0]
        fm.purge([item['id']], trash_dir=self.trash)
        self.assertEqual(fm.list_trash(trash_dir=self.trash)['items'], [])
        for bad in ('../x', '', '.hidden', 'a/b'):
            with self.assertRaises(FMError):
                fm.restore(bad, trash_dir=self.trash)

    def test_chmod_validation_and_recursion(self):
        fm.create(self.root, 'd', 'dir')
        fm.create(self.p('d'), 'f', 'file')
        fm.chmod([self.p('d')], '0700', recursive=True)
        self.assertEqual(oct(os.stat(self.p('d', 'f')).st_mode & 0o777), '0o700')
        for bad in ('999', '12', 'rwx', '0o644', '77777'):
            with self.assertRaises(FMError):
                fm.chmod([self.p('d')], bad)

    def test_chown_unknown_user(self):
        fm.create(self.root, 'f', 'file')
        with self.assertRaisesRegex(FMError, 'Unknown user'):
            fm.chown([self.p('f')], 'no-such-user-xyz')

    def _zip(self, path, members):
        with zipfile.ZipFile(path, 'w') as bundle:
            for name, data in members:
                bundle.writestr(name, data)

    def test_extract_zip_and_tar_safely(self):
        fm.create(self.root, 'out', 'dir')
        self._zip(self.p('ok.zip'), [('a/b.txt', 'hi')])
        self.assertEqual(fm.extract(self.p('ok.zip'), self.p('out'))['extracted'], 1)
        self.assertTrue(os.path.isfile(self.p('out', 'a', 'b.txt')))
        self._zip(self.p('evil.zip'), [('../../escape.txt', 'x')])
        with self.assertRaisesRegex(FMError, 'outside'):
            fm.extract(self.p('evil.zip'), self.p('out'))
        tar_path = self.p('evil.tar')
        with tarfile.open(tar_path, 'w') as bundle:
            info = tarfile.TarInfo('link')
            info.type, info.linkname = tarfile.SYMTYPE, '/etc'
            bundle.addfile(info)
        with self.assertRaisesRegex(FMError, 'outside'):
            fm.extract(tar_path, self.p('out'))
        with open(self.p('plain.txt'), 'w') as handle:
            handle.write('x')
        with self.assertRaisesRegex(FMError, 'Unsupported'):
            fm.extract(self.p('plain.txt'), self.p('out'))

    def test_compress_roundtrip(self):
        fm.create(self.root, 'site', 'dir')
        fm.write_file(self.p('site', 'index.php'), '<?php echo 1;')
        for fmt in ('zip', 'tar.gz'):
            info = fm.compress([self.p('site')], self.root, 'bundle-' + fmt.replace('.', ''), fmt)
            self.assertTrue(info['name'].endswith(fmt))
            self.assertEqual(info['mode'], '0600')

    def test_search_du_checksum(self):
        fm.create(self.root, 'Alpha', 'dir')
        fm.write_file(self.p('Alpha', 'alphabet.txt'), 'abc')
        names = sorted(r['name'] for r in fm.search(self.root, 'ALPHA')['results'])
        self.assertEqual(names, ['Alpha', 'alphabet.txt'])
        self.assertGreaterEqual(fm.disk_usage(self.root)['files'], 1)
        self.assertEqual(fm.checksum(self.p('Alpha', 'alphabet.txt'))['sha256'],
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_audit_log_records_changes(self):
        fm.create(self.root, 'x', 'file', actor='admin')
        fm.rename(self.p('x'), 'y', actor='admin')
        with open(self.log) as handle:
            entries = [json.loads(line) for line in handle]
        self.assertEqual([e['action'] for e in entries], ['create', 'rename'])
        self.assertEqual(entries[1]['actor'], 'admin')


if __name__ == '__main__':
    unittest.main()
