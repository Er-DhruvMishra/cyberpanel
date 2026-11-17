"""Storage Cleaner trash categories: file manager .trash, mailbox Trash/Junk, desktop trash."""
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

DAY = 86400


def make(path, size=1024, age_days=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(b'x' * size)
    if age_days:
        age(path, age_days)


def age(path, days):
    stamp = time.time() - days * DAY
    os.utime(path, (stamp, stamp), follow_symlinks=False)


def by_mtime(info):  # ctime cannot be set in a test; use the (settable) mtime as "trashed at"
    return info.st_mtime


class FakeTrashRows:
    """Stands in for filemanager.models.Trash: {domain: [(pk, fileName)]}, names quoted like filemanager.py."""

    def __init__(self, rows):
        self.data = {d: list(r) for d, r in rows.items()}
        self.deleted = []

    def rows(self, domain):
        return list(self.data.get(domain, []))

    def delete(self, pks):
        pks = set(pks)
        self.deleted += sorted(pks)
        for domain in self.data:
            self.data[domain] = [r for r in self.data[domain] if r[0] not in pks]


class TrashBase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.patch = mock.patch.object(st, 'trashed_at', by_mtime)
        self.patch.start()
        self.log = []

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.root)

    def site(self, domain='example.com'):
        home = os.path.join(self.root, 'home', domain)
        os.makedirs(os.path.join(home, '.trash'), exist_ok=True)
        return home


class FileManagerTrash(TrashBase):
    def fill(self, home):
        trash = os.path.join(home, '.trash')
        make(os.path.join(trash, 'old.txt'), 4096, age_days=40)
        make(os.path.join(trash, 'week', 'a.php'), 4096)
        age(os.path.join(trash, 'week'), 10)
        make(os.path.join(trash, 'new.txt'), 4096, age_days=1)
        return trash

    def test_age_filter(self):
        home = self.site()
        trash = self.fill(home)
        db = FakeTrashRows({})
        st.clean_fm_trash(home, 30, False, self.log.append, db)
        self.assertEqual(sorted(os.listdir(trash)), ['new.txt', 'week'])
        st.clean_fm_trash(home, 7, False, self.log.append, db)
        self.assertEqual(sorted(os.listdir(trash)), ['new.txt'])
        st.clean_fm_trash(home, 0, False, self.log.append, db)
        self.assertEqual(os.listdir(trash), [])
        self.assertTrue(os.path.isdir(trash), 'the .trash folder itself is kept')

    def test_dry_run_changes_nothing(self):
        home = self.site()
        trash = self.fill(home)
        quoted = st.quote_trash_name
        db = FakeTrashRows({'example.com': [(1, quoted('old.txt'))]})
        freed = st.clean_fm_trash(home, 0, True, self.log.append, db)
        self.assertGreater(freed, 0)
        self.assertEqual(sorted(os.listdir(trash)), ['new.txt', 'old.txt', 'week'])
        self.assertEqual(db.deleted, [])
        self.assertIn('would empty', self.log[-1])

    def test_trash_rows_removed_for_deleted_items_only(self):
        home = self.site()
        self.fill(home)
        make(os.path.join(home, '.trash', "it's.txt"), age_days=40)
        quoted = st.quote_trash_name
        self.assertEqual(quoted("it's.txt"), "'it'\"'\"'s.txt'")
        self.assertEqual(st.unquote_trash_name(quoted("it's.txt")), "it's.txt")
        db = FakeTrashRows({'example.com': [(1, quoted('old.txt')), (2, quoted('new.txt')), (3, quoted("it's.txt")),
                                            (4, quoted('week')), (5, quoted('gone-long-ago.txt'))],
                            'other.com': [(9, quoted('old.txt'))]})
        st.clean_fm_trash(home, 30, False, self.log.append, db)
        self.assertEqual(sorted(db.deleted), [1, 3, 5], 'deleted items and records without a file are dropped')
        self.assertEqual([r[0] for r in db.data['example.com']], [2, 4])
        self.assertEqual(db.data['other.com'], [(9, quoted('old.txt'))], 'another website is untouched')
        self.assertIn('3 restore record(s) removed', self.log[-1])

    def test_database_failure_is_logged_not_fatal(self):
        home = self.site()
        self.fill(home)

        class Broken(FakeTrashRows):
            def rows(self, domain):
                raise RuntimeError('database is down')
        st.clean_fm_trash(home, 0, False, self.log.append, Broken({}))
        self.assertEqual(os.listdir(os.path.join(home, '.trash')), [])
        self.assertTrue(any('database is down' in line for line in self.log))

    def test_symlinked_trash_is_refused(self):
        outside = os.path.join(self.root, 'precious')
        make(os.path.join(outside, 'data.db'), age_days=90)
        home = os.path.join(self.root, 'home', 'evil.com')
        os.makedirs(home)
        os.symlink(outside, os.path.join(home, '.trash'))
        with self.assertRaises(st.CleanError):
            st.clean_fm_trash(home, 0, False, self.log.append, FakeTrashRows({}))
        with mock.patch.object(st, 'site_homes', return_value=[home]):
            self.assertEqual(st.probe_fm_trash()['items'], [])
            st.run_fm_trash(False, self.log.append, db=FakeTrashRows({}))
        self.assertTrue(os.path.exists(os.path.join(outside, 'data.db')))

    def test_symlinks_inside_trash_are_removed_as_links(self):
        outside = os.path.join(self.root, 'precious')
        make(os.path.join(outside, 'data.db'))
        make(os.path.join(self.root, 'secret.txt'))
        home = self.site()
        trash = os.path.join(home, '.trash')
        os.symlink(outside, os.path.join(trash, 'dirlink'))
        os.makedirs(os.path.join(trash, 'folder'))
        os.symlink(outside, os.path.join(trash, 'folder', 'nested-link'))
        os.symlink(os.path.join(self.root, 'secret.txt'), os.path.join(trash, 'filelink'))
        st.clean_fm_trash(home, 0, False, self.log.append, FakeTrashRows({}))
        self.assertEqual(os.listdir(trash), [])
        self.assertTrue(os.path.exists(os.path.join(outside, 'data.db')))
        self.assertTrue(os.path.exists(os.path.join(self.root, 'secret.txt')))

    def test_remove_at_refuses_unsafe_names(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for name in ('', '.', '..', 'a/b'):
                with self.assertRaises(st.CleanError):
                    st.remove_at(fd, name, os.fstat(fd).st_dev)
        finally:
            os.close(fd)

    def test_probe_output(self):
        homes = []
        for n in range(st.TRASH_TOP_SITES + 2):
            home = self.site('site%02d.com' % n)
            make(os.path.join(home, '.trash', 'f.bin'), (n + 1) * 8192, age_days=40 if n % 2 else 1)
            homes.append(home)
        homes.append(os.path.join(self.root, 'home', 'empty.com'))
        os.makedirs(os.path.join(homes[-1], '.trash'))
        with mock.patch.object(st, 'site_homes', return_value=homes):
            probe = st.probe_fm_trash()
        self.assertEqual(probe['count'], st.TRASH_TOP_SITES + 2)
        self.assertEqual(probe['choices'], [0, 7, 30])
        self.assertEqual(probe['days'], 0)
        self.assertEqual(probe['kb'], probe['by_days']['0']['kb'])
        self.assertEqual(probe['by_days']['30']['count'], (st.TRASH_TOP_SITES + 2) // 2)
        self.assertLess(probe['by_days']['30']['kb'], probe['by_days']['0']['kb'])
        self.assertLess(probe['oldest'], time.time() - 39 * DAY)
        self.assertEqual(len(probe['items']), st.TRASH_TOP_SITES, 'top 20 websites')
        self.assertTrue(probe['items'][0]['path'].endswith('site21.com/.trash'), 'biggest first')
        sizes = [i['kb'] for i in probe['items']]
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        self.assertIn('1 item(s), oldest', probe['items'][0]['note'])
        self.assertIn('22 websites have trash', probe['note'])

    def test_run_restricts_to_picked_sites_and_validates_days(self):
        a, b = self.site('a.com'), self.site('b.com')
        make(os.path.join(a, '.trash', 'x'))
        make(os.path.join(b, '.trash', 'y'))
        with mock.patch.object(st, 'site_homes', return_value=[a, b]):
            with self.assertRaises(st.CleanError):
                st.run_fm_trash(False, self.log.append, days=3, db=FakeTrashRows({}))
            st.run_fm_trash(False, self.log.append, items=[os.path.join(b, '.trash'), '/etc'], db=FakeTrashRows({}))
        self.assertEqual(os.listdir(os.path.join(a, '.trash')), ['x'])
        self.assertEqual(os.listdir(os.path.join(b, '.trash')), [])


class MailTrash(TrashBase):
    def mailbox(self, domain, user, folder, ages):
        path = os.path.join(self.root, 'vmail', domain, user, 'Maildir', '.' + folder)
        for n, days in enumerate(ages):
            make(os.path.join(path, 'cur' if n % 2 else 'new', '%d.M1P1.host:2,S' % n), 8192, age_days=days)
        return path

    def runner(self, mailboxes=('INBOX', 'INBOX.Trash', 'INBOX.Junk', 'INBOX.Junk E-mail')):
        calls = []

        def fake(argv, **kwargs):
            calls.append(argv)
            if argv[:3] == ['doveadm', 'mailbox', 'list']:
                return SimpleNamespace(returncode=0, stdout='\n'.join(mailboxes) + '\n')
            return SimpleNamespace(returncode=0, stdout='')
        return fake, calls

    def test_doveadm_command(self):
        self.assertEqual(st.doveadm_expunge_argv('info@example.com', 'INBOX.Trash', 30),
                         ['doveadm', 'expunge', '-u', 'info@example.com', 'mailbox', 'INBOX.Trash', 'savedbefore', '30d'])
        for bad in (0, -1, True, '30', 7.5):
            with self.assertRaises(st.CleanError):
                st.doveadm_expunge_argv('info@example.com', 'INBOX.Trash', bad)

    def test_mailbox_name_follows_the_namespace(self):
        fake, _ = self.runner()
        self.assertEqual(st.dovecot_mailbox_name('a@b.c', 'Trash', fake), 'INBOX.Trash')
        self.assertEqual(st.dovecot_mailbox_name('a@b.c', 'Junk E-mail', fake), 'INBOX.Junk E-mail')
        fake, _ = self.runner(('INBOX', 'Trash', 'Junk'))
        self.assertEqual(st.dovecot_mailbox_name('a@b.c', 'Trash', fake), 'Trash')
        with self.assertRaises(st.CleanError):
            st.dovecot_mailbox_name('a@b.c', 'Spam', fake)

    def test_run_uses_doveadm_expunge_and_never_deletes_files(self):
        trash = self.mailbox('example.com', 'info', 'Trash', [40, 40, 2])
        junk = self.mailbox('example.com', 'info', 'Junk', [60])
        other = self.mailbox('example.com', 'sales', 'Trash', [90])
        fake, calls = self.runner()
        root = os.path.join(self.root, 'vmail')
        with mock.patch.object(st, 'have', return_value=True):
            st.run_mail_trash(False, self.log.append, items=[trash, junk, '/home/vmail/../etc'], days=30,
                              runner=fake, root=root)
        expunges = [c for c in calls if c[1] == 'expunge']
        self.assertEqual(expunges, [
            ['doveadm', 'expunge', '-u', 'info@example.com', 'mailbox', 'INBOX.Trash', 'savedbefore', '30d'],
            ['doveadm', 'expunge', '-u', 'info@example.com', 'mailbox', 'INBOX.Junk', 'savedbefore', '30d']])
        self.assertFalse(any('sales@example.com' in c for c in calls), 'unpicked mailbox untouched')
        self.assertEqual(len(st.maildir_messages(trash)), 3, 'files are left to Dovecot')
        self.assertEqual(len(st.maildir_messages(other)), 1)

    def test_dry_run_and_nothing_picked_call_nothing(self):
        trash = self.mailbox('example.com', 'info', 'Trash', [40, 2])
        fake, calls = self.runner()
        root = os.path.join(self.root, 'vmail')
        self.assertEqual(st.run_mail_trash(False, self.log.append, items=None, runner=fake, root=root), 0)
        estimate = st.run_mail_trash(True, self.log.append, items=[trash], days=30, runner=fake, root=root)
        self.assertEqual(calls, [])
        self.assertEqual(estimate, 8)
        with mock.patch.object(st, 'have', return_value=False):
            with self.assertRaises(st.CleanError):
                st.run_mail_trash(False, self.log.append, items=[trash], runner=fake, root=root)

    def test_probe_output(self):
        self.mailbox('example.com', 'info', 'Trash', [40, 40, 2])
        self.mailbox('example.com', 'info', 'Junk', [100, 100, 100, 100])
        self.mailbox('example.com', 'empty', 'Trash', [])
        os.makedirs(os.path.join(self.root, 'vmail', 'example.com', 'info', 'Maildir', '.Sent', 'cur'))
        make(os.path.join(self.root, 'vmail', 'example.com', 'info', 'Maildir', '.Sent', 'cur', '1'), age_days=400)
        probe = st.probe_mail_trash(os.path.join(self.root, 'vmail'))
        self.assertEqual(probe['days'], 30)
        self.assertEqual(probe['choices'], [7, 30, 90])
        self.assertEqual(probe['count'], 6, 'two recent Trash messages and the Sent folder excluded')
        self.assertEqual(probe['kb'], 6 * 8)
        self.assertEqual(probe['by_days']['90']['count'], 4)
        self.assertEqual([os.path.basename(i['path']) for i in probe['items']], ['.Junk', '.Trash'])
        self.assertIn('info@example.com Junk: 4 message(s), oldest', probe['items'][0]['note'])
        self.assertEqual(probe['items'][1]['by_days']['7']['count'], 2)

    def test_symlinked_maildir_is_skipped(self):
        outside = os.path.join(self.root, 'elsewhere')
        make(os.path.join(outside, '.Trash', 'cur', '1'), age_days=90)
        user = os.path.join(self.root, 'vmail', 'example.com', 'info')
        os.makedirs(user)
        os.symlink(outside, os.path.join(user, 'Maildir'))
        self.assertEqual(st.mail_trash_folders(os.path.join(self.root, 'vmail')), [])


class DesktopTrash(TrashBase):
    def trash(self, home, name, deleted_days_ago, size=4096):
        base = os.path.join(home, '.local', 'share', 'Trash')
        make(os.path.join(base, 'files', name), size)
        stamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - deleted_days_ago * DAY))
        make(os.path.join(base, 'info', name + '.trashinfo'))
        with open(os.path.join(base, 'info', name + '.trashinfo'), 'w') as handle:
            handle.write('[Trash Info]\nPath=/root/%s\nDeletionDate=%s\n' % (name, stamp))
        return base

    def test_age_from_trashinfo_and_info_removed(self):
        home = os.path.join(self.root, 'root')
        base = self.trash(home, 'old.iso', 40)
        self.trash(home, 'new.iso', 1)
        probe = st.probe_desktop_trash([home])
        self.assertEqual(probe['count'], 2)
        self.assertEqual(probe['by_days']['30']['count'], 1)
        st.run_desktop_trash(False, self.log.append, days=30, homes=[home])
        self.assertEqual(os.listdir(os.path.join(base, 'files')), ['new.iso'])
        self.assertEqual(os.listdir(os.path.join(base, 'info')), ['new.iso.trashinfo'])

    def test_symlinked_local_is_refused(self):
        outside = os.path.join(self.root, 'etc-like')
        make(os.path.join(outside, 'share', 'Trash', 'files', 'passwd'))
        home = os.path.join(self.root, 'home', 'bob')
        os.makedirs(home)
        os.symlink(outside, os.path.join(home, '.local'))
        self.assertEqual(st.probe_desktop_trash([home])['items'], [])
        with self.assertRaises(st.CleanError):
            st.clean_desktop_trash(home, 0, False, self.log.append)
        st.run_desktop_trash(False, self.log.append, homes=[home])
        self.assertTrue(os.path.exists(os.path.join(outside, 'share', 'Trash', 'files', 'passwd')))


class Registry(unittest.TestCase):
    def test_categories_and_risk(self):
        table = {c[0]: c for c in st.CATEGORIES}
        for cid in ('trash', 'mail_trash', 'desktop_trash'):
            self.assertEqual(table[cid][2], 'review', cid)
            self.assertIn(cid, st.CATEGORY_IDS)
        self.assertTrue(table['mail_trash'][5], 'mailboxes are picked one by one')
        self.assertEqual(st.day_choices('trash'), (0, 7, 30))
        self.assertIsNone(st.day_choices('tmp_files'))
        for title in (c[1] for c in st.CATEGORIES):
            self.assertNotIn('CyberPanel', title)


class TrashViews(SimpleTestCase):
    def post(self, body):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1}), \
                mock.patch('universalAddons.privileged.call', return_value={'job_id': 'j'}) as call:
            response = views.clean(request)
        return response.status_code, call

    def test_days_validation(self):
        for body in ({'sel_trash': True, 'days_trash': 3}, {'sel_trash': True, 'days_trash': '7'},
                     {'sel_trash': True, 'days_trash': True}, {'sel_tmp_files': True, 'days_tmp_files': 7},
                     {'sel_mail_trash': ['/home/vmail/a.com/b/Maildir/.Trash'], 'days_mail_trash': 0}):
            status, call = self.post(body)
            self.assertEqual(status, 400, body)
            call.assert_not_called()
        status, call = self.post({'sel_trash': True, 'days_trash': 7, 'days_desktop_trash': 30,
                                  'sel_mail_trash': ['/home/vmail/a.com/b/Maildir/.Junk E-mail'], 'days_mail_trash': 90})
        self.assertEqual(status, 200)
        call.assert_called_once_with('storage', 'clean', dry_run=False,
                                     selection={'trash': True, 'mail_trash': ['/home/vmail/a.com/b/Maildir/.Junk E-mail']},
                                     options={'trash': {'days': 7}, 'mail_trash': {'days': 90}})


class CleanRunOptions(unittest.TestCase):
    def test_days_reach_the_category(self):
        from universalAddons.storage import actions
        seen = {}

        def fake_run(dry_run, log, items=None, **kwargs):
            seen.update(kwargs, items=items, dry_run=dry_run)
            return 0
        categories = [('trash', 'File manager trash', 'review', None, fake_run, False)]
        tmp = tempfile.mkdtemp()

        def run_job(job_id, steps):
            job = SimpleNamespace(log=lambda text: None)
            return {name: fn(job) for name, fn in steps}
        try:
            with mock.patch.object(st, 'CATEGORIES', categories), \
                    mock.patch.object(actions.jobs, 'run_job', run_job), \
                    mock.patch.object(actions.time, 'strftime', return_value='x'), \
                    mock.patch('builtins.open', mock.mock_open()):
                actions.clean_run('j', {'trash': True}, dry_run=True, options={'trash': {'days': 7}})
        finally:
            shutil.rmtree(tmp)
        self.assertEqual(seen, {'days': 7, 'items': None, 'dry_run': True})


if __name__ == '__main__':
    unittest.main()
