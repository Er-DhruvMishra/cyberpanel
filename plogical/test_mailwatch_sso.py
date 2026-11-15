import hashlib
import json
import os
import tempfile
import time
import unittest

from plogical import mailwatchSSO as sso


class MailWatchSSO(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_ticket_file_named_by_hash_never_by_token(self):
        token = sso.issue('admin', self.dir)
        name = hashlib.sha256(token.encode()).hexdigest() + '.json'
        self.assertEqual(os.listdir(self.dir), [name])
        record = json.load(open(os.path.join(self.dir, name)))
        self.assertEqual((record['user'], record['panel_user']), ('admin', 'admin'))
        self.assertGreater(record['expires'], time.time())
        self.assertEqual(oct(os.stat(os.path.join(self.dir, name)).st_mode & 0o777), '0o640')

    def test_expired_and_foreign_files_pruned(self):
        old = os.path.join(self.dir, 'a' * 64 + '.json')
        open(old, 'w').close()
        os.utime(old, (time.time() - 600, time.time() - 600))
        open(os.path.join(self.dir, 'junk'), 'w').close()
        sso.issue('admin', self.dir)
        self.assertEqual(len(os.listdir(self.dir)), 1)

    def test_missing_directory_is_a_clear_error(self):
        with self.assertRaises(sso.SSOError):
            sso.issue('admin', os.path.join(self.dir, 'nope'))

    def test_handoff_posts_the_token(self):
        page = sso.handoff_page('tok_EN')
        self.assertIn('method="post"', page)
        self.assertIn('name="cp_sso" value="tok_EN"', page)
        self.assertNotIn('?', page.split('action="')[1].split('"')[0])


if __name__ == '__main__':
    unittest.main()
