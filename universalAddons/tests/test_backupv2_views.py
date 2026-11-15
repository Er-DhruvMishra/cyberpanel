import json
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons.backupv2 import views
from universalAddons.tests import helpers


class BackupViews(SimpleTestCase):
    def post(self, view, body, is_admin=1):
        return helpers.post(view, body, admin=bool(is_admin))[:2]

    def test_admin_only(self):
        for name in ('overview', 'save_repo', 'export_key', 'ssh_key', 'save_policy', 'delete_policy', 'run_now',
                     'snapshots', 'ls', 'restore', 'check', 'job'):
            with mock.patch('universalAddons.privileged.call') as call:
                self.assertEqual(self.post(getattr(views, name), {}, is_admin=0)[0], 403, name)
            call.assert_not_called()

    def test_save_repo_forwards_known_fields_and_secrets_separately(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.post(views.save_repo, {'id': 's3', 'type': 's3', 'bucket': 'b', 'accessKey': 'AK', 'secretKey': 'SK',
                                        'junk': 'x'})
        args = call.call_args[1]
        self.assertEqual(args['spec'], {'id': 's3', 'type': 's3', 'bucket': 'b'})
        self.assertEqual((args['access_key'], args['secret_key']), ('AK', 'SK'))

    def test_restore_validation(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'j'}) as call:
            for body in ({'repo': 'r', 'snapshot': 'zz', 'domain': 'a.com', 'kind': 'files'},
                         {'repo': 'r', 'snapshot': 'abcdef12', 'domain': 'a.com', 'kind': 'everything'},
                         {'repo': 'r', 'snapshot': 'abcdef12', 'domain': 'a.com', 'kind': 'files', 'target': 'relative'},
                         {'repo': 'R!', 'snapshot': 'abcdef12', 'domain': 'a.com', 'kind': 'files'}):
                self.assertEqual(self.post(views.restore, body)[0], 400, body)
            call.assert_not_called()
            self.post(views.restore, {'repo': 'r', 'snapshot': 'abcdef12', 'domain': 'A.com', 'kind': 'db',
                                      'database': 'wp'})
        self.assertEqual(call.call_args[1]['domain'], 'a.com')

    def test_policy_keep_values_collected(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.post(views.save_policy, {'id': 'n', 'repo': 'r', 'units': ['files'], 'schedule': 'daily',
                                          'keep_daily': 7, 'keep_weekly': '', 'keep_monthly': 0})
        self.assertEqual(call.call_args[1]['spec']['keep'], {'daily': 7})
