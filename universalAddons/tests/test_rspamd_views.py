import json
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons.rspamd import views


class RspamdViews(SimpleTestCase):
    def post(self, view, body, is_admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': is_admin}):
            response = view(request)
        return response.status_code, json.loads(response.content)

    def test_admin_only(self):
        for name in ('detect', 'plan', 'filtering', 'apply', 'install', 'migrate_dkim', 'stats', 'log', 'learn', 'job'):
            with mock.patch('universalAddons.privileged.call') as call:
                self.assertEqual(self.post(getattr(views, name), {}, is_admin=0)[0], 403, name)
            call.assert_not_called()

    def test_apply_forwards_only_known_flat_keys(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.post(views.apply, {'reject': 12, 'allow_list': ['a.com'], 'evil': 'x', 'settings': {'reject': 1}})
        call.assert_called_once_with('rspamd', 'apply', settings={'reject': 12, 'allow_list': ['a.com']})

    def test_filtering_requires_explicit_boolean(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.assertEqual(self.post(views.filtering, {'enable': 'yes'})[0], 400)
            call.assert_not_called()
            self.post(views.filtering, {'enable': False})
        call.assert_called_once_with('rspamd', 'filtering', enable=False, replace_spamassassin=False)

    def test_learn_validation(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'x'}) as call:
            self.assertEqual(self.post(views.learn, {'kind': 'spam', 'folder': '../x', 'mailbox': 'a@b.com'})[0], 400)
            self.assertEqual(self.post(views.learn, {'kind': 'spam', 'folder': 'Junk', 'mailbox': 'bad'})[0], 400)
            self.post(views.learn, {'kind': 'ham', 'folder': 'INBOX', 'mailbox': 'Bob@Example.com'})
        call.assert_called_once_with('rspamd', 'learn', kind='ham', domain='example.com', user='bob', folder='INBOX')

    def test_job_id_validated(self):
        with mock.patch('universalAddons.privileged.call') as call:
            self.assertEqual(self.post(views.job, {'job': '../../etc'})[0], 400)
        call.assert_not_called()
