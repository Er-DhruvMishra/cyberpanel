"""Normal Google Drive backups: direct Google connection and GDrive record storage (synthetic only)."""
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.db import connection, models
from django.test import TransactionTestCase
from IncBackups import test_gdrive_oauth as base_tests
from IncBackups import gdrive_oauth as flow
from plogical import gdriveClient


class NormalFlowTests(base_tests.FlowTests):
    mode = 'normal'
    path = '/backup/gDriveSetup'

    def begin_body(self):
        return {'accountName': 'new-account'}

    def install_target(self):
        return '_install_normal'

    def check_install(self, user_id, account, credentials):
        self.assertEqual((user_id, account), (7, 'new-account'))
        self.assertNotIn('client_secret', credentials)
        self.assertEqual(credentials['client_id'], base_tests.CLIENT['client_id'])
        self.assertEqual(credentials['token_uri'], 'https://oauth2.googleapis.com/token')

    def test_name_owned_by_another_user_is_refused_before_google(self):
        self._account_owner_mock.return_value = 99
        result = flow.begin(self.request('POST', self.begin_body()), mode='normal')
        self.assertEqual(result.status_code, 409)
        self.assertNotIn(flow.SESSION_KEY, self.session)

    def test_own_existing_name_is_a_reconnect(self):
        self._account_owner_mock.return_value = 7
        state = self.state_of(self.start())
        self.assertTrue(self.session[flow.SESSION_KEY][state]['reconnect'])
        page = self.complete({'state': state, 'code': '4/synthetic-code'}, method='GET')
        self.assertIn('Reconnect', page.content.decode())

    def test_normal_name_limit(self):
        result = flow.begin(self.request('POST', {'accountName': 'a' * 51}), mode='normal')
        self.assertEqual(result.status_code, 400)

    def test_normal_state_cannot_be_used_as_v2(self):
        state = self.state_of(self.start())
        with mock.patch.object(flow.requests, 'post') as network:
            request = self.request('POST', {'state': state, 'code': '4/synthetic-code'},
                                   path='/IncrementalBackups/ConfigureV2BackupSetup')
            self.assertEqual(flow.complete(request, mode='v2').status_code, 400)
        network.assert_not_called()


class NormalAccessTests(base_tests.AccessTests):
    def test_normal_not_paid_and_no_website_required(self):
        self.acl.CheckForPremFeature.return_value = 0
        flow._check_access(self.request, None, 'normal')
        self.acl.CheckForPremFeature.assert_not_called()
        self.acl.checkOwnership.assert_not_called()
        self.acl.currentContextPermission.return_value = 0
        with self.assertRaises(flow.AccessDenied):
            flow._check_access(self.request, None, 'normal')


class FixtureDrive(models.Model):
    owner_id = models.IntegerField()
    name = models.CharField(max_length=50, unique=True)
    auth = models.TextField()
    runTime = models.CharField(max_length=20, default='NEVER')

    class Meta:
        app_label = 'qa_handoff'
        db_table = 'qa_normal_drive_fixture'


class NormalPersistenceTests(TransactionTestCase):
    def setUp(self):
        with connection.schema_editor() as editor:
            editor.create_model(FixtureDrive)
        self.modules = mock.patch.dict(sys.modules, {'websiteFunctions.models': SimpleNamespace(GDrive=FixtureDrive)})
        self.modules.start()
        self.credentials = {'token': 'SYNTHETIC', 'refresh_token': 'SYNTHETIC-R', 'expiry': '2030-01-01T00:00:00Z',
                            'token_uri': 'https://oauth2.googleapis.com/token', 'scopes': [flow.SCOPE],
                            'client_id': 'synthetic.apps.googleusercontent.com'}

    def tearDown(self):
        self.modules.stop()
        with connection.schema_editor() as editor:
            editor.delete_model(FixtureDrive)

    def test_insert_stores_panel_client_record_without_secret(self):
        flow._install_normal(7, 'new-account', dict(self.credentials, client_secret='MUST-NOT-STORE'))
        added = FixtureDrive.objects.get(name='new-account')
        self.assertEqual((added.owner_id, added.runTime), (7, 'NEVER'))
        self.assertEqual(json.loads(added.auth), dict(self.credentials, handoff_version=3))
        self.assertNotIn('MUST-NOT-STORE', added.auth)

    def test_other_users_record_is_never_updated(self):
        old = FixtureDrive.objects.create(owner_id=8, name='existing', auth='EXACT-OLD-BYTES', runTime='Daily')
        with self.assertRaises(Exception):
            flow._install_normal(7, 'existing', self.credentials)
        old.refresh_from_db()
        self.assertEqual((old.owner_id, old.auth, old.runTime), (8, 'EXACT-OLD-BYTES', 'Daily'))

    def test_reconnect_keeps_schedule_and_retention(self):
        legacy = {'token': 'old', 'refresh_token': 'old-r', 'token_uri': 'https://oauth2.googleapis.com/token',
                  'scopes': [flow.SCOPE], 'folderIDIP': 'vendor-folder', 'FileRetentiontime': '1w'}
        FixtureDrive.objects.create(owner_id=7, name='mine', auth=json.dumps(legacy), runTime='Daily')
        self.assertEqual(flow._install_normal(7, 'mine', self.credentials), 'reconnected')
        row = FixtureDrive.objects.get(name='mine')
        auth = json.loads(row.auth)
        self.assertEqual(row.runTime, 'Daily')
        self.assertEqual(auth['FileRetentiontime'], '1w')
        self.assertEqual(auth['token'], 'SYNTHETIC')
        self.assertNotIn('folderIDIP', auth, 'a new client cannot see the vendor-created folder (drive.file)')
        auth['folderIDIP'] = 'own-folder'
        row.auth = json.dumps(auth)
        row.save()
        flow._install_normal(7, 'mine', dict(self.credentials, token='NEWER'))
        self.assertEqual(json.loads(FixtureDrive.objects.get(name='mine').auth)['folderIDIP'], 'own-folder')
        self.assertEqual(FixtureDrive.objects.count(), 1)

    def test_account_states_flag_vendor_and_reconnect(self):
        FixtureDrive.objects.create(owner_id=7, name='a-vendor', auth=json.dumps({'token': 't', 'refresh_token': 'r'}))
        FixtureDrive.objects.create(owner_id=7, name='b-panel', auth=json.dumps(dict(self.credentials, handoff_version=3)))
        FixtureDrive.objects.create(owner_id=7, name='c-failed', auth=json.dumps(dict(self.credentials, handoff_version=3,
                                                                                    auth_failed=1)))
        FixtureDrive.objects.create(owner_id=8, name='d-other', auth='{}')
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'client.json')
            gdriveClient.save_client(self.credentials['client_id'], 'SYNTHETIC-SECRET', path=path)
            with mock.patch.object(gdriveClient, 'CONFIG_PATH', path):
                states = flow._account_states(7)
                self.assertEqual([(x['name'], x['connection'], x['reconnect']) for x in states],
                                 [('a-vendor', 'vendor', False), ('b-panel', 'panel', False), ('c-failed', 'panel', True)])
                gdriveClient.save_client('other.apps.googleusercontent.com', 'SYNTHETIC-SECRET', path=path)
                self.assertTrue(flow._account_states(7)[1]['reconnect'], 'client changed: reconnect needed')
