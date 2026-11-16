"""Refresh of Drive accounts connected with the panel's own OAuth client (mocked, no Google access)."""
import copy
from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from plogical import gdriveClient
from plogical.gdriveRefresh import PANEL_CLIENT_VERSION, connection_kind, drive_credentials

CLIENT_ID = 'panel.apps.googleusercontent.com'
SECRET = 'SYNTHETIC-PANEL-SECRET'


class FakeCredentials:
    calls = []
    fail = False

    def __init__(self, token, refresh_token=None, token_uri=None, client_id=None, client_secret=None, scopes=None, expiry=None):
        self.token, self.refresh_token, self.expiry = token, refresh_token, expiry
        self.client_id, self.client_secret, self.token_uri = client_id, client_secret, token_uri

    @property
    def expired(self):
        return self.expiry is not None and self.expiry < datetime.utcnow()

    def refresh(self, request):
        type(self).calls.append((self.token_uri, self.client_id, self.client_secret, self.refresh_token))
        if self.fail:
            raise RuntimeError('SYNTHETIC-NETWORK-DETAIL')
        self.token = 'synthetic-refreshed'
        self.expiry = datetime.utcnow() + timedelta(hours=1)


class PanelClientRefreshTests(unittest.TestCase):
    def setUp(self):
        FakeCredentials.calls, FakeCredentials.fail = [], False
        self.google = patch.dict('sys.modules', {
            'google': types.ModuleType('google'), 'google.oauth2': types.ModuleType('google.oauth2'),
            'google.oauth2.credentials': types.SimpleNamespace(Credentials=FakeCredentials),
            'google.auth': types.ModuleType('google.auth'), 'google.auth.transport': types.ModuleType('google.auth.transport'),
            'google.auth.transport.requests': types.SimpleNamespace(Request=Mock(return_value=object())),
        })
        self.google.start()
        self.addCleanup(self.google.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, 'gdrive-oauth.json')
        path_patch = patch.object(gdriveClient, 'CONFIG_PATH', self.path)
        path_patch.start()
        self.addCleanup(path_patch.stop)
        gdriveClient.save_client(CLIENT_ID, SECRET)
        self.auth = {'token': 'synthetic-old', 'refresh_token': 'synthetic-refresh',
                     'token_uri': 'https://oauth2.googleapis.com/token',
                     'scopes': ['https://www.googleapis.com/auth/drive.file'], 'client_id': CLIENT_ID,
                     'expiry': '2020-01-01T00:00:00Z', 'handoff_version': PANEL_CLIENT_VERSION,
                     'folderIDIP': 'keep-folder', 'FileRetentiontime': '1w'}

    def test_refresh_uses_client_file_and_google_only(self):
        before = copy.deepcopy(self.auth)
        with patch('plogical.gdriveRefresh.legacy_access_token') as vendor:
            credentials, result = drive_credentials(self.auth)
        vendor.assert_not_called()
        self.assertEqual(FakeCredentials.calls, [('https://oauth2.googleapis.com/token', CLIENT_ID, SECRET, 'synthetic-refresh')])
        self.assertEqual(result['token'], 'synthetic-refreshed')
        self.assertEqual(result['folderIDIP'], 'keep-folder')
        self.assertNotIn('client_secret', result, 'the secret stays in the client file')
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(self.auth, before)
        self.assertEqual(connection_kind(result), 'panel')

    def test_missing_or_changed_client_means_reconnect_never_vendor(self):
        for setup in ('missing', 'changed', 'secret-in-record'):
            with self.subTest(setup=setup):
                auth = copy.deepcopy(self.auth)
                if setup == 'missing':
                    gdriveClient.clear_client()
                elif setup == 'changed':
                    gdriveClient.save_client('other.apps.googleusercontent.com', SECRET)
                else:
                    auth['client_secret'] = SECRET
                with patch('plogical.gdriveRefresh.legacy_access_token') as vendor:
                    with self.assertRaisesRegex(ValueError, '^Google Drive authorization failed$'):
                        drive_credentials(auth, force_refresh=True)
                vendor.assert_not_called()
                gdriveClient.save_client(CLIENT_ID, SECRET)

    def test_google_failure_is_redacted(self):
        FakeCredentials.fail = True
        with self.assertRaises(ValueError) as caught:
            drive_credentials(self.auth)
        self.assertNotIn('SYNTHETIC', str(caught.exception))

    def test_vendor_connected_accounts_still_use_vendor_refresh(self):
        legacy = {key: self.auth[key] for key in ('token', 'refresh_token', 'token_uri', 'scopes')}
        self.assertEqual(connection_kind(legacy), 'vendor')
        with patch('plogical.gdriveRefresh.legacy_access_token', return_value='vendor-new') as vendor:
            _, result = drive_credentials(legacy, force_refresh=True)
        vendor.assert_called_once_with('synthetic-refresh')
        self.assertEqual(result['token'], 'vendor-new')


class InstalledGoogleAuthPanelClientTests(unittest.TestCase):
    def test_real_google_auth_posts_panel_client_to_google(self):
        try:
            from google.auth.transport.requests import Request  # noqa: F401
        except ImportError:
            self.skipTest('google-auth not installed')
        calls = []

        def transport(**kwargs):
            calls.append(kwargs)
            return types.SimpleNamespace(status=200, headers={}, data=json.dumps({
                'access_token': 'synthetic-real-lib', 'expires_in': 3600, 'token_type': 'Bearer'}).encode())

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'gdrive-oauth.json')
            gdriveClient.save_client(CLIENT_ID, SECRET, path=path)
            auth = {'token': 'old', 'refresh_token': 'synthetic-refresh', 'token_uri': 'https://oauth2.googleapis.com/token',
                    'scopes': ['https://www.googleapis.com/auth/drive.file'], 'client_id': CLIENT_ID,
                    'expiry': '2020-01-01T00:00:00Z', 'handoff_version': PANEL_CLIENT_VERSION}
            with patch.object(gdriveClient, 'CONFIG_PATH', path), \
                    patch('google.auth.transport.requests.Request', return_value=transport), \
                    patch('plogical.gdriveRefresh.legacy_access_token') as vendor:
                _, result = drive_credentials(auth)
        vendor.assert_not_called()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['url'], 'https://oauth2.googleapis.com/token')
        body = calls[0]['body']
        body = parse_qs(body.decode() if isinstance(body, bytes) else body)
        self.assertEqual(body['client_id'], [CLIENT_ID])
        self.assertEqual(body['client_secret'], [SECRET])
        self.assertEqual(body['grant_type'], ['refresh_token'])
        self.assertEqual(result['token'], 'synthetic-real-lib')
        self.assertNotIn('client_secret', result)


class ClientFileTests(unittest.TestCase):
    def test_file_is_0600_and_written_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'gdrive-oauth.json')
            gdriveClient.save_client(CLIENT_ID, SECRET, path=path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.listdir(directory), ['gdrive-oauth.json'])
            self.assertEqual(gdriveClient.load_client(path), {'client_id': CLIENT_ID, 'client_secret': SECRET})
            status = gdriveClient.public_status(path)
            self.assertEqual(status, {'configured': True, 'client_id': CLIENT_ID, 'client_secret': 'set', 'error': ''})
            self.assertNotIn(SECRET, json.dumps(status))


if __name__ == '__main__':
    unittest.main()
