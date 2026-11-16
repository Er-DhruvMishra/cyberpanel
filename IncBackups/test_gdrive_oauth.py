"""Google Drive connection directly with Google. No real Google account or network is used."""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.test import RequestFactory, SimpleTestCase, override_settings
from django.template import Context, Engine
from IncBackups import gdrive_oauth as flow
from plogical import gdriveClient

CLIENT = {'client_id': 'synthetic.apps.googleusercontent.com', 'client_secret': 'SYNTHETIC-CLIENT-SECRET'}
HOST = 'panel.example.test:8090'


class Session(dict):
    session_key = 'synthetic-panel-session'
    modified = False

    def save(self):
        pass


def token_response(**overrides):
    body = {'access_token': 'SYNTHETIC-ACCESS', 'refresh_token': 'SYNTHETIC-REFRESH', 'expires_in': 3599,
            'token_type': 'Bearer', 'scope': flow.SCOPE}
    body.update(overrides)
    response = mock.Mock(status_code=200)
    response.json.return_value = body
    return response


@override_settings(SESSION_ENGINE='django.contrib.sessions.backends.db')
class FlowTests(SimpleTestCase):
    mode = 'v2'
    path = '/IncrementalBackups/ConfigureV2BackupSetup'

    def setUp(self):
        self.factory = RequestFactory()
        self.session = Session(userID=7)
        for name, value in (('_check_access', None), ('_client', dict(CLIENT)), ('_account_owner', None)):
            patcher = mock.patch.object(flow, name, return_value=value)
            setattr(self, name + '_mock', patcher.start())
            self.addCleanup(patcher.stop)

    def request(self, method, data=None, path=None):
        path = path or self.path
        if method == 'POST':
            req = self.factory.post(path, json.dumps(data or {}), content_type='application/json',
                                    HTTP_HOST=HOST, HTTP_ORIGIN='https://' + HOST, secure=True)
        else:
            req = self.factory.get(path, data or {}, HTTP_HOST=HOST, secure=True)
        req.session = self.session
        req._dont_enforce_csrf_checks = True
        return req

    def begin_body(self):
        return {'Selectedwebsite': 'owned.example', 'accountName': 'qa-drive'}

    def start(self):
        with mock.patch.object(flow.requests, 'post') as network, mock.patch.object(flow.requests, 'get') as get:
            result = flow.begin(self.request('POST', self.begin_body()), mode=self.mode)
        network.assert_not_called()
        get.assert_not_called()
        self.assertEqual(result.status_code, 200, result.content)
        data = json.loads(result.content)
        self.assertEqual(data['status'], 1)
        self.assertNotIn(CLIENT['client_secret'], result.content.decode())
        return data['authorization_url']

    def state_of(self, url):
        return parse_qs(urlsplit(url).query)['state'][0]

    def install_target(self):
        return '_install_backend'

    def complete(self, data, method='POST'):
        return flow.complete(self.request(method, data), mode=self.mode)

    # --- authorisation URL, state and PKCE -------------------------------------------------

    def test_authorization_url_goes_to_google_with_offline_consent_and_pkce(self):
        url = self.start()
        parts = urlsplit(url)
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ('https', 'accounts.google.com', '/o/oauth2/v2/auth'))
        query = {key: value[0] for key, value in parse_qs(parts.query).items()}
        self.assertEqual(query['client_id'], CLIENT['client_id'])
        self.assertEqual(query['redirect_uri'], 'https://' + HOST + self.path)
        self.assertEqual(query['response_type'], 'code')
        self.assertEqual(query['scope'], 'https://www.googleapis.com/auth/drive.file')
        self.assertEqual(query['access_type'], 'offline')
        self.assertEqual(query['prompt'], 'consent')
        self.assertEqual(query['code_challenge_method'], 'S256')
        self.assertNotIn('client_secret', query)
        record = self.session[flow.SESSION_KEY][query['state']]
        expected = base64.urlsafe_b64encode(hashlib.sha256(record['verifier'].encode()).digest()).decode().rstrip('=')
        self.assertEqual(query['code_challenge'], expected)
        self.assertNotIn(record['verifier'], url)

    def test_state_is_random_and_bound_to_session(self):
        first, second = self.state_of(self.start()), self.state_of(self.start())
        self.assertNotEqual(first, second)
        self.assertGreaterEqual(len(first), 43)
        self.assertEqual(self.session[flow.SESSION_KEY][first]['user_id'], 7)

    def test_unknown_state_is_rejected_without_network(self):
        self.start()
        with mock.patch.object(flow.requests, 'post') as network:
            result = self.complete({'state': 'x' * 43, 'code': '4/synthetic-code'})
        self.assertEqual(result.status_code, 400)
        network.assert_not_called()

    def test_switched_user_session_and_expiry_fail_before_exchange(self):
        for kind in ('user', 'session', 'expired'):
            with self.subTest(kind=kind):
                self.session = Session(userID=7)
                state = self.state_of(self.start())
                if kind == 'user':
                    self.session['userID'] = 8
                if kind == 'session':
                    self.session.session_key = 'different-session'
                if kind == 'expired':
                    self.session[flow.SESSION_KEY][state]['created'] -= flow.TTL + 1
                with mock.patch.object(flow.requests, 'post') as network:
                    result = self.complete({'state': state, 'code': '4/synthetic-code'})
                self.assertEqual(result.status_code, 400)
                network.assert_not_called()

    def test_csrf_required_for_post_endpoints(self):
        for function in (flow.begin, flow.complete, flow.client_settings):
            request = self.request('POST', {})
            request._dont_enforce_csrf_checks = False
            with self.subTest(function=function.__name__):
                result = function(request)
                self.assertEqual(result.status_code, 403)
                self.assertEqual(result['Cache-Control'], 'no-store')

    def test_null_or_foreign_origin_is_not_trusted(self):
        for origin in (None, 'null', 'https://attacker.example', 'http://' + HOST):
            request = self.request('POST', self.begin_body())
            if origin is None:
                request.META.pop('HTTP_ORIGIN')
            else:
                request.META['HTTP_ORIGIN'] = origin
            with self.subTest(origin=origin):
                self.assertEqual(flow.begin(request, mode=self.mode).status_code, 400)
        self.assertNotIn(flow.SESSION_KEY, self.session)

    def test_return_get_shows_confirmation_only(self):
        state = self.state_of(self.start())
        with mock.patch.object(flow.requests, 'post') as network, \
                mock.patch.object(flow, self.install_target()) as install:
            result = self.complete({'state': state, 'code': '4/synthetic-code', 'scope': flow.SCOPE,
                                    'authuser': '0', 'prompt': 'consent'}, method='GET')
        self.assertEqual(result.status_code, 200)
        self.assertIn('csrfmiddlewaretoken', result.content.decode())
        self.assertIn('IndiansCloud', result.content.decode())
        self.assertEqual(result['Referrer-Policy'], 'strict-origin')
        network.assert_not_called()
        install.assert_not_called()
        self.assertIn(state, self.session[flow.SESSION_KEY])

    def test_google_error_return_saves_nothing_and_consumes_state(self):
        state = self.state_of(self.start())
        with mock.patch.object(flow.requests, 'post') as network, \
                mock.patch.object(flow, self.install_target()) as install:
            result = self.complete({'state': state, 'error': 'access_denied'}, method='GET')
        self.assertEqual(result.status_code, 200)
        network.assert_not_called()
        install.assert_not_called()
        self.assertNotIn(state, self.session[flow.SESSION_KEY])

    def test_duplicate_or_unexpected_return_fields_rejected(self):
        state = self.state_of(self.start())
        request = self.factory.get(self.path + '?state=' + state + '&state=' + state + '&code=4/x' + 'c' * 20,
                                   HTTP_HOST=HOST, secure=True)
        request.session = self.session
        self.assertEqual(flow.complete(request, mode=self.mode).status_code, 400)
        self.assertEqual(self.complete({'state': state, 'code': '4/' + 'c' * 20, 'client_secret': 'x'},
                                       method='GET').status_code, 400)

    # --- token exchange (mocked) ------------------------------------------------------------

    def test_exchange_posts_code_verifier_and_client_to_google(self):
        self.exchange_once()

    def exchange_once(self):
        state = self.state_of(self.start())
        verifier = self.session[flow.SESSION_KEY][state]['verifier']
        with mock.patch.object(flow.requests, 'post', return_value=token_response()) as post, \
                mock.patch.object(flow, self.install_target()) as install:
            result = self.complete({'state': state, 'code': '4/synthetic-code'})
            again = self.complete({'state': state, 'code': '4/synthetic-code'})
        self.assertEqual(result.status_code, 200, result.content)
        self.assertEqual(again.status_code, 400, 'state is single use')
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], 'https://oauth2.googleapis.com/token')
        self.assertFalse(post.call_args.kwargs['allow_redirects'])
        sent = post.call_args.kwargs['data']
        self.assertEqual(sent, {'code': '4/synthetic-code', 'client_id': CLIENT['client_id'],
                                'client_secret': CLIENT['client_secret'], 'grant_type': 'authorization_code',
                                'redirect_uri': 'https://' + HOST + self.path, 'code_verifier': verifier})
        install.assert_called_once()
        self.assertNotIn('SYNTHETIC', result.content.decode())
        return install.call_args.args

    def test_exchange_result_is_validated(self):
        for overrides in ({'refresh_token': None}, {'scope': 'https://www.googleapis.com/auth/drive.readonly'},
                          {'expires_in': 'soon'}, {'token_type': 'mac'}, {'access_token': 'bad token'}):
            with self.subTest(overrides=overrides):
                self.session = Session(userID=7)
                state = self.state_of(self.start())
                with mock.patch.object(flow.requests, 'post', return_value=token_response(**overrides)), \
                        mock.patch.object(flow, self.install_target()) as install:
                    result = self.complete({'state': state, 'code': '4/synthetic-code'})
                self.assertEqual(result.status_code, 400)
                install.assert_not_called()

    def test_google_rejection_or_network_error_never_reflects_details(self):
        for side_effect in (RuntimeError('SECRET-DETAIL'), None):
            self.session = Session(userID=7)
            state = self.state_of(self.start())
            failed = mock.Mock(status_code=400)
            failed.json.return_value = {'error': 'invalid_grant', 'error_description': 'SECRET-DETAIL'}
            with mock.patch.object(flow.requests, 'post', side_effect=side_effect, return_value=failed), \
                    mock.patch.object(flow, self.install_target()) as install:
                result = self.complete({'state': state, 'code': '4/synthetic-code'})
            self.assertEqual(result.status_code, 400)
            self.assertNotIn('SECRET-DETAIL', result.content.decode())
            install.assert_not_called()

    def test_client_changed_between_start_and_return_fails(self):
        state = self.state_of(self.start())
        self._client_mock.return_value = {'client_id': 'other.apps.googleusercontent.com', 'client_secret': 'OTHER-SECRET'}
        with mock.patch.object(flow.requests, 'post') as network:
            self.assertEqual(self.complete({'state': state, 'code': '4/synthetic-code'}).status_code, 400)
        network.assert_not_called()

    def test_not_configured_client_blocks_start(self):
        self._client_mock.return_value = None
        result = flow.begin(self.request('POST', self.begin_body()), mode=self.mode)
        self.assertEqual(result.status_code, 503)
        self.assertIn('OAuth client', json.loads(result.content)['error_message'])
        self.assertFalse(flow.capability(self.mode)[0])

    def test_begin_and_callback_recheck_access(self):
        self._check_access_mock.side_effect = flow.AccessDenied
        self.assertEqual(flow.begin(self.request('POST', self.begin_body()), mode=self.mode).status_code, 403)
        self._check_access_mock.side_effect = None
        state = self.state_of(self.start())
        self._check_access_mock.side_effect = flow.AccessDenied
        with mock.patch.object(flow.requests, 'post') as network:
            self.assertEqual(self.complete({'state': state, 'code': '4/synthetic-code'}).status_code, 403)
        network.assert_not_called()

    @override_settings(SESSION_ENGINE='django.contrib.sessions.backends.signed_cookies')
    def test_cookie_session_must_not_hold_pkce_secret(self):
        self.assertEqual(flow.begin(self.request('POST', self.begin_body()), mode=self.mode).status_code, 503)

    def test_get_begin_not_allowed(self):
        self.assertEqual(flow.begin(self.request('GET'), mode=self.mode).status_code, 405)

    def test_pending_limit(self):
        import time
        self.session[flow.SESSION_KEY] = {str(i): {'created': time.time()} for i in range(4)}
        self.assertEqual(flow.begin(self.request('POST', self.begin_body()), mode=self.mode).status_code, 429)

    def test_browser_supplied_client_is_ignored(self):
        body = dict(self.begin_body(), client_id='attacker.apps.googleusercontent.com', client_secret='X')
        with mock.patch.object(flow.requests, 'post'):
            result = flow.begin(self.request('POST', body), mode=self.mode)
        query = parse_qs(urlsplit(json.loads(result.content)['authorization_url']).query)
        self.assertEqual(query['client_id'], [CLIENT['client_id']])


    def test_install_receives_expected_credentials(self):
        self.check_install(*self.exchange_once())

    def check_install(self, website, account, credentials):
        # v2 (incremental) remotes are refreshed by rclone, which needs the client secret.
        self.assertEqual((website, account), ('owned.example', 'qa-drive'))
        self.assertEqual(credentials['client_secret'], CLIENT['client_secret'])
        self.assertEqual(credentials['scopes'], [flow.SCOPE])
        self.assertEqual(credentials['refresh_token'], 'SYNTHETIC-REFRESH')


class ClientSettingsTests(SimpleTestCase):
    """The admin settings form: stored 0600, never echoes the secret."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, 'gdrive-oauth.json')
        patcher = mock.patch.object(gdriveClient, 'CONFIG_PATH', self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.admin = mock.patch.object(flow, '_is_admin', return_value=True)
        self.admin_mock = self.admin.start()
        self.addCleanup(self.admin.stop)
        self.factory = RequestFactory()

    def call(self, method, data=None):
        if method == 'POST':
            request = self.factory.post('/backup/gDriveOAuthClient', json.dumps(data), content_type='application/json',
                                        HTTP_HOST=HOST, HTTP_ORIGIN='https://' + HOST, secure=True)
        else:
            request = self.factory.get('/backup/gDriveOAuthClient', HTTP_HOST=HOST, secure=True)
        request.session = Session(userID=1)
        request._dont_enforce_csrf_checks = True
        return flow.client_settings(request)

    def test_secret_is_saved_privately_and_never_returned(self):
        with mock.patch.object(flow.requests, 'post') as network:
            saved = self.call('POST', CLIENT)
        network.assert_not_called()
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(Path(self.path).read_text()), CLIENT)
        shown = self.call('GET')
        for response in (saved, shown):
            body = response.content.decode()
            self.assertNotIn(CLIENT['client_secret'], body)
            data = json.loads(body)
            self.assertEqual(data['client_secret'], 'set')
            self.assertEqual(data['client_id'], CLIENT['client_id'])
            self.assertEqual(data['redirect_uris'], ['https://' + HOST + '/backup/gDriveSetup',
                                                     'https://' + HOST + '/IncrementalBackups/ConfigureV2BackupSetup',
                                                     'https://' + HOST + '/addons/destinations/oauth/gdrive/callback'])
            self.assertEqual(data['scope'], 'https://www.googleapis.com/auth/drive.file')

    def test_blank_secret_keeps_saved_one_only_for_same_client(self):
        self.call('POST', CLIENT)
        self.assertEqual(self.call('POST', {'client_id': CLIENT['client_id'], 'client_secret': ''}).status_code, 200)
        self.assertEqual(gdriveClient.load_client()['client_secret'], CLIENT['client_secret'])
        result = self.call('POST', {'client_id': 'other.apps.googleusercontent.com', 'client_secret': ''})
        self.assertEqual(result.status_code, 400)
        self.assertEqual(gdriveClient.load_client(), CLIENT)

    def test_not_set_status_and_clear(self):
        self.assertEqual(json.loads(self.call('GET').content)['client_secret'], 'not set')
        self.call('POST', CLIENT)
        data = json.loads(self.call('POST', {'clear': True}).content)
        self.assertEqual((data['client_secret'], data['configured']), ('not set', False))
        self.assertFalse(os.path.exists(self.path))

    def test_invalid_values_rejected_without_echo(self):
        for body in ({'client_id': 'not-a-google-client', 'client_secret': 'SYNTHETIC-CLIENT-SECRET'},
                     {'client_id': CLIENT['client_id'], 'client_secret': 'has spaces <script>'}):
            result = self.call('POST', body)
            self.assertEqual(result.status_code, 400)
            self.assertNotIn('SYNTHETIC-CLIENT-SECRET', result.content.decode())
            self.assertNotIn('<script>', result.content.decode())
        self.assertFalse(os.path.exists(self.path))

    def test_non_admin_denied(self):
        self.admin_mock.return_value = False
        self.assertEqual(self.call('GET').status_code, 403)
        self.assertEqual(self.call('POST', CLIENT).status_code, 403)
        self.assertFalse(os.path.exists(self.path))

    def test_unsafe_file_is_not_used(self):
        Path(self.path).write_text(json.dumps(CLIENT))
        os.chmod(self.path, 0o644)
        with self.assertRaises(gdriveClient.ClientConfigError):
            gdriveClient.load_client()
        self.assertEqual(gdriveClient.public_status()['client_secret'], 'not set')
        os.unlink(self.path)
        target = os.path.join(self.directory.name, 'elsewhere.json')
        Path(target).write_text(json.dumps(CLIENT))
        os.chmod(target, 0o600)
        os.symlink(target, self.path)
        with self.assertRaises(gdriveClient.ClientConfigError):
            gdriveClient.load_client()
        with self.assertRaises(gdriveClient.ClientConfigError):
            gdriveClient.save_client(CLIENT['client_id'], CLIENT['client_secret'])

    def test_status_never_contains_secret(self):
        self.call('POST', CLIENT)
        request = RequestFactory().get('/backup/GDriveSetupStatus', HTTP_HOST=HOST, secure=True)
        request.session = Session(userID=1)
        with mock.patch.object(flow, '_check_access'), mock.patch.object(flow, '_account_states', return_value=[]):
            result = flow.status(request, mode='normal')
        data = json.loads(result.content)
        self.assertTrue(data['enabled'])
        self.assertEqual(data['redirect_uri'], 'https://' + HOST + '/backup/gDriveSetup')
        self.assertNotIn(CLIENT['client_secret'], result.content.decode())


class AccessTests(SimpleTestCase):
    def setUp(self):
        self.user = SimpleNamespace(pk=7)
        self.admin = mock.Mock()
        self.admin.objects.get.return_value = self.user
        self.acl = mock.Mock()
        self.acl.currentContextPermission.return_value = 1
        self.acl.checkOwnership.return_value = 1
        self.acl.CheckForPremFeature.return_value = 1
        self.modules = mock.patch.dict(sys.modules, {
            'loginSystem.models': SimpleNamespace(Administrator=self.admin),
            'plogical.acl': SimpleNamespace(ACLManager=self.acl)})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.request = SimpleNamespace(session={'userID': 7})

    def test_permission_ownership_and_entitlement_required(self):
        flow._check_access(self.request, 'owned.example')
        self.acl.checkOwnership.assert_called_once_with('owned.example', self.user, self.acl.loadedACL.return_value)
        for attribute in ('currentContextPermission', 'checkOwnership', 'CheckForPremFeature'):
            with self.subTest(attribute=attribute):
                getattr(self.acl, attribute).return_value = 0
                with self.assertRaises(flow.AccessDenied):
                    flow._check_access(self.request, 'owned.example')
                getattr(self.acl, attribute).return_value = 1

    def test_unauthenticated_and_boolean_identity_rejected(self):
        for value in (None, True, '7'):
            self.request.session['userID'] = value
            with self.assertRaises(flow.AccessDenied):
                flow._check_access(self.request, 'owned.example')
        self.admin.objects.get.assert_not_called()

    def test_admin_check(self):
        self.acl.loadedACL.return_value = {'admin': 1}
        self.assertTrue(flow._is_admin(self.request))
        self.acl.loadedACL.return_value = {'admin': 0}
        self.assertFalse(flow._is_admin(self.request))
        self.assertFalse(flow._is_admin(SimpleNamespace(session={'userID': True})))


class TemplateTests(SimpleTestCase):
    def test_configuration_template_has_no_client_fields(self):
        root = Path(__file__).resolve().parents[1]
        engine = Engine(dirs=[str(root / 'baseTemplate/templates'), str(root / 'IncBackups/templates')],
                        libraries={'i18n': 'django.templatetags.i18n', 'static': 'django.templatetags.static'})
        with mock.patch('django.urls.reverse', return_value='/navigation/'):
            html = engine.get_template('IncBackups/ConfigureV2Backup.html').render(Context(
                {'BackupStat': 1, 'websiteList': ['owned.example'], 'CP_VERSION': 'qa-test'}))
        self.assertIn('IncBackups/IncBackups.js', html)
        self.assertIn('gdrive-own-client-3', html)
        self.assertNotIn('ng-model="client_secret"', html)
        self.assertNotIn('platform.cyberpersons.com/gDrive', html)
