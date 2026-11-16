"""Settings storage, key secrecy, budgets, ACL, the pipeline end to end and page render."""
import json
import os
import shutil
import stat
import tempfile
from unittest import mock

from django.db import connection, transaction
from django.test import RequestFactory, SimpleTestCase

from aiScanner import aiScannerManager as manager_mod
from aiScanner import api, budget, pipeline, prefilter, settings_store, status_api, views
from aiScanner.models import ScanHistory
from aiScanner.tests_providers import FakeHTTP, FakeResponse
from loginSystem.models import ACL, Administrator

KEY = 'gsk_live_secret_key_0123456789'
OTHER_KEY = 'sk-user-own-key-abcdefghijk'


def ai_answer(ids, verdict='malicious'):
    files = [{'id': i, 'verdict': verdict, 'severity': 'critical',
              'findings': [{'line': 1, 'reason': 'web shell', 'action': 'delete it'}]} for i in ids]
    return FakeResponse(200, {'choices': [{'message': {'content': json.dumps({'files': files})}}],
                              'usage': {'total_tokens': 321}})


class MemoryDB(SimpleTestCase):
    """Creates just the tables these tests need in the in-memory SQLite database.

    The project's full test-database setup cannot run (another app's migrations
    depend on the migration-less loginSystem app), so the runner is not asked
    for a database; this class opts in after the runner has decided.
    """
    @classmethod
    def models(cls):
        from loginSystem.models import ACL, Administrator
        from packages.models import Package
        from websiteFunctions.models import ChildDomains, Websites
        from aiScanner.models import ScheduledScan, ScheduledScanExecution
        from aiScanner.status_models import ScanStatusUpdate
        from django.apps import apps
        cosmetic = list(apps.get_app_config('baseTemplate').get_models())
        return [ACL, Administrator, Package, Websites, ChildDomains, ScanHistory, ScanStatusUpdate,
                ScheduledScan, ScheduledScanExecution] + cosmetic

    @classmethod
    def setUpClass(cls):
        cls.databases = {'default'}
        super().setUpClass()
        name = str(connection.settings_dict['NAME'] or '')
        assert connection.vendor == 'sqlite' and (name in ('', ':memory:') or 'memory' in name), name
        existing = set(connection.introspection.table_names())
        cls.created = []
        with connection.schema_editor() as editor:
            for model in cls.models():
                if model._meta.db_table not in existing:
                    editor.create_model(model)
                    cls.created.append(model)

    @classmethod
    def tearDownClass(cls):
        # leave the database as we found it (other suites create these tables themselves)
        with connection.schema_editor() as editor:
            for model in reversed(cls.created):
                editor.delete_model(model)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self._atomic = transaction.atomic()
        self._atomic.__enter__()

    def tearDown(self):
        transaction.set_rollback(True)
        self._atomic.__exit__(None, None, None)
        super().tearDown()


class StoreMixin:
    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {'AISCANNER_DIR': os.path.join(self.dir, 'aiscanner')})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.dir, ignore_errors=True)
        super().tearDown()

    def enable_ai(self, **extra):
        config = settings_store.load_config()
        config.update({'mode': 'ai', 'privacy_ack': True,
                       'primary': {'provider': 'groq', 'model': '', 'account_id': '', 'base_url': '', 'json_mode': None}})
        config.update(extra)
        settings_store.save_config(config)
        settings_store.set_key(settings_store.key_owner('primary'), KEY)


class SettingsStoreTests(StoreMixin, SimpleTestCase):
    def test_files_are_private(self):
        settings_store.set_key(settings_store.key_owner('primary'), KEY)
        settings_store.save_config(settings_store.load_config())
        directory = settings_store.base_dir()
        self.assertEqual(stat.S_IMODE(os.stat(directory).st_mode), 0o700)
        for name in ('secrets.json', 'config.json'):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(directory, name)).st_mode), 0o600)
        with open(os.path.join(directory, 'config.json')) as handle:
            self.assertNotIn(KEY, handle.read())

    def test_public_view_never_contains_the_key(self):
        self.enable_ai()
        view = settings_store.public_view(settings_store.load_config())
        self.assertTrue(view['primary']['key_set'])
        self.assertFalse(view['fallback']['key_set'])
        self.assertNotIn(KEY, json.dumps(view))

    def test_ai_mode_needs_privacy_ack(self):
        with self.assertRaises(settings_store.StoreError):
            settings_store.apply_admin_settings(settings_store.load_config(), {'mode': 'ai', 'privacy_ack': False})

    def test_users_cannot_pick_custom_endpoints(self):
        with self.assertRaises(settings_store.StoreError):
            settings_store.clean_slot({'provider': 'custom', 'base_url': 'http://127.0.0.1:8080/v1'}, allow_custom=False)


class BudgetTests(StoreMixin, SimpleTestCase):
    def test_request_cap(self):
        caps = {'max_requests_per_day': 2, 'max_tokens_per_day': 10 ** 6, 'requests_per_minute': 100}
        budget.reserve('b', 10, caps)
        budget.reserve('b', 10, caps)
        with self.assertRaises(budget.BudgetExceeded):
            budget.reserve('b', 10, caps)
        budget.reserve('other', 10, caps)  # buckets are separate

    def test_token_cap_and_settle(self):
        caps = {'max_requests_per_day': 100, 'max_tokens_per_day': 1000, 'requests_per_minute': 100}
        budget.reserve('b', 900, caps)
        budget.settle('b', 900, 100)
        budget.reserve('b', 800, caps)
        with self.assertRaises(budget.BudgetExceeded):
            budget.reserve('b', 200, caps)

    def test_daily_reset(self):
        caps = {'max_requests_per_day': 1, 'max_tokens_per_day': 1000, 'requests_per_minute': 100}
        budget.reserve('b', 1, caps, now=1_000_000)
        with self.assertRaises(budget.BudgetExceeded):
            budget.reserve('b', 1, caps, now=1_000_010)
        budget.reserve('b', 1, caps, now=1_000_000 + 86400)

    def test_rpm_pacing_and_cooldown(self):
        caps = {'max_requests_per_day': 100, 'max_tokens_per_day': 10 ** 6, 'requests_per_minute': 2}
        self.assertEqual(budget.reserve('b', 1, caps, now=1000), 0)
        self.assertEqual(budget.reserve('b', 1, caps, now=1001), 0)
        self.assertAlmostEqual(budget.reserve('b', 1, caps, now=1002), 58, delta=1)
        budget.cool_down('b', 120, now=1003)
        with self.assertRaises(budget.BudgetExceeded):
            budget.reserve('b', 1, caps, now=1010)
        budget.reserve('b', 1, caps, now=1200)

    def test_user_scan_cap(self):
        self.assertTrue(budget.try_start_user_scan(7, 2))
        self.assertTrue(budget.try_start_user_scan(7, 2))
        self.assertFalse(budget.try_start_user_scan(7, 2))
        self.assertTrue(budget.try_start_user_scan(8, 2))


def make_acl(name, admin):
    return ACL.objects.create(name=name, adminStatus=1 if admin else 0, config=json.dumps({'adminStatus': 1 if admin else 0}))


class ViewTestBase(StoreMixin, MemoryDB):
    def setUp(self):
        super().setUp()
        from packages.models import Package
        from websiteFunctions.models import Websites
        admin_acl = make_acl('admin', True)
        user_acl = make_acl('user', False)
        self.admin = Administrator.objects.create(userName='admin', password='x', email='a@x', type=1, acl=admin_acl)
        self.alice = Administrator.objects.create(userName='alice', password='x', email='b@x', type=3, acl=user_acl,
                                                  owner=self.admin.pk)
        self.bob = Administrator.objects.create(userName='bob', password='x', email='c@x', type=3, acl=user_acl,
                                                owner=self.admin.pk)
        package = Package.objects.create(admin=self.admin, packageName='p', diskSpace=1, bandwidth=1)
        self.site_a = Websites.objects.create(admin=self.alice, package=package, domain='alice.example', adminEmail='a@x',
                                              phpSelection='8.2', ssl=0, externalApp='alice1234')
        self.site_b = Websites.objects.create(admin=self.bob, package=package, domain='bob.example', adminEmail='b@x',
                                              phpSelection='8.2', ssl=0, externalApp='bobb5678')
        self.rf = RequestFactory()
        self.acl_patch = mock.patch('plogical.acl.ACLManager.loadedACL', side_effect=self.fake_acl)
        self.acl_patch.start()
        self.log_patch = mock.patch('plogical.CyberCPLogFileWriter.CyberCPLogFileWriter.writeToFile')
        self.log_patch.start()
        self.denied = set()

    def tearDown(self):
        self.acl_patch.stop()
        self.log_patch.stop()
        super().tearDown()

    def fake_acl(self, user_id):
        acl = {'admin': 1 if int(user_id) == self.admin.pk else 0}
        if int(user_id) in self.denied:
            acl['aiScannerAccess'] = 0
        return acl

    def call(self, view, user, method='get', body=None, *args):
        if method == 'post':
            request = self.rf.post('/aiscanner/x', data=json.dumps(body or {}), content_type='application/json')
        else:
            request = getattr(self.rf, method)('/aiscanner/x')
        request.session = {'userID': user.pk} if user else {}
        request._dont_enforce_csrf_checks = True
        response = view(request, *args)
        return response.status_code, (json.loads(response.content) if response['Content-Type'].startswith('application/json') else response)


class KeySecrecyTests(ViewTestBase):
    def test_settings_endpoints_never_return_the_key(self):
        payload = {'settings': {'mode': 'ai', 'privacy_ack': True,
                                'primary': {'provider': 'groq', 'model': 'openai/gpt-oss-20b'},
                                'keys': {'primary': {'value': KEY}}}}
        status, data = self.call(views.saveSettings, self.admin, 'post', payload)
        self.assertEqual(status, 200, data)
        self.assertTrue(data['success'], data)
        self.assertNotIn(KEY, json.dumps(data))
        self.assertTrue(data['settings']['primary']['key_set'])
        self.assertEqual(settings_store.get_key(settings_store.key_owner('primary')), KEY)
        status, data = self.call(views.getSettings, self.admin)
        self.assertNotIn(KEY, json.dumps(data))
        self.assertTrue(data['settings']['primary']['key_set'])
        # saving again without a key keeps the stored one
        payload['settings']['keys'] = {}
        self.call(views.saveSettings, self.admin, 'post', payload)
        self.assertEqual(settings_store.get_key(settings_store.key_owner('primary')), KEY)
        # explicit removal
        payload['settings'].update({'mode': 'local', 'keys': {'primary': {'clear': True}}})
        status, data = self.call(views.saveSettings, self.admin, 'post', payload)
        self.assertFalse(data['settings']['primary']['key_set'])

    def test_page_does_not_embed_the_key(self):
        self.enable_ai()
        with mock.patch('plogical.acl.ACLManager.findWebsiteObjects', return_value=[self.site_a]):
            status, response = self.call(views.aiScannerHome, self.admin)
        self.assertEqual(status, 200)
        self.assertNotIn(KEY, response.content.decode())

    def test_test_key_button(self):
        self.enable_ai()
        http = FakeHTTP(FakeResponse(200, {'choices': [{'message': {'content': '{"ok":true}'}}], 'usage': {'total_tokens': 5}}))
        request = self.rf.post('/x', data=json.dumps({'settings': {'slot': 'primary'}}), content_type='application/json')
        request.session = {'userID': self.admin.pk}
        response = manager_mod.AIScannerManager().testKey(request, self.admin.pk, http=http)
        data = json.loads(response.content)
        self.assertTrue(data['success'], data)
        self.assertEqual(http.calls[0][1]['headers']['Authorization'], 'Bearer ' + KEY)
        self.assertNotIn(KEY, response.content.decode())
        http = FakeHTTP(FakeResponse(401, {'error': {'message': 'bad key ' + KEY}}))
        response = manager_mod.AIScannerManager().testKey(request, self.admin.pk, http=http)
        self.assertFalse(json.loads(response.content)['success'])
        self.assertNotIn(KEY, response.content.decode())


class ACLTests(ViewTestBase):
    def test_non_admin_cannot_change_admin_settings(self):
        status, data = self.call(views.saveSettings, self.alice, 'post',
                                 {'settings': {'mode': 'ai', 'privacy_ack': True, 'primary': {'provider': 'groq'}}})
        self.assertFalse(data['success'])
        self.assertEqual(settings_store.load_config()['mode'], 'local')
        status, data = self.call(views.getSettings, self.alice)
        self.assertNotIn('primary', data['settings'])
        self.assertNotIn('budget', data['settings'])

    def test_own_key_policy(self):
        config = settings_store.load_config()
        config['key_policy'] = 'own'
        settings_store.save_config(config)
        status, data = self.call(views.saveSettings, self.alice, 'post',
                                 {'settings': {'own': {'provider': 'custom', 'base_url': 'http://127.0.0.1:1/v1'}}})
        self.assertFalse(data['success'])
        status, data = self.call(views.saveSettings, self.alice, 'post',
                                 {'settings': {'own': {'provider': 'groq'}, 'keys': {'own': {'value': OTHER_KEY}}}})
        self.assertTrue(data['success'], data)
        self.assertTrue(data['settings']['own']['key_set'])
        self.assertNotIn(OTHER_KEY, json.dumps(data))
        self.assertEqual(settings_store.get_key(settings_store.key_owner('primary', self.alice.pk)), OTHER_KEY)

    def test_scan_only_owned_sites(self):
        launched = []
        manager = manager_mod.AIScannerManager()

        def start(user, domain):
            request = self.rf.post('/x', data=json.dumps({'domain': domain}), content_type='application/json')
            request.session = {'userID': user.pk}
            return json.loads(manager.startScan(request, user.pk, launcher=launched.append).content)

        self.assertFalse(start(self.alice, 'bob.example')['success'])
        self.assertTrue(start(self.alice, 'alice.example')['success'])
        self.assertFalse(start(self.alice, 'alice.example')['success'])  # already running
        self.assertEqual(len(launched), 1)
        self.assertTrue(start(self.admin, 'bob.example')['success'])
        self.assertFalse(start(self.alice, 'nope.example')['success'])

    def test_history_and_details_visibility(self):
        mine = ScanHistory.objects.create(admin=self.alice, scan_id='ic_a', domain='alice.example')
        theirs = ScanHistory.objects.create(admin=self.bob, scan_id='ic_b', domain='bob.example')
        status, data = self.call(views.getScanHistory, self.alice)
        self.assertEqual([s['scan_id'] for s in data['scans']], ['ic_a'])
        status, data = self.call(views.getScanHistory, self.admin)
        self.assertEqual({s['scan_id'] for s in data['scans']}, {'ic_a', 'ic_b'})
        status, data = self.call(views.getScanDetails, self.alice, 'get', None, theirs.scan_id)
        self.assertEqual(status, 403)
        status, data = self.call(views.getScanDetails, self.alice, 'get', None, mine.scan_id)
        self.assertTrue(data['success'])
        status, data = self.call(views.getScanStatus, self.bob, 'get', None, mine.scan_id)
        self.assertEqual(status, 403)
        request = self.rf.get('/x')
        request.session = {}
        self.assertEqual(status_api.get_live_scan_progress(request, mine.scan_id).status_code, 401)

    def test_access_flag_and_login_required(self):
        self.denied.add(self.alice.pk)
        status, data = self.call(views.getScanHistory, self.alice)
        self.assertEqual(status, 403)
        status, data = self.call(views.startScan, self.alice, 'post', {'domain': 'alice.example'})
        self.assertFalse(data['success'])
        status, data = self.call(views.getScanHistory, None)
        self.assertEqual(status, 401)

    def test_vendor_endpoints_are_gone(self):
        for func in (api.authenticate_worker, api.list_files, api.get_file_content, api.scan_callback,
                     api.scanner_backup_file, api.scanner_get_file, api.scanner_replace_file,
                     api.scanner_rename_file, api.scanner_delete_file, status_api.receive_status_update):
            self.assertEqual(func(self.rf.post('/x')).status_code, 410)


class PipelineTests(ViewTestBase):
    def setUp(self):
        super().setUp()
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, 'wp-content', 'uploads'))
        with open(os.path.join(self.root, 'wp-content', 'uploads', 'x.php'), 'w') as handle:
            handle.write("<?php\n$api_key = 'TOPSECRET-123';\n@eval(base64_decode($_POST['z']));\n")
        with open(os.path.join(self.root, 'wp-config.php'), 'w') as handle:
            handle.write("<?php\ndefine('DB_PASSWORD', 'dbpw-ZZZ');\neval(base64_decode('aGk='));\n")
        with open(os.path.join(self.root, 'index.php'), 'w') as handle:
            handle.write('<?php echo "clean";')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        super().tearDown()

    def runner(self, command, user):
        self.assertEqual(user, 'alice1234')
        return 'AISCANNER-JSON:' + json.dumps(prefilter.scan_tree(self.root))

    def scan(self, user=None, scan_type='full'):
        return ScanHistory.objects.create(admin=user or self.alice, scan_id='ic_%d' % ScanHistory.objects.count(),
                                          domain='alice.example', scan_type=scan_type)

    def test_local_only_mode_makes_no_request(self):
        http = FakeHTTP()
        scan = pipeline.run_scan(self.scan(), self.site_a, self.alice.pk, False, runner=self.runner, http=http)
        self.assertEqual(scan.status, 'completed', scan.error_message)
        self.assertEqual(http.calls, [])
        self.assertEqual(scan.summary['mode'], 'local')
        files = {f['file'] for f in scan.findings}
        self.assertEqual(files, {'wp-content/uploads/x.php', 'wp-config.php'})
        self.assertGreater(scan.issues_found, 0)
        self.assertTrue(all(set(f) >= {'severity', 'file', 'line', 'reason', 'action'} for f in scan.findings))

    def test_ai_mode_sends_only_redacted_snippets(self):
        self.enable_ai()
        http = FakeHTTP(ai_answer(['F1', 'F2']))
        scan = pipeline.run_scan(self.scan(self.admin), self.site_a, self.admin.pk, True, runner=self.runner,
                                 http=http, sleep=lambda s: None)
        self.assertEqual(scan.status, 'completed', scan.error_message)
        self.assertEqual(len(http.calls), 1)
        sent = json.dumps(http.calls[0][1]['json'])
        self.assertNotIn('TOPSECRET-123', sent)
        self.assertNotIn('dbpw-ZZZ', sent)
        self.assertNotIn('index.php', sent)
        self.assertIn('eval(base64_decode', sent)
        self.assertEqual(scan.summary['mode'], 'ai')
        self.assertEqual(scan.summary['ai_tokens'], 321)
        self.assertTrue(any(f['source'] == 'ai' for f in scan.findings))
        self.assertEqual(budget.snapshot()['buckets']['admin:primary']['requests'], 1)

    def test_quick_scan_and_user_cap(self):
        self.enable_ai(user_daily_ai_scans=1)
        http = FakeHTTP(ai_answer(['F1', 'F2']), ai_answer(['F1', 'F2']))
        scan = pipeline.run_scan(self.scan(scan_type='quick'), self.site_a, self.alice.pk, False, runner=self.runner, http=http)
        self.assertEqual(http.calls, [])
        pipeline.run_scan(self.scan(), self.site_a, self.alice.pk, False, runner=self.runner, http=http, sleep=lambda s: None)
        self.assertEqual(len(http.calls), 1)
        scan = pipeline.run_scan(self.scan(), self.site_a, self.alice.pk, False, runner=self.runner, http=http, sleep=lambda s: None)
        self.assertEqual(len(http.calls), 1)
        self.assertTrue(any('allowance' in n for n in scan.summary['notes']))

    def test_budget_exhaustion_falls_back_to_local(self):
        config = {'budget': {'max_requests_per_day': 0, 'max_tokens_per_day': 0, 'requests_per_minute': 1}}
        self.enable_ai(**config)
        http = FakeHTTP()
        scan = pipeline.run_scan(self.scan(self.admin), self.site_a, self.admin.pk, True, runner=self.runner, http=http)
        self.assertEqual(scan.status, 'completed')
        self.assertEqual(http.calls, [])
        self.assertTrue(any('limit' in n for n in scan.summary['notes']))

    def test_rate_limited_primary_uses_fallback(self):
        self.enable_ai(fallback={'provider': 'mistral', 'model': '', 'account_id': '', 'base_url': '', 'json_mode': None})
        settings_store.set_key(settings_store.key_owner('fallback'), OTHER_KEY)
        http = FakeHTTP(FakeResponse(429, {}, headers={'retry-after': '900'}), ai_answer(['F1', 'F2']))
        scan = pipeline.run_scan(self.scan(self.admin), self.site_a, self.admin.pk, True, runner=self.runner,
                                 http=http, sleep=lambda s: None)
        self.assertEqual(len(http.calls), 2)
        self.assertIn('api.mistral.ai', http.calls[1][0])
        self.assertEqual(scan.summary['providers'], ['mistral / mistral-small-latest'])
        with self.assertRaises(budget.BudgetExceeded):  # primary is cooling down
            budget.reserve('admin:primary', 1, settings_store.load_config()['budget'])

    def test_garbage_model_output_keeps_local_results(self):
        self.enable_ai()
        http = FakeHTTP(FakeResponse(200, {'choices': [{'message': {'content': '<script>alert(1)</script>'}}]}))
        scan = pipeline.run_scan(self.scan(self.admin), self.site_a, self.admin.pk, True, runner=self.runner,
                                 http=http, sleep=lambda s: None)
        self.assertEqual(scan.status, 'completed')
        self.assertTrue(all(f['source'] == 'local' for f in scan.findings))
        self.assertTrue(any('not valid scanner JSON' in n for n in scan.summary['notes']))

    def test_failed_prefilter_marks_scan_failed(self):
        scan = pipeline.run_scan(self.scan(), self.site_a, self.alice.pk, False, runner=lambda c, u: 'Permission denied')
        self.assertEqual(scan.status, 'failed')
        self.assertTrue(scan.error_message)

    def test_background_entry_point_rechecks_ownership(self):
        scan = ScanHistory.objects.create(admin=self.bob, scan_id='ic_x', domain='alice.example')
        result = manager_mod.run_scan_by_id('ic_x', runner=self.runner)
        self.assertEqual(result.status, 'failed')
        scan = ScanHistory.objects.create(admin=self.alice, scan_id='ic_y', domain='alice.example')
        self.assertEqual(manager_mod.run_scan_by_id('ic_y', runner=self.runner).status, 'completed')


class PageRenderTests(ViewTestBase):
    def render(self, user):
        with mock.patch('plogical.acl.ACLManager.findWebsiteObjects', return_value=[self.site_a]):
            status, response = self.call(views.aiScannerHome, user)
        self.assertEqual(status, 200)
        return response.content.decode()

    def test_admin_page(self):
        html = self.render(self.admin)
        self.assertIn('AI Security Scanner - IndiansCloud', html)
        self.assertIn('id="ais-settings"', html)
        self.assertIn('alice.example', html)
        self.assertIn('Free tiers may keep your data', html)
        for vendor in ('platform.cyberpersons.com', 'setup-payment', 'Add Payment', 'free scans', 'balance'):
            self.assertNotIn(vendor, html)

    def test_user_page_has_no_admin_settings(self):
        html = self.render(self.alice)
        self.assertNotIn('id="set-mode"', html)
        self.assertIn('Scan a website', html)

    def test_redirects_to_login_without_session(self):
        request = self.rf.get('/aiscanner/')
        request.session = {}
        self.assertEqual(views.aiScannerHome(request).status_code, 302)

    def test_no_vendor_urls_left_in_app(self):
        base = os.path.dirname(pipeline.__file__)
        for dirpath, _, files in os.walk(base):
            for name in files:
                if name.endswith(('.py', '.html')) and not name.startswith('tests_'):
                    with open(os.path.join(dirpath, name), encoding='utf-8') as handle:
                        text = handle.read()
                    self.assertNotIn('cyberpersons.com', text, name)
                    self.assertNotIn('CheckForPremFeature', text, name)
