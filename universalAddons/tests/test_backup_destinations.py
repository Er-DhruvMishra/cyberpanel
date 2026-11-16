"""Backup destinations: permission matrix, secrets, OAuth state/PKCE, rclone config, page render,
and the Google Drive Reconnect regression. Everything is synthetic: no provider is contacted and
no command runs (rclone/restic calls go to fake runners)."""
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory, SimpleTestCase, TestCase

from loginSystem.models import ACL, Administrator
from packages.models import Package
from plogical import gdriveClient
from plogical.acl import ACLManager
from universalAddons.backupv2 import service as bk
from universalAddons.destinations import actions, clients, oauth, policy, providers, views
from universalAddons.models import BackupDestination, DestinationBackupJob
from websiteFunctions.models import Websites

HOST = 'panel.example.test:8090'
ORIGIN = 'https://' + HOST
ROOT = Path(__file__).resolve().parents[2]
SECRET = 'SYNTHETIC-SECRET-VALUE-9f8e7d'


PANEL_TABLES = (ACL, Administrator, Package, Websites)


class World(TestCase):
    """admin; reseller R with user U1; user U2 created by admin; reseller R2 with user U3.

    The panel apps ship no migrations, so their tables are created here (outside the test
    transaction, as sqlite requires) and dropped afterwards."""

    @classmethod
    def setUpClass(cls):
        from django.db import connection
        with connection.schema_editor() as editor:
            for model in PANEL_TABLES:
                editor.create_model(model)
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        from django.db import connection
        super().tearDownClass()
        with connection.schema_editor() as editor:
            for model in reversed(PANEL_TABLES):
                editor.delete_model(model)

    @classmethod
    def setUpTestData(cls):
        acl_admin = ACL.objects.create(name='admin', adminStatus=1, config=ACLManager.AdminACL)
        acl_reseller = ACL.objects.create(name='reseller', resellerCenter=1, config=ACLManager.ResellerACL)
        acl_user = ACL.objects.create(name='user', config=ACLManager.UserACL)

        def account(name, acl, owner=None):
            item = Administrator.objects.create(userName=name, password='x', email=name + '@example.test', type=1,
                                                acl=acl, securityLevel=1)
            item.owner = owner.pk if owner else item.pk
            item.save()
            return item
        cls.admin = account('admin', acl_admin)
        cls.r = account('res1', acl_reseller, cls.admin)
        cls.u1 = account('user1', acl_user, cls.r)
        cls.u2 = account('user2', acl_user, cls.admin)
        cls.r2 = account('res2', acl_reseller, cls.admin)
        cls.u3 = account('user3', acl_user, cls.r2)
        package = Package.objects.create(admin=cls.admin, packageName='Default', diskSpace=0, bandwidth=0)

        def site(domain, owner):
            return Websites.objects.create(admin=owner, package=package, domain=domain, adminEmail='a@example.test',
                                           phpSelection='PHP 8.2', ssl=0, externalApp=domain.split('.')[0][:7])
        cls.site_u1, cls.site_r = site('u1site.example.com', cls.u1), site('rsite.example.com', cls.r)
        cls.site_u2, cls.site_u3 = site('u2site.example.com', cls.u2), site('u3site.example.com', cls.u3)
        cls.site_admin = site('adminsite.example.com', cls.admin)

        def dest(owner, name, connected=True):
            return BackupDestination.objects.create(owner_id=owner.pk, name=name, provider='sftp', connected=connected,
                                                    public_config=json.dumps({'host': 'h.example.net', 'port': 22,
                                                                              'user': 'u', 'path': 'b', 'auth': 'password'}))
        cls.d = {name: dest(owner, name) for name, owner in (
            ('admin', cls.admin), ('r', cls.r), ('u1', cls.u1), ('u2', cls.u2), ('r2', cls.r2), ('u3', cls.u3))}
        cls.d_off = dest(cls.u1, 'u1-off', connected=False)

    def actor(self, who):
        return policy.load_actor(who.pk)

    def post(self, view, body, who, path='/x'):
        request = RequestFactory().post(path, data=json.dumps(body), content_type='application/json',
                                        HTTP_HOST=HOST, HTTP_ORIGIN=ORIGIN)
        request.session = {'userID': who.pk}
        response = view(request)
        return response.status_code, json.loads(response.content)


# ----------------------------------------------------------------------------- permission matrix

# (actor, site, destination) -> may back up to / restore from it
MATRIX = [
    # Administrator: own, site owner's, site owner's reseller's
    ('admin', 'site_u1', 'admin', True), ('admin', 'site_u1', 'u1', True), ('admin', 'site_u1', 'r', True),
    ('admin', 'site_u1', 'u2', False), ('admin', 'site_u1', 'r2', False), ('admin', 'site_u1', 'u3', False),
    ('admin', 'site_u2', 'u2', True), ('admin', 'site_u2', 'r', False), ('admin', 'site_r', 'r', True),
    ('admin', 'site_r', 'u1', False), ('admin', 'site_admin', 'admin', True), ('admin', 'site_admin', 'u1', False),
    # Reseller: own or the site owner's, for its own sites and its users' sites
    ('r', 'site_u1', 'r', True), ('r', 'site_u1', 'u1', True), ('r', 'site_u1', 'admin', False),
    ('r', 'site_u1', 'u2', False), ('r', 'site_r', 'r', True), ('r', 'site_r', 'u1', False),
    ('r', 'site_u2', 'r', False), ('r', 'site_u2', 'u2', False), ('r', 'site_u3', 'r', False),
    ('r', 'site_admin', 'r', False),
    # User: own destinations, own sites only
    ('u1', 'site_u1', 'u1', True), ('u1', 'site_u1', 'r', False), ('u1', 'site_u1', 'admin', False),
    ('u1', 'site_r', 'u1', False), ('u1', 'site_u2', 'u1', False), ('u1', 'site_u2', 'u2', False),
    ('u2', 'site_u2', 'u2', True), ('u2', 'site_u2', 'admin', False), ('u2', 'site_u1', 'u2', False),
    # Another reseller's tree
    ('r2', 'site_u3', 'r2', True), ('r2', 'site_u3', 'u3', True), ('r2', 'site_u1', 'r2', False),
    ('r2', 'site_u3', 'r', False),
]


class PermissionMatrix(World):
    def who(self, name):
        return {'admin': self.admin, 'r': self.r, 'u1': self.u1, 'u2': self.u2, 'r2': self.r2, 'u3': self.u3}[name]

    def test_policy_matrix(self):
        for actor, site, dest, allowed in MATRIX:
            a, s, d = self.actor(self.who(actor)), getattr(self, site), self.d[dest]
            with self.subTest(actor=actor, site=site, dest=dest):
                if allowed:
                    policy.require_use(a, d, s)
                else:
                    with self.assertRaises(PermissionError):
                        policy.require_use(a, d, s)
                self.assertEqual(d in policy.allowed_destinations(a, s), allowed)

    def test_backup_restore_and_listing_endpoints_enforce_matrix(self):
        for actor, site, dest, allowed in MATRIX:
            body = {'domain': getattr(self, site).domain, 'destination': self.d[dest].pk}
            for view, extra in ((views.backup_now, {}), (views.snapshots, {}),
                                (views.restore, {'snapshot': 'abcdef12', 'kind': 'files'}),
                                (views.restore, {'snapshot': 'abcdef12', 'kind': 'db', 'database': 'wp1'}),
                                (views.save_job, {'schedule': 'daily'})):
                with self.subTest(actor=actor, site=site, dest=dest, view=view.__name__), \
                        mock.patch('universalAddons.privileged.call', return_value={'job_id': 'a' * 24}) as call:
                    code, data = self.post(view, dict(body, **extra), self.who(actor))
                    if allowed:
                        self.assertEqual((code, data['status']), (200, 1), data)
                    else:
                        self.assertEqual(code, 403, data)
                        for item in call.call_args_list:
                            self.assertNotIn(item[0][1], ('backup_now', 'snapshots', 'restore'))

    def test_root_side_rechecks_for_backup_and_restore(self):
        with mock.patch.object(actions, '_django'):
            for actor, site, dest, allowed in MATRIX:
                args = (self.who(actor).pk, self.d[dest].pk, getattr(self, site).domain)
                with self.subTest(actor=actor, site=site, dest=dest):
                    if allowed:
                        actions._context(*args)
                    else:
                        with self.assertRaises(bk.BackupError):
                            actions._context(*args)
                    with mock.patch.object(actions.jobs, 'spawn', return_value={'job_id': 'b' * 24}) as spawn:
                        for call in (lambda: actions.backup_now(*args),
                                     lambda: actions.restore(*args, snapshot='abcdef12', kind='files')):
                            if allowed:
                                call()
                            else:
                                with self.assertRaises(bk.BackupError):
                                    call()
                        self.assertEqual(spawn.called, allowed)

    def test_disconnected_destination_cannot_be_used(self):
        with self.assertRaises(PermissionError):
            policy.require_use(self.actor(self.u1), self.d_off, self.site_u1)
        self.assertNotIn(self.d_off, policy.allowed_destinations(self.actor(self.u1), self.site_u1))

    def test_scheduled_run_rechecks_creator(self):
        job = DestinationBackupJob.objects.create(website_id=self.site_u1.pk, destination=self.d['r'], created_by_id=self.r.pk)
        # The site moves to another reseller's user: the reseller no longer manages it.
        Websites.objects.filter(pk=self.site_u1.pk).update(admin=self.u3)
        with mock.patch.object(actions, '_django'), mock.patch.object(actions.jobs, 'run_job') as run, \
                mock.patch.object(actions.os, 'makedirs'):
            with self.assertRaises(bk.BackupError):
                actions.run_scheduled(job.pk)
        run.assert_not_called()
        job.refresh_from_db()
        self.assertTrue(job.last_status.startswith('Not run'))

    def test_only_owner_manages_a_destination(self):
        for view, body in ((views.rename, {'name': 'x'}), (views.test, {}), (views.usage, {}),
                           (views.delete, {'confirm': 'u1'}),
                           (views.save, {'provider': 'sftp', 'settings': {}, 'secrets': ''})):
            for who in (self.admin, self.r, self.u2):
                with self.subTest(view=view.__name__, who=who.userName), \
                        mock.patch('universalAddons.privileged.call') as call, \
                        mock.patch('universalAddons.privileged.call_private') as private:
                    code, _ = self.post(view, dict(body, id=self.d['u1'].pk, provider='sftp',
                                                   settings={'host': 'h.example.net', 'user': 'u', 'auth': 'password'}),
                                        who)
                    self.assertIn(code, (400, 403))
                    call.assert_not_called()
                    private.assert_not_called()
        self.assertTrue(BackupDestination.objects.filter(pk=self.d['u1'].pk, name='u1').exists())

    def test_site_dropdown_labels_and_reveals_no_settings(self):
        code, data = self.post(views.site_destinations, {'domain': self.site_u1.domain}, self.admin)
        self.assertEqual(code, 200)
        labels = {item['name']: item['label'] for item in data['destinations']}
        self.assertEqual(labels, {'admin': 'Mine', 'u1': 'Site owner: user1', 'r': 'Reseller: res1'})
        for item in data['destinations']:
            self.assertEqual(set(item), {'id', 'name', 'provider', 'provider_title', 'owner', 'label'})
        code, data = self.post(views.site_destinations, {'domain': self.site_u2.domain}, self.u1)
        self.assertEqual(code, 403)

    def test_jobs_list_only_shows_usable_jobs(self):
        DestinationBackupJob.objects.create(website_id=self.site_u1.pk, destination=self.d['r'], created_by_id=self.r.pk)
        DestinationBackupJob.objects.create(website_id=self.site_u1.pk, destination=self.d['u1'], created_by_id=self.u1.pk)
        _, data = self.post(views.jobs, {}, self.u1)
        self.assertEqual([j['destination_name'] for j in data['jobs']], ['u1'])
        _, data = self.post(views.jobs, {}, self.r)
        self.assertEqual(sorted(j['destination_name'] for j in data['jobs']), ['r', 'u1'])
        _, data = self.post(views.jobs, {}, self.u2)
        self.assertEqual(data['jobs'], [])


# ----------------------------------------------------------------------------- secrets

def b64(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()


class Secrets(World):
    def test_secrets_go_to_root_store_only_and_are_never_returned(self):
        with mock.patch('universalAddons.privileged.call_private', return_value={'saved': True}) as private:
            code, data = self.post(views.save, {
                'provider': 's3', 'name': 'offsite',
                'settings': {'preset': 'wasabi', 'region': 'eu-central-1', 'bucket': 'my-bucket', 'prefix': 'x'},
                'secrets': b64({'access_key_id': 'AKIASYNTHETIC1', 'secret_access_key': SECRET})}, self.u1)
        self.assertEqual(code, 200, data)
        self.assertEqual(private.call_args[0][:2], ('destinations', 'save_secrets'))
        self.assertEqual(private.call_args[1]['secrets'],
                         {'access_key_id': 'AKIASYNTHETIC1', 'secret_access_key': SECRET})
        row = BackupDestination.objects.get(owner_id=self.u1.pk, name='offsite')
        self.assertNotIn(SECRET, row.public_config)
        self.assertNotIn('AKIASYNTHETIC1', row.public_config)
        for who in (self.u1, self.r, self.admin):
            for view, body in ((views.overview, {}), (views.site_destinations, {'domain': self.site_u1.domain}),
                               (views.jobs, {})):
                with mock.patch('universalAddons.privileged.call', return_value={}):
                    _, out = self.post(view, body, who)
                text = json.dumps(out)
                self.assertNotIn(SECRET, text)
                self.assertNotIn('AKIASYNTHETIC1', text)

    def test_admin_overview_lists_only_own_destinations(self):
        _, data = self.post(views.overview, {}, self.admin)
        self.assertEqual([d['name'] for d in data['destinations']], ['admin'])
        self.assertTrue(data['is_admin'])

    def test_failed_root_store_removes_the_new_row(self):
        with mock.patch('universalAddons.privileged.call_private', side_effect=RuntimeError('store failed')):
            code, data = self.post(views.save, {'provider': 'b2', 'name': 'b2x', 'settings': {'bucket': 'bucket-1'},
                                                'secrets': b64({'account': 'keyid0001', 'key': SECRET})}, self.u2)
        self.assertEqual(data['status'], 0)
        self.assertFalse(BackupDestination.objects.filter(name='b2x').exists())

    def test_oauth_client_secret_is_never_returned(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(clients, 'CLIENT_DIR', directory), \
                mock.patch.object(gdriveClient, 'CONFIG_PATH', os.path.join(directory, 'g.json')):
            code, data = self.post(views.oauth_clients, {'provider': 'dropbox', 'client_id': 'dbxappkey1',
                                                         'client_secret_b64': b64({'client_secret': SECRET})},
                                   self.admin)
            self.assertEqual(code, 200, data)
            self.assertNotIn(SECRET, json.dumps(data))
            info = os.stat(os.path.join(directory, 'dropbox.json'))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(directory).st_mode), 0o700)
            item = [p for p in data['providers'] if p['provider'] == 'dropbox'][0]
            self.assertEqual((item['configured'], item['client_secret']), (True, 'set'))
            self.assertEqual(item['redirect_uri'], ORIGIN + '/addons/destinations/oauth/dropbox/callback')
            code, _ = self.post(views.oauth_clients, {'provider': 'dropbox', 'client_id': 'evil',
                                                      'client_secret_b64': b64({'client_secret': 'x' * 10})}, self.u1)
            self.assertEqual(code, 403)
            self.assertEqual(clients.load('dropbox')['client_secret'], SECRET)

    def test_root_store_and_run_config_are_private_and_temporary(self):
        dest = BackupDestination.objects.create(owner_id=self.u1.pk, name='sf', provider='sftp', connected=True,
                                                public_config=json.dumps({'host': 'h.example.net', 'port': 2222,
                                                                          'user': 'bk', 'path': '/srv/b',
                                                                          'auth': 'password'}))
        argv_seen = []

        def runner(argv, **kwargs):
            argv_seen.append(argv)
            return SimpleNamespace(returncode=0, stdout='OBSCURED-PASSWORD\n')
        with tempfile.TemporaryDirectory() as store, tempfile.TemporaryDirectory() as locks, \
                mock.patch.object(actions, '_django'):
            actions.save_secrets(dest.pk, {'password': SECRET}, store=store)
            secret_file = os.path.join(store, 'secrets', '%d.json' % dest.pk)
            self.assertEqual(stat.S_IMODE(os.stat(secret_file).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(store, 'secrets')).st_mode), 0o700)
            with actions.session(dest, store=store, runner=runner, lock_dir=locks) as (remote, path):
                self.assertEqual(remote, 'dst%d' % dest.pk)
                self.assertEqual(os.environ['RCLONE_CONFIG'], path)
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                self.assertTrue(path.startswith(os.path.join(store, 'run') + os.sep))
                text = Path(path).read_text()
                self.assertIn('pass = OBSCURED-PASSWORD', text)
                self.assertNotIn(SECRET, text)
            self.assertFalse(os.path.exists(path), 'run config is deleted afterwards')
            self.assertNotIn('RCLONE_CONFIG', os.environ)
        for argv in argv_seen:
            self.assertNotIn(SECRET, ' '.join(argv), 'secrets never on a command line')
        self.assertEqual(argv_seen[0], ['rclone', 'obscure', '-'])

    def test_refreshed_oauth_token_is_kept(self):
        dest = BackupDestination.objects.create(owner_id=self.u1.pk, name='bx', provider='box', connected=True,
                                                public_config=json.dumps({'folder': 'B'}))
        old = providers.rclone_token('old-access', 'old-refresh', 3600)
        new = providers.rclone_token('new-access', 'rotated-refresh', 3600)
        with tempfile.TemporaryDirectory() as store, tempfile.TemporaryDirectory() as locks, \
                mock.patch.object(actions, '_django'), \
                mock.patch.object(actions, 'oauth_client', return_value={'client_id': 'boxid1', 'client_secret': 'boxsecret1'}):
            actions.save_secrets(dest.pk, {'token': old}, store=store)
            with actions.session(dest, store=store, lock_dir=locks) as (remote, path):
                text = Path(path).read_text()
                self.assertIn('client_secret = boxsecret1', text)
                Path(path).write_text(text.replace(old, new))   # what rclone does after a refresh
            self.assertEqual(actions.load_secrets(dest.pk, store)['token'], new)


# ----------------------------------------------------------------------------- connection test

class ConnectionTest(World):
    def test_writes_lists_and_deletes_a_test_object(self):
        dest = BackupDestination.objects.create(owner_id=self.u1.pk, name='wd', provider='webdav', connected=True,
                                                public_config=json.dumps({'vendor': 'nextcloud', 'host': 'cloud.example.net',
                                                                          'dav_path': 'remote.php/dav/files/me',
                                                                          'user': 'me', 'path': 'backups'}))
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs.get('input')))
            sub = argv[1] if argv[1] == 'obscure' else argv[11]
            if sub == 'obscure':
                return SimpleNamespace(returncode=0, stdout='OBS\n')
            if sub == 'lsjson':
                name = [a for a, _ in calls if len(a) > 12 and a[11] == 'rcat'][0][12].rsplit('/', 1)[1]
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'Name': name}]))
            return SimpleNamespace(returncode=0, stdout='')
        with tempfile.TemporaryDirectory() as store, tempfile.TemporaryDirectory() as locks, \
                mock.patch.object(actions, '_django'), mock.patch.object(actions, 'STORE', store), \
                mock.patch.object(bk, 'LOCK_DIR', locks):
            actions.save_secrets(dest.pk, {'password': SECRET}, store=store)
            result = actions.test(dest.pk, store=store, runner=runner)
        self.assertTrue(result['ok'], result)
        subs = [argv[11] for argv, _ in calls if argv[1] != 'obscure']
        self.assertEqual(subs, ['mkdir', 'rcat', 'lsjson', 'deletefile'])
        rcat = [c for c in calls if c[0][1] != 'obscure' and c[0][11] == 'rcat'][0]
        self.assertTrue(rcat[1], 'test object content comes through stdin')
        self.assertEqual([argv for argv, _ in calls if argv[1] != 'obscure'][1][12].split('/')[0],
                         'dst%d:backups' % dest.pk)

    def test_test_endpoint_records_result(self):
        with mock.patch('universalAddons.privileged.call', return_value={'ok': False, 'message': 'auth failed'}):
            code, data = self.post(views.test, {'id': self.d['u1'].pk}, self.u1)
        self.assertEqual(code, 200)
        row = BackupDestination.objects.get(pk=self.d['u1'].pk)
        self.assertEqual((row.last_test_ok, row.last_test_message), (False, 'auth failed'))

    def test_delete_needs_confirmation_and_keeps_data_unless_asked(self):
        with mock.patch('universalAddons.privileged.call', return_value={'deleted': 1, 'purged': False}) as call:
            code, _ = self.post(views.delete, {'id': self.d['u2'].pk, 'confirm': 'wrong'}, self.u2)
            self.assertEqual(code, 400)
            call.assert_not_called()
            code, _ = self.post(views.delete, {'id': self.d['u2'].pk, 'confirm': 'u2'}, self.u2)
        self.assertEqual(code, 200)
        self.assertEqual(call.call_args_list[0][0][:2], ('destinations', 'delete'))
        self.assertIs(call.call_args_list[0][1]['purge'], False)
        self.assertFalse(BackupDestination.objects.filter(pk=self.d['u2'].pk).exists())


# ----------------------------------------------------------------------------- OAuth state + PKCE

FAKE_CLIENTS = {'gdrive': {'client_id': '123-abc.apps.googleusercontent.com', 'client_secret': 'GOCSPX-synthetic1'},
                'onedrive': {'client_id': '0f0e0d0c-1111-2222-3333-444455556666', 'client_secret': 'ms~synthetic.secret'},
                'dropbox': {'client_id': 'dbxappkey1', 'client_secret': 'dbxsecret1'},
                'box': {'client_id': 'boxclientid1', 'client_secret': 'boxsecret1'},
                'pcloud': {'client_id': 'pcloudid1', 'client_secret': 'pcloudsecret1'}}
AUTH_HOST = {'gdrive': 'accounts.google.com', 'onedrive': 'login.microsoftonline.com', 'dropbox': 'www.dropbox.com',
             'box': 'account.box.com', 'pcloud': 'my.pcloud.com'}


class Response:
    def __init__(self, data, status=200):
        self.status_code, self._data = status, data

    def json(self):
        return self._data


class OAuthFlows(World):
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        self.addCleanup(shutil.rmtree, self.directory, True)
        patches = [mock.patch.object(clients, 'CLIENT_DIR', self.directory),
                   mock.patch.object(gdriveClient, 'CONFIG_PATH', os.path.join(self.directory, 'gdrive.json'))]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        for provider, client in FAKE_CLIENTS.items():
            clients.save(provider, client['client_id'], client['client_secret'])
        self.session = SessionStore()
        self.session['userID'] = self.u1.pk
        self.session.save()

    def request(self, method, path, data=None, session=None, origin=ORIGIN):
        factory = RequestFactory()
        headers = {'HTTP_HOST': HOST}
        if origin:
            headers['HTTP_ORIGIN'] = origin
        if method == 'GET':
            request = factory.get(path, data or {}, **headers)
        elif path.endswith('/begin'):
            request = factory.post(path, data=json.dumps(data or {}), content_type='application/json', **headers)
        else:
            request = factory.post(path, data=urlencode(data or {}), content_type='application/x-www-form-urlencoded',
                                   **headers)
        request.session = session or self.session
        request._dont_enforce_csrf_checks = True
        return request

    def begin(self, provider, body=None):
        response = oauth.begin(self.request('POST', '/addons/destinations/oauth/%s/begin' % provider,
                                            body or {'name': 'my ' + provider, 'folder': 'Site Backups'}), provider)
        return response, json.loads(response.content)

    def token_reply(self, provider):
        if provider == 'pcloud':
            return {'result': 0, 'access_token': 'pcloud-access', 'token_type': 'bearer', 'uid': 1}
        return {'access_token': provider + '-access', 'refresh_token': provider + '-refresh', 'expires_in': 3600,
                'token_type': 'Bearer', 'scope': 'https://www.googleapis.com/auth/drive.file'}

    def complete(self, provider, state, code='SYNTH-code_123.abc', extra=None):
        path = oauth.callback_path(provider)
        query = dict({'state': state, 'code': code}, **(extra or {}))
        page = oauth.callback(self.request('GET', path, query), provider)
        posts, gets = [], []

        def post(url, **kwargs):
            posts.append((url, kwargs))
            return Response(self.token_reply(provider))

        def get(url, **kwargs):
            gets.append((url, kwargs))
            if url == oauth.GRAPH_DRIVE:
                return Response({'id': 'b!synthDrive-1', 'driveType': 'business'})
            return Response(self.token_reply(provider))
        with mock.patch.object(oauth.requests, 'post', post), mock.patch.object(oauth.requests, 'get', get), \
                mock.patch('universalAddons.privileged.call_private', return_value={'saved': True}) as private:
            done = oauth.callback(self.request('POST', path, {'state': state, 'csrfmiddlewaretoken': 'x'}), provider)
        return page, done, posts, gets, private

    def test_every_provider_state_pkce_exchange_and_storage(self):
        for provider in providers.OAUTH_PROVIDERS:
            with self.subTest(provider=provider):
                response, data = self.begin(provider)
                self.assertEqual((response.status_code, data['status']), (200, 1), data)
                url = urlsplit(data['authorization_url'])
                params = {k: v[0] for k, v in parse_qs(url.query).items()}
                self.assertEqual((url.scheme, url.hostname), ('https', AUTH_HOST[provider]))
                self.assertEqual(params['client_id'], FAKE_CLIENTS[provider]['client_id'])
                self.assertEqual(params['redirect_uri'], ORIGIN + '/addons/destinations/oauth/%s/callback' % provider)
                self.assertEqual(params['response_type'], 'code')
                self.assertNotIn(FAKE_CLIENTS[provider]['client_secret'], data['authorization_url'])
                state = params['state']
                record = self.session[oauth.SESSION_KEY][state]
                self.assertEqual((record['provider'], record['user_id']), (provider, self.u1.pk))
                if oauth.OAUTH[provider]['pkce']:
                    expected = base64.urlsafe_b64encode(hashlib.sha256(record['verifier'].encode()).digest()).decode().rstrip('=')
                    self.assertEqual((params['code_challenge'], params['code_challenge_method']), (expected, 'S256'))
                else:
                    self.assertNotIn('code_challenge', params)
                extra = {'hostname': 'eapi.pcloud.com', 'locationid': '2'} if provider == 'pcloud' else None
                page, done, posts, gets, private = self.complete(provider, state, extra=extra)
                self.assertEqual(page.status_code, 200)
                self.assertNotIn('SYNTH-code_123.abc', page.content.decode(), 'code stays server-side')
                self.assertIn(state, page.content.decode())
                self.assertEqual(done.status_code, 200, done.content)
                if provider == 'pcloud':
                    self.assertEqual(gets[0][0], 'https://eapi.pcloud.com/oauth2_token')
                    self.assertEqual(gets[0][1]['params']['code'], 'SYNTH-code_123.abc')
                else:
                    url, kwargs = posts[0]
                    self.assertEqual(url, oauth.OAUTH[provider]['token'])
                    self.assertEqual(kwargs['data']['code'], 'SYNTH-code_123.abc')
                    self.assertEqual(kwargs['data']['redirect_uri'], params['redirect_uri'])
                    self.assertEqual(kwargs['data'].get('code_verifier'), record['verifier'])
                stored = private.call_args[1]['secrets']
                token = json.loads(stored['token'])
                self.assertEqual(token['access_token'], provider + '-access')
                self.assertEqual(token['token_type'], 'Bearer')
                if provider == 'pcloud':
                    self.assertEqual((stored['hostname'], token['expiry']), ('eapi.pcloud.com', '0001-01-01T00:00:00Z'))
                else:
                    self.assertEqual(token['refresh_token'], provider + '-refresh')
                    self.assertTrue(token['expiry'].endswith('Z'))
                if provider == 'onedrive':
                    self.assertEqual((stored['drive_id'], stored['drive_type']), ('b!synthDrive-1', 'business'))
                    self.assertEqual(gets[0][1]['headers']['Authorization'], 'Bearer onedrive-access')
                row = BackupDestination.objects.get(owner_id=self.u1.pk, name='my ' + provider)
                self.assertTrue(row.connected)
                self.assertEqual(json.loads(row.public_config), {'folder': 'Site Backups'})
                self.assertNotIn(provider + '-access', row.public_config)
                # state is single use
                _, again, posts2, _, private2 = self.complete(provider, state)
                self.assertEqual(again.status_code, 400)
                private2.assert_not_called()

    def test_state_bound_to_session_user_and_age(self):
        _, data = self.begin('dropbox')
        state = parse_qs(urlsplit(data['authorization_url']).query)['state'][0]
        other = SessionStore()
        other['userID'] = self.u1.pk
        other.save()
        path = oauth.callback_path('dropbox')
        self.assertEqual(oauth.callback(self.request('GET', path, {'state': state, 'code': 'abcdefgh12'},
                                                     session=other), 'dropbox').status_code, 400)
        self.assertEqual(oauth.callback(self.request('GET', path, {'state': 'A' * 43, 'code': 'abcdefgh12'}),
                                        'dropbox').status_code, 400)
        self.assertEqual(oauth.callback(self.request('GET', oauth.callback_path('box'),
                                                     {'state': state, 'code': 'abcdefgh12'}), 'box').status_code, 400)
        self.assertEqual(oauth.callback(self.request('GET', path, {'state': state, 'code': 'abcdefgh12', 'x': '1'}),
                                        'dropbox').status_code, 400)
        with mock.patch.object(oauth.time, 'time', return_value=time.time() + oauth.TTL + 1):
            self.assertEqual(oauth.callback(self.request('GET', path, {'state': state, 'code': 'abcdefgh12'}),
                                            'dropbox').status_code, 400)
        # POST without the same-origin header is refused before any exchange
        oauth.callback(self.request('GET', path, {'state': state, 'code': 'abcdefgh12'}), 'dropbox')
        with mock.patch.object(oauth.requests, 'post') as network:
            refused = oauth.callback(self.request('POST', path, {'state': state, 'csrfmiddlewaretoken': 'x'},
                                                  origin='null'), 'dropbox')
        self.assertEqual(refused.status_code, 400)
        network.assert_not_called()

    def test_begin_refusals(self):
        self.assertEqual(oauth.begin(self.request('POST', '/addons/destinations/oauth/dropbox/begin', {'name': 'a'},
                                                  origin='https://evil.example'), 'dropbox').status_code, 400)
        response, data = self.begin('dropbox', {'name': 'bad/name'})
        self.assertEqual(response.status_code, 400)
        response, _ = self.begin('dropbox', {'destination': self.d['u2'].pk})
        self.assertEqual(response.status_code, 403, 'cannot reconnect another account\'s destination')
        clients.clear('box')
        response, data = self.begin('box')
        self.assertEqual(response.status_code, 503)
        self.assertIn('not set up', data['error_message'])
        for _ in range(oauth.MAX_PENDING):
            self.begin('dropbox')
        self.assertEqual(self.begin('dropbox')[0].status_code, 429)

    def test_reconnect_updates_existing_destination(self):
        dest = BackupDestination.objects.create(owner_id=self.u1.pk, name='old drive', provider='gdrive',
                                                public_config=json.dumps({'folder': 'Old'}), connected=False)
        _, data = self.begin('gdrive', {'destination': dest.pk})
        self.assertTrue(data['reconnect'])
        state = parse_qs(urlsplit(data['authorization_url']).query)['state'][0]
        page, done, _, _, private = self.complete('gdrive', state)
        self.assertIn('Reconnect', page.content.decode())
        self.assertEqual(done.status_code, 200)
        self.assertEqual(private.call_args[1]['dest_id'], dest.pk)
        dest.refresh_from_db()
        self.assertTrue(dest.connected)
        self.assertEqual(BackupDestination.objects.filter(owner_id=self.u1.pk, provider='gdrive').count(), 1)

    def test_provider_error_saves_nothing(self):
        _, data = self.begin('onedrive')
        state = parse_qs(urlsplit(data['authorization_url']).query)['state'][0]
        page = oauth.callback(self.request('GET', oauth.callback_path('onedrive'),
                                           {'state': state, 'error': 'access_denied', 'error_description': 'no'}),
                              'onedrive')
        self.assertIn('Not connected', page.content.decode())
        self.assertFalse(BackupDestination.objects.filter(name='my onedrive').exists())

    def test_missing_refresh_token_is_refused(self):
        record = {'callback': 'https://x/cb', 'verifier': 'v'}
        with self.assertRaises(ValueError):
            oauth.exchange('dropbox', record, 'code', FAKE_CLIENTS['dropbox'],
                           post=lambda *a, **k: Response({'access_token': 'a', 'token_type': 'bearer', 'expires_in': 3600}))


# ----------------------------------------------------------------------------- rclone rendering

def obscured(value):
    return 'OBS[' + value + ']'


def section(text):
    lines = text.strip().split('\n')
    return lines[0], dict(line.split(' = ', 1) for line in lines[1:])


class RcloneConfig(SimpleTestCase):
    oauth_app = {"client_id": "cid1", "client_secret": "csecret1"}
    token = providers.rclone_token('acc', 'ref', 3600)

    def render(self, provider, public, secrets, client=None):
        clean = providers.validate_public(provider, public)
        return clean, section(providers.render('dst7', provider, clean, secrets, client, obscured))

    def test_oauth_providers(self):
        expected = {'gdrive': ('drive', {'scope': 'drive.file'}),
                    'onedrive': ('onedrive', {'drive_id': 'b!d1', 'drive_type': 'personal', 'region': 'global'}),
                    'dropbox': ('dropbox', {}), 'box': ('box', {}), 'pcloud': ('pcloud', {'hostname': 'api.pcloud.com'})}
        for provider, (kind, extra) in expected.items():
            with self.subTest(provider=provider):
                secrets = {'token': self.token, 'drive_id': 'b!d1', 'drive_type': 'personal', 'hostname': 'api.pcloud.com'}
                clean, (head, values) = self.render(provider, {'folder': 'My Backups'}, secrets, self.oauth_app)
                self.assertEqual(head, '[dst7]')
                self.assertEqual(values, dict({'type': kind, 'client_id': 'cid1', 'client_secret': 'csecret1',
                                               'token': self.token}, **extra))
                self.assertEqual(providers.repo_path(provider, clean), 'My Backups/restic')
                self.assertEqual(set(json.loads(values['token'])), {'access_token', 'token_type', 'refresh_token', 'expiry'})
        with self.assertRaises(providers.ProviderError):
            providers.render('dst7', 'dropbox', {'folder': 'x'}, {'token': self.token}, None, obscured)

    def test_s3_presets(self):
        keys = {'access_key_id': 'AKIA1234', 'secret_access_key': 'S3CRET/abc+def'}
        cases = {
            'aws': ({'region': 'eu-west-1'}, {'provider': 'AWS', 'region': 'eu-west-1'}),
            'b2s3': ({'region': 'us-west-004'}, {'provider': 'Other', 'region': 'us-west-004',
                                                 'endpoint': 'https://s3.us-west-004.backblazeb2.com'}),
            'wasabi': ({'region': 'eu-central-1'}, {'provider': 'Wasabi', 'region': 'eu-central-1',
                                                    'endpoint': 'https://s3.eu-central-1.wasabisys.com'}),
            'r2': ({'account_id': 'a' * 32}, {'provider': 'Cloudflare', 'region': 'auto',
                                              'endpoint': 'https://' + 'a' * 32 + '.r2.cloudflarestorage.com'}),
            'idrive': ({'endpoint': 'x1y2.va.idrivee2-3.com'}, {'provider': 'IDrive',
                                                               'endpoint': 'https://x1y2.va.idrivee2-3.com'}),
            'minio': ({'endpoint': 'minio.lan:9000', 'use_http': True}, {'provider': 'Minio',
                                                                         'endpoint': 'http://minio.lan:9000'}),
        }
        for preset, (public, expected) in cases.items():
            with self.subTest(preset=preset):
                clean, (_, values) = self.render('s3', dict(public, preset=preset, bucket='bkt', prefix='p/q'), keys)
                for key, value in expected.items():
                    self.assertEqual(values[key], value)
                if 'endpoint' not in expected:
                    self.assertNotIn('endpoint', values)
                self.assertEqual((values['type'], values['env_auth'], values['access_key_id'],
                                  values['secret_access_key'], values['no_check_bucket']),
                                 ('s3', 'false', 'AKIA1234', 'S3CRET/abc+def', 'true'))
                self.assertEqual(providers.repo_path('s3', clean), 'bkt/p/q/restic')
        with self.assertRaises(providers.ProviderError):
            providers.validate_public('s3', {'preset': 'r2', 'bucket': 'bkt', 'account_id': 'nothex'})

    def test_sftp_password_and_key(self):
        public = {'host': 'backup.example.net', 'port': '2222', 'user': 'bk', 'path': '/srv/backups', 'auth': 'password'}
        clean, (_, values) = self.render('sftp', public, {'password': 'p@ss'})
        self.assertEqual((values['type'], values['host'], values['port'], values['user'], values['pass']),
                         ('sftp', 'backup.example.net', '2222', 'bk', 'OBS[p@ss]'))
        self.assertEqual(values['shell_type'], 'none')
        self.assertEqual(providers.repo_path('sftp', clean), '/srv/backups/restic')
        key = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\n'
        secrets = providers.validate_secrets('sftp', dict(clean, auth='key'), {'private_key': key, 'key_passphrase': 'kp'})
        _, (_, values) = self.render('sftp', dict(public, auth='key'), secrets)
        self.assertEqual(values['key_pem'], '-----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\nBBBB\\n-----END OPENSSH PRIVATE KEY-----')
        self.assertEqual(values['key_file_pass'], 'OBS[kp]')
        self.assertNotIn('pass', values)

    def test_ftp_webdav_b2(self):
        for tls, expected in (('explicit', {'explicit_tls': 'true'}), ('implicit', {'tls': 'true'}), ('none', {})):
            _, (_, values) = self.render('ftp', {'host': 'ftp.example.net', 'user': 'f', 'tls': tls}, {'password': 'x'})
            self.assertEqual(values['pass'], 'OBS[x]')
            self.assertEqual({k: v for k, v in values.items() if k in ('tls', 'explicit_tls')}, expected)
            self.assertEqual(values['port'], '21')
        clean, (_, values) = self.render('webdav', {'vendor': 'nextcloud', 'host': 'cloud.example.net',
                                                    'dav_path': 'remote.php/dav/files/me', 'user': 'me'}, {'password': 'pw'})
        self.assertEqual((values['type'], values['url'], values['vendor'], values['pass']),
                         ('webdav', 'https://cloud.example.net/remote.php/dav/files/me', 'nextcloud', 'OBS[pw]'))
        self.assertEqual(providers.repo_path('webdav', clean), 'indianscloud-backups/restic')
        _, (_, values) = self.render('b2', {'bucket': 'my-bucket'}, {'account': 'kid', 'key': 'appkey'})
        self.assertEqual((values['type'], values['account'], values['key'], values['hard_delete']),
                         ('b2', 'kid', 'appkey', 'false'))

    def test_values_cannot_inject_config_lines(self):
        with self.assertRaises(providers.ProviderError):
            providers.render('dst7', 'b2', {'bucket': 'my-bucket'}, {'account': 'kid', 'key': 'a\n[evil]'}, None, obscured)
        with self.assertRaises(providers.ProviderError):
            providers.validate_secrets('ftp', {'tls': 'none'}, {'password': 'a\nb'})
        with self.assertRaises(providers.ProviderError):
            providers.validate_public('sftp', {'host': 'h.example.net', 'user': 'u', 'path': '../etc'})
        with self.assertRaises(providers.ProviderError):
            providers.render('Bad Remote', 'b2', {'bucket': 'my-bucket'}, {'account': 'k', 'key': 'v'}, None, obscured)

    def test_secrets_encoding_and_kept_values(self):
        blob = base64.b64encode(json.dumps({'password': 'a$b&c(d)\'e:f'}).encode()).decode()
        self.assertEqual(providers.decode_secrets(blob), {'password': 'a$b&c(d)\'e:f'})
        with self.assertRaises(providers.ProviderError):
            providers.decode_secrets('not base64!')
        public = providers.validate_public('ftp', {'host': 'ftp.example.net', 'user': 'f'})
        with self.assertRaises(providers.ProviderError):
            providers.validate_secrets('ftp', public, {})
        kept = providers.validate_secrets('ftp', public, {}, existing={'password': providers.KEPT})
        self.assertIs(kept['password'], providers.KEPT)
        self.assertEqual(providers.validate_secrets('ftp', public, {}, existing={'password': 'old'}), {'password': 'old'})


class CronLines(SimpleTestCase):
    def test_only_enabled_scheduled_jobs(self):
        records = [SimpleNamespace(pk=1, enabled=True, schedule='daily', hour=3),
                   SimpleNamespace(pk=2, enabled=False, schedule='daily', hour=3),
                   SimpleNamespace(pk=3, enabled=True, schedule='manual', hour=3),
                   SimpleNamespace(pk=4, enabled=True, schedule='weekly', hour=23)]
        lines = actions.cron_lines(records).strip().split('\n')
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[1].startswith('7 3 * * * root '))
        self.assertTrue(lines[2].startswith('28 23 * * 0 root '))
        self.assertIn('destinations run_scheduled', lines[1])


# ----------------------------------------------------------------------------- page render

class PageRender(World):
    def render(self, template, who, **context):
        from django.template.loader import render_to_string
        request = RequestFactory().get('/x', HTTP_HOST=HOST)
        request.session = {'userID': who.pk}
        return render_to_string(template, dict(context, request=request))

    def test_page_view_uses_template_for_every_account_type(self):
        captured = {}

        class Proc:
            def __init__(self, request, template, data=None, function=None):
                captured.update(template=template, function=function)

            def render(self):
                from django.http import HttpResponse
                return HttpResponse('page')
        for who in (self.admin, self.r, self.u1):
            request = RequestFactory().get('/addons/destinations/')
            request.session = {'userID': who.pk}
            with mock.patch('plogical.httpProc.httpProc', Proc):
                self.assertEqual(views.page(request).status_code, 200)
            self.assertEqual(captured, {'template': 'universalAddons/destinations.html', 'function': None})

    def test_destinations_page_renders(self):
        body = self.render('universalAddons/destinations.html', self.u1)
        for needle in ('Backup destinations', 'IndiansCloud', 'universalAddons/destinations.js', 'id="ua-destinations"',
                       'data-base="/addons/destinations/"', 'id="dst-provider"', 'id="site-dest"', 'id="apps-list"'):
            self.assertIn(needle, body)

    def test_google_drive_page_links_to_destinations(self):
        body = self.render('backup/googleDrive.html', self.admin, accounts=['old'], websites=[])
        self.assertIn('/addons/destinations/?provider=gdrive', body)
        self.assertNotIn('id="setupGdrive"', body)

    def test_backup_page_has_destination_dropdown(self):
        body = self.render('backup/backup.html', self.u1, websiteList=['u1site.example.com'])
        self.assertIn('id="site-destination-select"', body)
        self.assertIn('universalAddons/destinations-site.js', body)


# ----------------------------------------------------------------------------- Reconnect regression

class GoogleDriveReconnectRegression(SimpleTestCase):
    """Reconnect was disabled whenever the panel had no Google OAuth client (status enabled=false):
    clicking did nothing, and the reason was shown only inside the hidden Connect dialog."""

    def test_template_keeps_reconnect_clickable_and_shows_the_reason(self):
        template = (ROOT / 'backup/templates/backup/googleDrive.html').read_text()
        start = template.index('ng-click="reconnectAccount()"')
        button = template[start:template.index('>', start)]
        self.assertNotIn('gdriveSetupEnabled', button)
        self.assertIn('ng-if="selectedAccount && !gdriveSetupEnabled"', template)

    def test_controller_notifies_instead_of_returning_silently(self):
        for path in ('backup/static/backup/backup.js', 'static/backup/backup.js'):
            source = (ROOT / path).read_text()
            body = source[source.index('$scope.setupAccount = function'):source.index('$scope.reconnectAccount')]
            self.assertIn('if (!$scope.gdriveSetupEnabled) { setupUnavailable(); return; }', body, path)
            self.assertNotIn('if (!$scope.gdriveSetupEnabled || $scope.gdriveSetupPending) return;', body, path)

    def test_javascript_regression_suite(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('node is not installed')
        result = subprocess.run([node, str(ROOT / 'backup/test_gdrive_handoff.js')], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout.decode()[-2000:])

    def test_legacy_account_name_can_be_reconnected_by_its_owner_only(self):
        from IncBackups import gdrive_oauth as flow
        from IncBackups import test_gdrive_oauth as base
        case = base.FlowTests('test_authorization_url_goes_to_google_with_offline_consent_and_pkce')
        case.mode, case.path = 'normal', '/backup/gDriveSetup'
        case.setUp()
        try:
            owner = mock.patch.object(flow, '_account_owner', return_value=7)
            with owner:
                response = flow.begin(case.request('POST', {'accountName': 'my drive.backup'}), mode='normal')
            self.assertEqual(response.status_code, 200, response.content)
            record = list(case.session[flow.SESSION_KEY].values())[0]
            self.assertEqual((record['account'], record['reconnect']), ('my drive.backup', True))
            for owner_id in (None, 99):
                with mock.patch.object(flow, '_account_owner', return_value=owner_id):
                    response = flow.begin(case.request('POST', {'accountName': 'other drive.x'}), mode='normal')
                self.assertEqual(response.status_code, 400)
        finally:
            case.doCleanups()
