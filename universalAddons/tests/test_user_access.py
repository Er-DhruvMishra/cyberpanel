"""Site owners and the add-ons opened to them: policy off, foreign site, own site, admin-only actions,
jobs and pages. Root-side checks that back the web layer are tested further down."""
import os
import shutil
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from universalAddons import access
from universalAddons.backupv2 import views as backup_views
from universalAddons.emaildebug import views as emaildebug_views
from universalAddons.htaccess import views as htaccess_views
from universalAddons.limits import views as limits_views
from universalAddons.sslv2 import views as ssl_views
from universalAddons.tests import helpers
from universalAddons.tests.helpers import FOREIGN, OWNED
from universalAddons.wordpress import views as wp_views

MINE = OWNED[0]
JOB = 'ab' * 12


class Base(SimpleTestCase):
    FEATURE = None

    def call(self, view, body, admin=False, on=True, session=None, result=None):
        """(status, body, runner mock, session) for a request by a user (or administrator)."""
        policy = {self.FEATURE: True} if on else {}
        with mock.patch('universalAddons.privileged.call', return_value=result if result is not None else {}) as runner:
            status, data, session = helpers.post(view, body, session=session, admin=admin, policy=policy)
        return status, data, runner, session

    def assertRefused(self, view, body, on=True, status=403):
        code, data, runner, _ = self.call(view, body, on=on)
        self.assertEqual(code, status, (view.__name__, body, data))
        runner.assert_not_called()

    def assertRunner(self, view, body, *expected, admin=False, result=None, **kwargs):
        code, data, runner, session = self.call(view, body, admin=admin, result=result)
        self.assertEqual(code, 200, (view.__name__, body, data))
        runner.assert_called_once_with(*expected, **kwargs)
        return data, session


# ----------------------------------------------------------------------------- WordPress

class WordPressUsers(Base):
    FEATURE = 'wordpress_for_users'
    SITE_ACTIONS = [
        ('info', {}), ('item', {'kind': 'plugin', 'action': 'update', 'slug': 'akismet'}),
        ('flag', {'flag': 'WP_DEBUG', 'enable': False}), ('autoupdates', {'kind': 'plugin', 'enable': True}),
        ('hardening', {}), ('fix', {'fix': 'xmlrpc'}), ('performance', {'what': 'lscache'}), ('login', {}),
        ('snapshots', {}), ('update', {'scope': 'all'}), ('snapshot', {}), ('rollback', {'snapshot': '20250101-010101-abcd'}),
        ('install', {'title': 'Blog', 'adminUser': 'me', 'adminEmail': 'me@example.com'}),
    ]

    def test_policy_off_refuses_everything(self):
        for name, extra in self.SITE_ACTIONS + [('sites', {}), ('job', {'job': JOB})]:
            self.assertRefused(getattr(wp_views, name), dict(extra, domain=MINE), on=False)

    def test_foreign_site_refused_on_every_action(self):
        for name, extra in self.SITE_ACTIONS:
            self.assertRefused(getattr(wp_views, name), dict(extra, domain=FOREIGN))
        self.assertRefused(wp_views.clone, {'source': MINE, 'target': FOREIGN})
        self.assertRefused(wp_views.clone, {'source': FOREIGN, 'target': MINE})
        self.assertRefused(wp_views.push, {'staging': MINE, 'production': FOREIGN})
        self.assertRefused(wp_views.push, {'staging': FOREIGN, 'production': MINE})

    def test_own_site_allowed(self):
        for name, extra in self.SITE_ACTIONS:
            code, data, runner, _ = self.call(getattr(wp_views, name), dict(extra, domain=MINE.upper()))
            self.assertEqual(code, 200, (name, data))
            self.assertEqual(runner.call_args[1].get('domain'), MINE, name)

    def test_listing_is_limited_to_own_sites(self):
        self.assertRunner(wp_views.sites, {}, 'wordpress', 'list', domains=sorted(OWNED))
        self.assertRunner(wp_views.sites, {}, 'wordpress', 'list', domains=None, admin=True)

    def test_database_quota_applies_to_users_only(self):
        self.assertRunner(wp_views.clone, {'source': MINE, 'target': OWNED[1]}, 'wordpress', 'clone',
                          source=MINE, target=OWNED[1], quota=True)
        self.assertRunner(wp_views.clone, {'source': MINE, 'target': FOREIGN}, 'wordpress', 'clone',
                          source=MINE, target=FOREIGN, quota=False, admin=True)
        data, _ = self.assertRunner(wp_views.install, {'domain': MINE, 'title': 't', 'adminUser': 'a', 'adminEmail': 'a@b.co'},
                                    'wordpress', 'install', domain=MINE, title='t', admin_user='a',
                                    admin_email='a@b.co', locale='en_US', quota=True)

    def test_wpcli_update_is_admin_only(self):
        self.assertRefused(wp_views.wpcli, {})
        self.assertRunner(wp_views.wpcli, {}, 'wordpress', 'wpcli_update', admin=True)

    def test_jobs_only_visible_to_the_session_that_started_them(self):
        _, session = self.assertRunner(wp_views.snapshot, {'domain': MINE}, 'wordpress', 'snapshot', domain=MINE,
                                       result={'job_id': JOB})
        self.assertIn('wordpress:' + JOB, session[access.JOBS_SESSION_KEY])
        code, _, runner, _ = self.call(wp_views.job, {'job': JOB}, session=session)
        self.assertEqual(code, 200)
        runner.assert_called_once_with('wordpress', 'job', job_id=JOB)
        self.assertRefused(wp_views.job, {'job': JOB})                    # another session
        self.assertRefused(wp_views.job, {'job': 'cd' * 12})
        code, _, runner, _ = self.call(wp_views.job, {'job': 'cd' * 12}, admin=True)
        self.assertEqual(code, 200)                                       # administrators see every job

    def test_remembered_jobs_are_bounded(self):
        session = {'userID': 7}
        request = SimpleNamespace(session=session)
        for n in range(access.MAX_REMEMBERED_JOBS + 10):
            access.remember_job(request, 'wordpress', {'job_id': '%024x' % n})
        self.assertEqual(len(session[access.JOBS_SESSION_KEY]), access.MAX_REMEMBERED_JOBS)
        access.remember_job(request, 'wordpress', {'no': 'job'})
        self.assertEqual(len(session[access.JOBS_SESSION_KEY]), access.MAX_REMEMBERED_JOBS)


# ----------------------------------------------------------------------------- Backup V2

class BackupUsers(Base):
    FEATURE = 'backup_for_users'
    SNAP = 'abcdef12'

    def test_policy_off_refused(self):
        for name, body in (('overview', {}), ('backup_now', {'repo': 'r', 'domain': MINE}),
                           ('snapshots', {'repo': 'r', 'domain': MINE}),
                           ('ls', {'repo': 'r', 'domain': MINE, 'snapshot': self.SNAP}),
                           ('restore', {'repo': 'r', 'domain': MINE, 'snapshot': self.SNAP, 'kind': 'files'}),
                           ('job', {'job': JOB})):
            self.assertRefused(getattr(backup_views, name), body, on=False)

    def test_foreign_site_refused(self):
        for name, body in (('backup_now', {'repo': 'r', 'domain': FOREIGN}),
                           ('snapshots', {'repo': 'r', 'domain': FOREIGN}),
                           ('ls', {'repo': 'r', 'domain': FOREIGN, 'snapshot': self.SNAP}),
                           ('restore', {'repo': 'r', 'domain': FOREIGN, 'snapshot': self.SNAP, 'kind': 'files'}),
                           ('restore', {'repo': 'r', 'domain': FOREIGN, 'snapshot': self.SNAP, 'kind': 'db',
                                        'database': 'x_wp'})):
            self.assertRefused(getattr(backup_views, name), body)

    def test_users_must_name_a_site(self):
        self.assertRefused(backup_views.snapshots, {'repo': 'r'}, status=400)
        self.assertRefused(backup_views.ls, {'repo': 'r', 'snapshot': self.SNAP}, status=400)

    def test_own_site_goes_to_the_user_actions(self):
        self.assertRunner(backup_views.overview, {}, 'backupv2', 'user_overview', domains=sorted(OWNED))
        self.assertRunner(backup_views.snapshots, {'repo': 'r', 'domain': MINE}, 'backupv2', 'user_snapshots',
                          repo_id='r', domain=MINE)
        self.assertRunner(backup_views.ls, {'repo': 'r', 'domain': MINE, 'snapshot': self.SNAP, 'path': '/home'},
                          'backupv2', 'user_ls', repo_id='r', domain=MINE, snapshot=self.SNAP, path='/home')
        self.assertRunner(backup_views.backup_now, {'repo': 'r', 'domain': MINE}, 'backupv2', 'user_backup',
                          repo_id='r', domain=MINE)
        self.assertRunner(backup_views.restore, {'repo': 'r', 'domain': MINE, 'snapshot': self.SNAP, 'kind': 'files',
                                                 'include': '/home/%s/public_html' % MINE},
                          'backupv2', 'user_restore', repo_id='r', snapshot=self.SNAP, domain=MINE, kind='files',
                          include='/home/%s/public_html' % MINE, database='')
        self.assertRunner(backup_views.restore, {'repo': 'r', 'domain': MINE, 'snapshot': self.SNAP, 'kind': 'db',
                                                 'database': 'mine_wp'},
                          'backupv2', 'user_restore', repo_id='r', snapshot=self.SNAP, domain=MINE, kind='db',
                          include='', database='mine_wp')

    def test_user_restores_stay_inside_the_site(self):
        base = {'repo': 'r', 'domain': MINE, 'snapshot': self.SNAP, 'kind': 'files'}
        self.assertRefused(backup_views.restore, dict(base, target='/home/restore-x'))
        self.assertRefused(backup_views.restore, dict(base, include='/home/%s/public_html' % FOREIGN))
        self.assertRefused(backup_views.restore, dict(base, include='/etc/passwd'))
        self.assertRefused(backup_views.restore, dict(base, kind='db', database='x;drop'), status=400)
        # the site home itself means "the whole snapshot"
        self.assertRunner(backup_views.restore, dict(base, include='/home/%s/' % MINE), 'backupv2', 'user_restore',
                          repo_id='r', snapshot=self.SNAP, domain=MINE, kind='files', include='', database='')

    def test_admin_keeps_full_access(self):
        self.assertRunner(backup_views.overview, {}, 'backupv2', 'overview', admin=True)
        self.assertRunner(backup_views.snapshots, {'repo': 'r'}, 'backupv2', 'snapshots', repo_id='r', domain='',
                          admin=True)
        self.assertRunner(backup_views.restore, {'repo': 'r', 'domain': FOREIGN, 'snapshot': self.SNAP, 'kind': 'files',
                                                 'target': '/home/restore-x'},
                          'backupv2', 'restore', repo_id='r', snapshot=self.SNAP, domain=FOREIGN, kind='files',
                          target='/home/restore-x', include='', database='', admin=True)

    def test_repositories_schedules_and_keys_are_admin_only(self):
        for name in ('save_repo', 'export_key', 'ssh_key', 'save_policy', 'delete_policy', 'run_now', 'check'):
            self.assertRefused(getattr(backup_views, name), {'repo': 'r', 'policy': 'p', 'id': 'r', 'type': 'local'})

    def test_repo_flag_for_users_is_forwarded(self):
        self.assertRunner(backup_views.save_repo, {'id': 'r', 'type': 'local', 'path': '/backup', 'for_users': True},
                          'backupv2', 'save_repo', spec={'id': 'r', 'type': 'local', 'path': '/backup', 'for_users': True},
                          access_key='', secret_key='', admin=True)

    def test_jobs_bound_to_session(self):
        _, session = self.assertRunner(backup_views.backup_now, {'repo': 'r', 'domain': MINE}, 'backupv2',
                                       'user_backup', repo_id='r', domain=MINE, result={'job_id': JOB})
        self.assertEqual(self.call(backup_views.job, {'job': JOB}, session=session)[0], 200)
        self.assertRefused(backup_views.job, {'job': JOB})


# ----------------------------------------------------------------------------- SSL V2

class SslUsers(Base):
    FEATURE = 'ssl_for_users'

    def issue(self, **extra):
        return dict({'domain': MINE, 'provider': 'pdns', 'wildcard': False}, **extra)

    def no_subdomains(self):
        return mock.patch('universalAddons.sslv2.views._foreign_subdomains', return_value=[])

    def test_policy_off_refused(self):
        for name, body in (('inventory', {}), ('check', {'domain': MINE, 'provider': 'pdns'}), ('issue', self.issue()),
                           ('job', {'job': JOB})):
            self.assertRefused(getattr(ssl_views, name), body, on=False)

    def test_foreign_domain_refused(self):
        self.assertRefused(ssl_views.check, {'domain': FOREIGN, 'provider': 'pdns'})
        self.assertRefused(ssl_views.issue, self.issue(domain=FOREIGN))
        with mock.patch('universalAddons.sslv2.views._alias_domains', return_value=set()):
            self.assertRefused(ssl_views.issue, self.issue(aliases=[FOREIGN]))

    def test_own_domain_allowed(self):
        self.assertRunner(ssl_views.check, {'domain': MINE, 'provider': 'pdns'}, 'sslv2', 'check', domain=MINE,
                          provider='pdns')
        with self.no_subdomains():
            self.assertRunner(ssl_views.issue, self.issue(aliases=[OWNED[1]], wildcard=True), 'sslv2', 'issue',
                              domain=MINE, provider='pdns', wildcard=True, aliases=[OWNED[1]], ca='letsencrypt',
                              key='ec-256', email='', cf_token='', result={'job_id': JOB})
        with mock.patch('universalAddons.sslv2.views._alias_domains', return_value={'parked.example.org'}):
            code, data, runner, _ = self.call(ssl_views.issue, self.issue(aliases=['parked.example.org']))
        self.assertEqual(code, 200, data)

    def test_wildcard_refused_when_it_covers_another_accounts_site(self):
        with mock.patch('universalAddons.sslv2.views._foreign_subdomains', return_value=['shop.' + MINE]):
            self.assertRefused(ssl_views.issue, self.issue(wildcard=True))

    def test_user_restrictions(self):
        self.assertRefused(ssl_views.issue, self.issue(ca='zerossl', email='a@b.co'), status=400)
        self.assertRefused(ssl_views.issue, self.issue(provider='cloudflare'), status=400)  # no saved admin token
        self.assertRunner(ssl_views.issue, self.issue(provider='cloudflare', cfToken='A' * 40), 'sslv2', 'issue',
                          domain=MINE, provider='cloudflare', wildcard=False, aliases=[], ca='letsencrypt', key='ec-256',
                          email='', cf_token='A' * 40)

    def test_inventory_limited_and_hides_saved_token(self):
        data, _ = self.assertRunner(ssl_views.inventory, {}, 'sslv2', 'inventory', domains=sorted(OWNED),
                                    result={'certificates': [], 'saved_cloudflare_token': True})
        self.assertNotIn('saved_cloudflare_token', data['result'])
        data, _ = self.assertRunner(ssl_views.inventory, {}, 'sslv2', 'inventory', admin=True,
                                    result={'certificates': [], 'saved_cloudflare_token': True})
        self.assertTrue(data['result']['saved_cloudflare_token'])

    def test_monitor_is_admin_only(self):
        self.assertRefused(ssl_views.monitor, {})
        self.assertRefused(ssl_views.monitor, {'enable': True})

    def test_jobs_bound_to_session(self):
        _, session = self.assertRunner(ssl_views.issue, self.issue(), 'sslv2', 'issue', domain=MINE, provider='pdns',
                                       wildcard=False, aliases=[], ca='letsencrypt', key='ec-256', email='',
                                       cf_token='', result={'job_id': JOB})
        self.assertEqual(self.call(ssl_views.job, {'job': JOB}, session=session)[0], 200)
        self.assertRefused(ssl_views.job, {'job': JOB})


# ----------------------------------------------------------------------------- .htaccess

class HtaccessUsers(Base):
    FEATURE = 'htaccess_for_users'

    def test_policy_off_refused(self):
        for name in ('overview', 'preview', 'enable', 'disable'):
            self.assertRefused(getattr(htaccess_views, name), {'domain': MINE}, on=False)

    def test_foreign_site_refused(self):
        for name in ('preview', 'enable', 'disable'):
            self.assertRefused(getattr(htaccess_views, name), {'domain': FOREIGN})

    def test_own_site_allowed_with_user_limits(self):
        self.assertRunner(htaccess_views.overview, {}, 'htaccess', 'overview', domains=sorted(OWNED))
        self.assertRunner(htaccess_views.enable, {'domain': MINE}, 'htaccess', 'enable', domain=MINE, by_user=True,
                          min_interval=htaccess_views.USER_MIN_INTERVAL)
        self.assertRunner(htaccess_views.disable, {'domain': MINE}, 'htaccess', 'disable', domain=MINE,
                          min_interval=htaccess_views.USER_MIN_INTERVAL)
        self.assertRunner(htaccess_views.enable, {'domain': FOREIGN}, 'htaccess', 'enable', domain=FOREIGN, admin=True)

    def test_preview_shows_users_only_the_generated_block(self):
        vhost = 'docRoot /home/x\n# BEGIN cp-ua-htaccess (generated)\ncontext / {\n}\n# END cp-ua-htaccess\nsecret 1\n'
        data, _ = self.assertRunner(htaccess_views.preview, {'domain': MINE}, 'htaccess', 'preview', domain=MINE,
                                    result={'vhost_after': vhost, 'vhost_path': '/usr/local/lsws/x', 'report': []})
        self.assertNotIn('secret', data['result']['vhost_after'])
        self.assertTrue(data['result']['vhost_after'].startswith('# BEGIN cp-ua-htaccess'))
        self.assertNotIn('vhost_path', data['result'])
        data, _ = self.assertRunner(htaccess_views.preview, {'domain': MINE}, 'htaccess', 'preview', domain=MINE,
                                    admin=True, result={'vhost_after': vhost, 'vhost_path': '/p', 'report': []})
        self.assertEqual(data['result']['vhost_after'], vhost)


# ----------------------------------------------------------------------------- Email Debugger

class EmailDebugUsers(Base):
    FEATURE = 'email_debug_for_users'

    def test_policy_off_refused(self):
        self.assertRefused(emaildebug_views.dns, {'domain': MINE}, on=False)
        self.assertRefused(emaildebug_views.context, {}, on=False)

    def test_foreign_domain_refused(self):
        self.assertRefused(emaildebug_views.dns, {'domain': FOREIGN})
        self.assertRefused(emaildebug_views.dns, {'domain': 'gmail.com'})

    def test_own_domain_allowed(self):
        self.assertRunner(emaildebug_views.dns, {'domain': MINE}, 'emaildebug', 'dns', domain=MINE)
        self.assertRunner(emaildebug_views.context, {}, 'emaildebug', 'context')
        self.assertRunner(emaildebug_views.dns, {'domain': 'gmail.com'}, 'emaildebug', 'dns', domain='gmail.com',
                          admin=True)

    def test_server_wide_tools_are_admin_only(self):
        for name, body in (('ports', {'target': 'local'}), ('logs', {'query': MINE}), ('queue', {}),
                           ('spam', {'emailMessage': 'Subject: x\n\nhi'}),
                           ('send', {'sender': 'a@' + MINE, 'recipient': 'b@example.org'})):
            self.assertRefused(getattr(emaildebug_views, name), body)


# ----------------------------------------------------------------------------- Resource Limits

class LimitsUsers(Base):
    FEATURE = 'limits_for_users'

    def test_policy_off_refused(self):
        self.assertRefused(limits_views.overview, {}, on=False)

    def test_users_read_their_own_sites_only(self):
        self.assertRunner(limits_views.overview, {}, 'limits', 'site_usage', domains=sorted(OWNED))
        self.assertRunner(limits_views.overview, {}, 'limits', 'overview', admin=True)

    def test_every_change_is_admin_only(self):
        for name, body in (('save', {'scope': 'site', 'name': MINE, 'limits': {}}),
                           ('preview', {'scope': 'site', 'name': MINE}),
                           ('apply', {'scope': 'site', 'name': MINE, 'token': '0' * 32}), ('du_scan', {}),
                           ('job', {'job': JOB})):
            self.assertRefused(getattr(limits_views, name), body)


# ----------------------------------------------------------------------------- apps (existing module)

class AppsJobs(Base):
    FEATURE = 'apps_for_users'

    def test_deploy_job_only_visible_to_the_session_that_started_it(self):
        from universalAddons.apps import views as apps_views
        _, session = self.assertRunner(apps_views.deploy, {'domain': MINE, 'app': 'api'}, 'apps', 'deploy',
                                       app_id='api', domain=MINE, result={'job_id': JOB})
        self.assertEqual(self.call(apps_views.job, {'job': JOB}, session=session)[0], 200)
        self.assertRefused(apps_views.job, {'job': JOB})


# ----------------------------------------------------------------------------- pages

class Pages(SimpleTestCase):
    OPENED = (('wordpress', 'wordpress_for_users'), ('backupv2', 'backup_for_users'), ('sslv2', 'ssl_for_users'),
              ('htaccess', 'htaccess_for_users'), ('emaildebug', 'email_debug_for_users'),
              ('limits', 'limits_for_users'))
    ADMIN_ONLY = ('rootfm', 'storage', 'sshsec', 'mysqlmgr', 'rspamd', 'apache', 'roundcube')

    def view(self, module):
        import importlib
        return importlib.import_module('universalAddons.%s.views' % module).page

    def test_opened_pages_follow_the_policy(self):
        for module, switch in self.OPENED:
            with mock.patch('universalAddons.emaildebug.views._own_mail_domains', return_value=[MINE]):
                status, values = helpers.page(self.view(module), policy={})
                self.assertEqual((status, values), (403, None), module)
                status, values = helpers.page(self.view(module), policy={switch: True})
                self.assertEqual(status, 200, module)
                self.assertIs(values['is_admin'], False, module)
                self.assertIsNone(values['_function'], module)
                status, values = helpers.page(self.view(module), admin=True)
                self.assertEqual(status, 200, module)
                self.assertIs(values['is_admin'], True, module)

    def test_email_debugger_lists_only_own_mail_domains(self):
        with mock.patch('universalAddons.emaildebug.views._own_mail_domains', return_value=[MINE]), \
                mock.patch('universalAddons.emaildebug.views._hosted_domains', return_value=[MINE, FOREIGN]):
            self.assertEqual(helpers.page(self.view('emaildebug'), policy={'email_debug_for_users': True})[1]['domains'],
                             [MINE])
            self.assertEqual(helpers.page(self.view('emaildebug'), admin=True)[1]['domains'], [MINE, FOREIGN])

    def test_admin_only_pages_answer_403_to_users(self):
        everything_on = {switch: True for _, switch in access.USER_FEATURES}
        for module in self.ADMIN_ONLY:
            status, values = helpers.page(self.view(module), policy=everything_on)
            self.assertEqual((status, values), (403, None), module)

    def test_admin_only_pages_render_for_admins(self):
        for module in self.ADMIN_ONLY:
            with mock.patch('universalAddons.roundcube.views.httpProc') as proc, \
                    mock.patch('universalAddons.roundcube.views.ACLManager.findAllSites', return_value=[]):
                proc.return_value.render.return_value = __import__('django.http').http.HttpResponse('page')
                status, _ = helpers.page(self.view(module), admin=True)
            self.assertEqual(status, 200, module)


# ----------------------------------------------------------------------------- root side: WordPress

class WordPressRoot(unittest.TestCase):
    def test_list_filters_to_given_domains(self):
        from universalAddons.wordpress import actions
        rows = [(MINE, 'mine', '/nonexistent/a', MINE), (FOREIGN, 'other', '/nonexistent/b', FOREIGN)]
        with mock.patch.object(actions, '_docroots', return_value=rows), \
                mock.patch.object(actions.wp, 'find_installs', side_effect=lambda r: [
                    {'domain': d, 'user': u, 'docroot': p, 'vhost': v} for d, u, p, v in r]), \
                mock.patch.object(actions, '_wp_cli_version', return_value=''):
            self.assertEqual([i['domain'] for i in actions.list_sites([MINE])['installs']], [MINE])
            self.assertEqual(len(actions.list_sites()['installs']), 2)

    def test_quota(self):
        from universalAddons.wordpress import actions

        def site(allowed, used):
            return SimpleNamespace(domain=MINE, package=SimpleNamespace(dataBases=allowed, packageName='p'),
                                   databases_set=SimpleNamespace(count=lambda: used))
        self.assertTrue(actions._within_quota(site(0, 50)))      # 0 = unlimited, as in the panel
        self.assertTrue(actions._within_quota(site(2, 1)))
        self.assertFalse(actions._within_quota(site(2, 2)))
        with mock.patch.object(actions, '_website', return_value=site(1, 1)):
            with self.assertRaises(actions.WPError):
                actions._check_quota(MINE)


# ----------------------------------------------------------------------------- root side: .htaccess

class HtaccessRoot(unittest.TestCase):
    def setUp(self):
        from universalAddons.htaccess import actions
        self.actions = actions
        self.state = {'sites': {}, 'blocks': [{'domain': MINE, 'ip': '192.0.2.1', 'at': int(time.time())},
                                              {'domain': FOREIGN, 'ip': '192.0.2.2', 'at': int(time.time())}]}
        self.patches = [mock.patch.object(actions.hs, 'load_state', side_effect=lambda: self.state),
                        mock.patch.object(actions.hs, 'save_state'),
                        mock.patch.object(actions, '_sites', return_value={MINE: ('/d', '/h'), FOREIGN: ('/d2', '/h2')}),
                        mock.patch.object(actions.hs, 'plan', side_effect=lambda d, *a: {
                            'domain': d, 'fingerprint': 'f', 'bruteforce': {'enabled': True, 'action': 'block'},
                            'changed': False}),
                        mock.patch.object(actions.hs, 'apply_plans', return_value={'applied': []}),
                        mock.patch.object(actions, '_ensure_cron')]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def test_overview_filtered_with_own_blocks_only(self):
        result = self.actions.overview([MINE])
        self.assertEqual([s['domain'] for s in result['sites']], [MINE])
        self.assertEqual([b['domain'] for b in result['blocks']], [MINE])
        self.assertEqual(len(self.actions.overview()['blocks']), 2)

    def test_owner_enabled_sites_never_block_in_the_firewall(self):
        self.actions.enable(MINE, by_user=True, min_interval=60)
        self.assertTrue(self.state['sites'][MINE]['by_user'])
        self.assertEqual(self.actions._guard_configs(self.state)[MINE]['action'], 'log')
        self.state['changed'] = {}
        self.actions.enable(MINE)  # an administrator takes the site over
        self.assertFalse(self.state['sites'][MINE]['by_user'])
        self.assertEqual(self.actions._guard_configs(self.state)[MINE]['action'], 'block')

    def test_owner_applies_are_rate_limited(self):
        self.actions.enable(MINE, by_user=True, min_interval=60)
        with self.assertRaises(self.actions.HtaccessError):
            self.actions.enable(MINE, by_user=True, min_interval=60)
        with self.assertRaises(self.actions.HtaccessError):
            self.actions.disable(MINE, min_interval=60)
        self.actions.enable(FOREIGN, by_user=True, min_interval=60)  # other sites are not affected


# ----------------------------------------------------------------------------- root side: SSL, limits

class SslAndLimitsRoot(unittest.TestCase):
    def test_ssl_inventory_filtered(self):
        from universalAddons.sslv2 import actions
        with mock.patch.object(actions, '_panel_domains', return_value=[MINE, FOREIGN]), \
                mock.patch.object(actions.service, 'inventory', side_effect=lambda names: [{'domain': n} for n in names]), \
                mock.patch.object(actions, '_saved_cf_token', return_value=False):
            self.assertEqual([r['domain'] for r in actions.inventory([MINE])['certificates']], [MINE])
            self.assertEqual(len(actions.inventory()['certificates']), 2)

    def test_limits_site_usage_filtered_and_read_only(self):
        from universalAddons.limits import actions
        sites = [{'domain': MINE, 'user': 'mine', 'package': 'p', 'state': 1},
                 {'domain': FOREIGN, 'user': 'other', 'package': 'p', 'state': 1}]
        with mock.patch.object(actions, '_sites', return_value=sites), \
                mock.patch.object(actions.sv, 'load_store', return_value={'packages': {}, 'overrides': {}}), \
                mock.patch.object(actions, '_defaults', return_value=({}, {'children': 4})), \
                mock.patch.object(actions.sv, 'usage_by_user', return_value={'mine': {'lsphp': 1}}) as usage, \
                mock.patch.object(actions.sv, 'quota_report', return_value={'users': {}}), \
                mock.patch.object(actions.sv, 'load_du_cache', return_value={}):
            result = actions.site_usage([MINE])
        self.assertEqual([r['domain'] for r in result['sites']], [MINE])
        self.assertEqual(result['sites'][0]['effective'], {'children': 4})
        usage.assert_called_once_with(['mine'])  # other users' processes are not even read
        self.assertNotIn('host', result)


# ----------------------------------------------------------------------------- root side: Backup V2

class BackupRoot(unittest.TestCase):
    def setUp(self):
        from universalAddons.backupv2 import actions
        self.actions = actions
        self.repos = {'open': {'id': 'open', 'type': 'local', 'path': '/b', 'for_users': True},
                      'closed': {'id': 'closed', 'type': 'local', 'path': '/c'}}
        self.store = {}
        self.patches = [mock.patch.object(actions.bk, '_load', side_effect=lambda n: self.repos if n == 'repos.json'
                                          else dict(self.store.get(n, {}))),
                        mock.patch.object(actions.bk, '_save', side_effect=lambda n, d: self.store.__setitem__(n, d)),
                        mock.patch.object(actions, '_sites', return_value=sorted([MINE, FOREIGN])),
                        mock.patch.object(actions, '_databases', side_effect=lambda d: ['mine_wp'] if d == MINE else ['other_wp']),
                        mock.patch.object(actions.jobs, 'spawn', return_value={'job_id': JOB})]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def test_overview_shows_open_repositories_without_details(self):
        with mock.patch.object(self.actions.bk, 'list_repos', return_value=list(self.repos.values())):
            result = self.actions.user_overview([MINE, 'blog.' + MINE])
        self.assertEqual(result['repos'], [{'id': 'open', 'name': 'open'}])   # no path, host or credentials
        self.assertEqual(result['sites'], [MINE])

    def test_closed_repository_and_unknown_site_refused(self):
        BackupError = self.actions.BackupError
        for call in (lambda: self.actions.user_backup('closed', MINE), lambda: self.actions.user_snapshots('closed', MINE),
                     lambda: self.actions.user_backup('nope', MINE), lambda: self.actions.user_backup('open', 'x.invalid'),
                     lambda: self.actions.user_restore('closed', 'abcdef12', MINE, 'files')):
            with self.assertRaises(BackupError):
                call()

    def test_backup_now_is_rate_limited_per_site(self):
        self.assertEqual(self.actions.user_backup('open', MINE), {'job_id': JOB})
        with self.assertRaises(self.actions.BackupError):
            self.actions.user_backup('open', MINE)
        self.assertEqual(self.actions.user_backup('open', FOREIGN), {'job_id': JOB})

    def test_restore_checks_database_and_uses_the_full_snapshot_id(self):
        item = {'full_id': 'abcdef12' + '0' * 56}
        with self.assertRaises(self.actions.BackupError):
            self.actions.user_restore('open', 'abcdef12', MINE, 'db', database='other_wp')
        with mock.patch.object(self.actions.bk, 'snapshot_for_site', return_value=item) as check:
            self.actions.user_restore('open', 'abcdef12', MINE, 'db', database='mine_wp')
        check.assert_called_once_with(self.repos['open'], 'abcdef12', MINE, 'db', 'mine_wp')
        self.assertEqual(self.actions.jobs.spawn.call_args[0][2]['snapshot'], item['full_id'])


class SnapshotOwnership(unittest.TestCase):
    """snapshot_for_site / site_snapshots against parsed restic listings."""

    def setUp(self):
        from universalAddons.backupv2 import service as bk
        self.bk = bk
        home = '/home/' + MINE
        self.listing = [
            {'id': 'aaaaaaa1', 'full_id': 'aaaaaaa1' + '1' * 56, 'site': MINE, 'unit': 'files', 'paths': [home],
             'database': '', 'tags': []},
            {'id': 'bbbbbbb2', 'full_id': 'bbbbbbb2' + '2' * 56, 'site': MINE, 'unit': 'db', 'paths': ['/db/mine_wp.sql'],
             'database': 'mine_wp', 'tags': []},
            {'id': 'ccccccc3', 'full_id': 'ccccccc3' + '3' * 56, 'site': MINE, 'unit': 'config',
             'paths': ['/usr/local/lsws/conf/vhosts/' + MINE], 'database': '', 'tags': []},
            {'id': 'ddddddd4', 'full_id': 'ddddddd4' + '4' * 56, 'site': MINE, 'unit': 'mail',
             'paths': ['/home/vmail/' + MINE], 'database': '', 'tags': []},
            {'id': 'eeeeeee5', 'full_id': 'eeeeeee5' + '5' * 56, 'site': FOREIGN, 'unit': 'files',
             'paths': ['/home/' + FOREIGN], 'database': '', 'tags': []},
        ]

    def snapshots(self, repo, domain=None, *a, **k):
        return [s for s in self.listing if domain is None or s['site'] == domain]

    def test_only_own_files_and_databases(self):
        with mock.patch.object(self.bk, 'snapshots', side_effect=self.snapshots):
            self.assertEqual([s['id'] for s in self.bk.site_snapshots({}, MINE)], ['aaaaaaa1', 'bbbbbbb2'])
            self.assertEqual(self.bk.snapshot_for_site({}, 'aaaaaaa1', MINE, 'files')['full_id'], self.listing[0]['full_id'])
            self.assertEqual(self.bk.snapshot_for_site({}, 'bbbbbbb2', MINE, 'db', 'mine_wp')['id'], 'bbbbbbb2')
            for snap, kind, db in (('eeeeeee5', 'files', ''),   # another site's snapshot
                                   ('ccccccc3', 'files', ''),   # configuration
                                   ('ddddddd4', 'files', ''),   # mail
                                   ('bbbbbbb2', 'db', 'other_wp'), ('bbbbbbb2', 'files', ''), ('aaaaaaa1', 'db', 'mine_wp'),
                                   ('aaaa', 'files', ''), ('zzzzzzzz', 'files', '')):
                with self.assertRaises(self.bk.BackupError, msg=(snap, kind, db)):
                    self.bk.snapshot_for_site({}, snap, MINE, kind, db)


@unittest.skipUnless(shutil.which('restic'), 'restic is not installed')
class OwnerRestoreWithRestic(unittest.TestCase):
    """restore_files_as_owner never lets restic write into the live site."""

    def setUp(self):
        from universalAddons.backupv2 import service as bk
        self.bk = bk
        self.root = tempfile.mkdtemp()
        self.sites = os.path.join(self.root, 'home')
        self.site = os.path.join(self.sites, MINE)
        os.makedirs(os.path.join(self.site, 'public_html'))
        self.write('public_html/index.php', 'v1')
        self.outside = os.path.join(self.root, 'outside')
        os.makedirs(self.outside)
        self.patches = [mock.patch.object(bk, 'SITES_ROOT', self.sites),
                        mock.patch.dict(os.environ, {'RESTIC_CACHE_DIR': os.path.join(self.root, 'cache')})]
        for patch in self.patches:
            patch.start()
        self.config = os.path.join(self.root, 'config')
        self.repo = bk.save_repo({'id': 'local', 'type': 'local', 'path': os.path.join(self.root, 'repo'),
                                  'for_users': True}, config_dir=self.config)
        self.assertTrue(self.repo['for_users'])
        bk.init_repo(self.repo, config_dir=self.config)
        bk.backup_site(self.repo, MINE, ['files'], [], 'h', config_dir=self.config, extra_tags=[bk.USER_TAG])
        self.snap = bk.site_snapshots(self.repo, MINE, config_dir=self.config)[0]
        import pwd
        self.me = pwd.getpwuid(os.getuid()).pw_name
        self.copies = []

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.root)

    def write(self, rel, text):
        with open(os.path.join(self.site, rel), 'w') as handle:
            handle.write(text)

    def read(self, rel):
        with open(os.path.join(self.site, rel)) as handle:
            return handle.read()

    def copy(self, src, dst):
        """Stands in for `sudo -u <site user> cp -a -T`: records that the copy ran outside restic."""
        import subprocess
        self.copies.append((src, dst))
        self.assertTrue(src.startswith(os.path.join(self.sites, '.cp-ua-restore-')), src)
        out = subprocess.run(['cp', '-a', '-T', src, dst], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True)
        return out.returncode, out.stdout

    def restore(self, include=None):
        return self.bk.restore_files_as_owner(self.repo, self.snap['full_id'], MINE, self.me, include,
                                              config_dir=self.config, copy=self.copy)

    def test_whole_site_and_single_path(self):
        self.write('public_html/index.php', 'broken')
        self.restore()
        self.assertEqual(self.read('public_html/index.php'), 'v1')
        self.write('public_html/index.php', 'broken again')
        self.restore(os.path.join(self.site, 'public_html', 'index.php'))
        self.assertEqual(self.read('public_html/index.php'), 'v1')
        self.assertEqual(len(self.copies), 2)
        self.assertFalse([n for n in os.listdir(self.sites) if n.startswith('.cp-ua-restore-')], 'staging removed')
        tags = [s['tags'] for s in self.bk.snapshots(self.repo, MINE, config_dir=self.config)]
        self.assertTrue(any('pre-restore' in t for t in tags), 'safety snapshot taken')

    def test_restic_never_writes_through_links_in_the_live_site(self):
        shutil.rmtree(os.path.join(self.site, 'public_html'))
        os.symlink(self.outside, os.path.join(self.site, 'public_html'))  # planted by the site owner
        calls = []
        real_run = self.bk.run

        def spy(argv, env=None, runner=None, **kwargs):
            calls.append(argv)
            return real_run(argv, env, **kwargs)
        with mock.patch.object(self.bk, 'run', side_effect=spy):
            with self.assertRaises(self.bk.BackupError):  # cp, as the owner, will not replace the link
                self.restore()
        self.assertEqual(os.listdir(self.outside), [], 'nothing was written through the link')
        self.assertFalse([n for n in os.listdir(self.sites) if n.startswith('.cp-ua-restore-')], 'staging removed')
        restic_restores = [a for a in calls if 'restore' in a]
        self.assertEqual(len(restic_restores), 1)
        target = restic_restores[0][restic_restores[0].index('--target') + 1]
        self.assertTrue(target.startswith(os.path.join(self.sites, '.cp-ua-restore-')), target)

    def test_paths_outside_the_site_refused(self):
        for include in (os.path.join(self.sites, FOREIGN, 'x'), os.path.join(self.site, '..', FOREIGN), '/etc/passwd'):
            with self.assertRaises(self.bk.BackupError, msg=include):
                self.restore(include)
        with self.assertRaises(self.bk.BackupError):
            self.bk.restore_files_as_owner(self.repo, self.snap['full_id'], MINE, 'root', None, config_dir=self.config,
                                           copy=self.copy)
        self.assertEqual(self.copies, [])

    def test_owner_retention_keeps_scheduled_snapshots(self):
        self.bk.backup_site(self.repo, MINE, ['files'], [], 'h', config_dir=self.config)  # a scheduled one
        for _ in range(self.bk.USER_KEEP_LAST + 1):
            self.write('public_html/index.php', str(time.time()))
            self.bk.backup_site(self.repo, MINE, ['files'], [], 'h', config_dir=self.config, extra_tags=[self.bk.USER_TAG])
        self.bk.owner_retention(self.repo, MINE, config_dir=self.config)
        snaps = self.bk.snapshots(self.repo, MINE, config_dir=self.config)
        self.assertEqual(sum(1 for s in snaps if self.bk.USER_TAG in s['tags']), self.bk.USER_KEEP_LAST)
        self.assertEqual(sum(1 for s in snaps if self.bk.USER_TAG not in s['tags']), 1)


if __name__ == '__main__':
    unittest.main()
