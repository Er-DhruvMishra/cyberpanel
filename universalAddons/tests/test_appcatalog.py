"""App catalogue: the catalogue, request validation, release feeds, checksum and signature checks
(commands mocked), archive checks, CLI installer arguments, the non-empty target refusal, the
one-time credentials, access and the page."""
import base64
import hashlib
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons import jobs
from universalAddons.appcatalog import actions, service as svc, views
from universalAddons.appcatalog.service import CatalogError
from universalAddons.siteinfo import Site
from universalAddons.tests.helpers import post

SITE = Site('mine.example.com', 'minex1234', '/home/mine.example.com', '/home/mine.example.com/public_html')
REQUEST = {'app': 'nextcloud', 'admin_email': 'boss@mine.example.com'}


class Catalogue(SimpleTestCase):
    def test_existing_installers_are_linked(self):
        apps = {a['key']: a for a in svc.catalogue('mine.example.com')}
        self.assertEqual(apps['wordpress']['url'], '/addons/wordpress/?site=mine.example.com')
        self.assertEqual(apps['joomla']['url'], '/websites/mine.example.com/joomlaInstall')
        self.assertEqual(apps['prestashop']['url'], '/websites/mine.example.com/installPrestaShop')
        self.assertEqual(apps['magento']['url'], '/websites/mine.example.com/installMagento')
        self.assertEqual(apps['mautic']['url'], '/websites/mine.example.com/installMautic')
        for key in ('drupal', 'ghost', 'nextcloud', 'phpbb', 'mediawiki', 'matomo', 'grav'):
            self.assertTrue(apps[key]['new'], key)
            self.assertTrue(apps[key]['source'], key)
            self.assertTrue(hasattr(actions.Installer, key), key)


class Requests(SimpleTestCase):
    def test_overwrite_needs_the_typed_domain(self):
        with self.assertRaisesRegex(CatalogError, 'type the domain'):
            svc.clean_request(dict(REQUEST, overwrite=True), 'mine.example.com')
        clean = svc.clean_request(dict(REQUEST, overwrite=True, confirm='Mine.Example.com'), 'mine.example.com')
        self.assertTrue(clean['overwrite'])

    def test_paths_and_names(self):
        self.assertEqual(svc.clean_request(dict(REQUEST, path='cloud/'), 'a.com')['path'], 'cloud')
        for bad in ('../x', '/etc', 'a/../../b', 'a b'):
            with self.assertRaises(CatalogError, msg=bad):
                svc.clean_request(dict(REQUEST, path=bad), 'a.com')
        with self.assertRaises(CatalogError):
            svc.clean_request(dict(REQUEST, admin_user='x;rm'), 'a.com')
        with self.assertRaises(CatalogError):
            svc.clean_request(dict(REQUEST, admin_email='nope'), 'a.com')
        with self.assertRaises(CatalogError):
            svc.clean_request(dict(REQUEST, app='phpmyadmin'), 'a.com')
        self.assertEqual(svc.clean_request(dict(REQUEST, app='ghost'), 'a.com')['path'], 'ghost')
        with self.assertRaises(CatalogError):
            svc.clean_request(dict(REQUEST, app='ghost', path='Ghost/x'), 'a.com')

    def test_passwords_and_database_names(self):
        password = svc.new_password()
        self.assertEqual(len(password), 20)
        self.assertTrue(password.isalnum())
        name, user = svc.database_names('minex1234', 'nextcloud', 'ab12')
        self.assertEqual(name, 'minex1_nextab12')
        self.assertLessEqual(len(name), 16)
        self.assertEqual(svc.redact('pw=Secret1 again Secret1', ['Secret1']), 'pw=******** again ********')


DRUPAL_XML = '''<?xml version="1.0"?><project><releases>
<release><name>drupal 11.3.0-rc1</name><version>11.3.0-rc1</version><version_extra>rc1</version_extra>
 <status>published</status><download_link>https://ftp.drupal.org/files/projects/drupal-11.3.0-rc1.tar.gz</download_link>
 <mdhash>00000000000000000000000000000000</mdhash></release>
<release><name>drupal 11.2.8</name><version>11.2.8</version><status>published</status>
 <download_link>https://ftp.drupal.org/files/projects/drupal-11.2.8.tar.gz</download_link>
 <mdhash>0123456789abcdef0123456789abcdef</mdhash><filesize>20000000</filesize></release>
</releases></project>'''


class Feeds(SimpleTestCase):
    def test_drupal_takes_latest_stable(self):
        release = svc.parse_drupal_feed(DRUPAL_XML)
        self.assertEqual(release, {'version': '11.2.8', 'url': 'https://ftp.drupal.org/files/projects/drupal-11.2.8.tar.gz',
                                   'md5': '0123456789abcdef0123456789abcdef', 'size': 20000000})
        with self.assertRaises(CatalogError):
            svc.parse_drupal_feed(DRUPAL_XML.replace('https://ftp.drupal.org', 'https://evil.example'))

    def test_phpbb(self):
        release = svc.parse_phpbb_feed(json.dumps({'stable': {'3.2': {'current': '3.2.11'}, '3.3': {'current': '3.3.15'}}}))
        self.assertEqual(release['url'], 'https://download.phpbb.com/pub/release/3.3/3.3.15/phpBB-3.3.15.zip')
        self.assertEqual(release['sha256_url'], release['url'] + '.sha256')
        with self.assertRaises(CatalogError):
            svc.parse_phpbb_feed(json.dumps({'stable': {'3.3': {'current': '3.3.15/../x'}}}))

    def test_mediawiki(self):
        release = svc.parse_mediawiki_feed(json.dumps({'expandtemplates': {'wikitext': '1.44.2'}}))
        self.assertEqual(release['url'], 'https://releases.wikimedia.org/mediawiki/1.44/mediawiki-1.44.2.tar.gz')
        self.assertEqual(release['sig_url'], release['url'] + '.sig')
        with self.assertRaises(CatalogError):
            svc.parse_mediawiki_feed(json.dumps({'expandtemplates': {'wikitext': '<b>1.44</b>'}}))

    def test_grav_needs_a_published_digest(self):
        asset = {'name': 'grav-admin-v1.7.49.zip', 'digest': 'sha256:' + 'a' * 64,
                 'browser_download_url': 'https://github.com/getgrav/grav/releases/download/1.7.49/grav-admin-v1.7.49.zip'}
        release = svc.parse_github_release(json.dumps({'assets': [{'name': 'grav-v1.7.49.zip'}, asset]}))
        self.assertEqual((release['version'], release['sha256']), ('1.7.49', 'a' * 64))
        with self.assertRaisesRegex(CatalogError, 'no SHA-256'):
            svc.parse_github_release(json.dumps({'assets': [dict(asset, digest=None)]}))
        with self.assertRaises(CatalogError):
            svc.parse_github_release(json.dumps({'prerelease': True, 'assets': [asset]}))

    def test_npm_integrity(self):
        digest = hashlib.sha512(b'ghost').digest()
        meta = {'name': 'ghost', 'version': '6.3.1', 'engines': {'node': '^20.11.1 || ^22.13.1'},
                'dist': {'tarball': 'https://registry.npmjs.org/ghost/-/ghost-6.3.1.tgz',
                         'integrity': 'sha512-' + base64.b64encode(digest).decode()}}
        release = svc.parse_npm_meta(json.dumps(meta))
        self.assertEqual(release['sha512'], digest.hex())
        self.assertEqual(svc.node_majors(release['node']), {20, 22})
        self.assertEqual(svc.pick_node(['18.20.4', '20.18.0', '22.11.0', '24.1.0'], release['node']), '22.11.0')
        self.assertIsNone(svc.pick_node(['18.20.4'], release['node']))
        with self.assertRaises(CatalogError):
            svc.parse_npm_meta(json.dumps(dict(meta, dist=dict(meta['dist'], integrity='sha1-abc'))))


class Verification(SimpleTestCase):
    """Checksums and signatures as the installer runs them (site-user commands mocked)."""

    def installer(self, outputs):
        calls = []

        def run_as(site, argv, **kwargs):
            calls.append(argv)
            for prefix, (code, out) in outputs.items():
                if argv[0] == prefix and (prefix != 'gpg' or '--verify' in argv):
                    return code, out
            return 0, ''
        patcher = mock.patch('universalAddons.appcatalog.actions.siteinfo.run_as', side_effect=run_as)
        patcher.start()
        self.addCleanup(patcher.stop)
        job = mock.Mock(job_id='0' * 24)
        return actions.Installer(SITE, svc.clean_request(REQUEST, SITE.domain), job), calls, job

    def test_digest_match_and_mismatch(self):
        good = 'ab' * 32
        installer, calls, _ = self.installer({'sha256sum': (0, '%s  /w/latest.tar.bz2\n' % good)})
        self.assertEqual(installer.verify_digest('/w/latest.tar.bz2', 'sha256', good.upper()), good)
        self.assertEqual(calls[-1], ['sha256sum', '--', '/w/latest.tar.bz2'])
        with self.assertRaisesRegex(CatalogError, 'Checksum mismatch'):
            installer.verify_digest('/w/latest.tar.bz2', 'sha256', 'cd' * 32)

    def test_checksum_files(self):
        self.assertEqual(svc.parse_checksum_file('%s  latest.tar.bz2\n' % ('ef' * 32), 'latest.tar.bz2'), 'ef' * 32)
        self.assertEqual(svc.parse_checksum_file('%s\n' % ('ef' * 32)), 'ef' * 32)
        with self.assertRaises(CatalogError):
            svc.parse_checksum_file('%s  other.zip\n' % ('ef' * 32), 'latest.tar.bz2')
        with self.assertRaises(CatalogError):
            svc.parse_checksum_file('<html>404</html>')

    def test_signature_with_pinned_fingerprint(self):
        fpr = svc.NEXTCLOUD_FINGERPRINT
        good = '[GNUPG:] GOODSIG D75899B9A724937A Nextcloud\n[GNUPG:] VALIDSIG %s 2025-01-01 1 0 4 0 1 10 01 %s\n' % (fpr, fpr)
        installer, calls, _ = self.installer({'gpg': (0, good)})
        self.assertEqual(installer.verify_signature('/w/f', '/w/f.asc', '/w/k.asc', fpr), [fpr])
        verify = [c for c in calls if '--verify' in c][0]
        self.assertEqual(verify[-3:], ['--verify', '/w/f.asc', '/w/f'])
        self.assertIn('--homedir', verify)
        other = good.replace(fpr, 'A' * 40)
        installer, _, _ = self.installer({'gpg': (0, other)})
        with self.assertRaisesRegex(CatalogError, 'not by the expected key'):
            installer.verify_signature('/w/f', '/w/f.asc', '/w/k.asc', fpr)
        installer, _, _ = self.installer({'gpg': (1, '[GNUPG:] BADSIG D75899B9A724937A Nextcloud\n')})
        with self.assertRaisesRegex(CatalogError, 'did not verify'):
            installer.verify_signature('/w/f', '/w/f.asc', '/w/k.asc', fpr)

    def test_secrets_never_reach_the_log(self):
        installer, _, job = self.installer({})
        password = installer.admin_password()
        installer.log('occ said: password %s' % password)
        self.assertNotIn(password, job.log.call_args[0][0])

    def test_archive_names(self):
        self.assertEqual(svc.check_archive_names(['nextcloud/', 'nextcloud/occ'], 'nextcloud'), 'nextcloud')
        self.assertEqual(svc.check_archive_names(['drupal-11.2.8/index.php'], 'drupal-'), 'drupal-11.2.8')
        self.assertEqual(svc.check_archive_names(['matomo/index.php', 'How to install Matomo.html'], 'matomo'), 'matomo')
        for names in (['nextcloud/../../etc/passwd'], ['/etc/passwd'], ['other/x']):
            with self.assertRaises(CatalogError, msg=names):
                svc.check_archive_names(names, 'nextcloud')


class InstallerArguments(SimpleTestCase):
    def test_occ(self):
        argv = svc.occ_install_args('/php', '/d/occ', 'db', 'u', 'dbpw', 'admin', 'tmp', '/home/a/nextcloud-data')
        self.assertEqual(argv[:4], ['/php', '/d/occ', 'maintenance:install', '--no-interaction'])
        self.assertIn('--database-name=db', argv)
        self.assertIn('--data-dir=/home/a/nextcloud-data', argv)
        follow = svc.occ_followup_args('/php', '/d/occ', 'a.com', 'https://a.com/cloud')
        self.assertEqual(follow[0][-3:], ['trusted_domains', '1', '--value=a.com'])

    def test_drush_has_no_password_on_its_command_line(self):
        argv = svc.drush_install_args('/d/vendor/bin/drush', 'My "Site"', 'admin', 'a@b.com')
        self.assertEqual(argv[:4], ['/d/vendor/bin/drush', 'site:install', 'standard', '--yes'])
        self.assertIn('--site-name=My "Site"', argv)
        self.assertFalse(any('pass' in a for a in argv))
        self.assertIn("'password' => 'Pw1'", svc.drush_settings('db', 'u', 'Pw1'))
        self.assertEqual(svc.parse_drush_password(' [success] Installation complete.  User name: admin  User password: '
                                                  'Xy7abc\n'), 'Xy7abc')

    def test_mediawiki_reads_passwords_from_files(self):
        argv = svc.mediawiki_install_args('/php', '/d', 'db', 'u', '/w/dbpass', '/w/adminpass', 'https://a.com', '/wiki',
                                          'My Wiki', 'admin')
        self.assertEqual(argv[1], '/d/maintenance/install.php')
        self.assertIn('--dbpassfile=/w/dbpass', argv)
        self.assertIn('--passfile=/w/adminpass', argv)
        self.assertEqual(argv[-2:], ['My Wiki', 'admin'])

    def test_phpbb_config_quotes_values(self):
        text = svc.phpbb_config('Board: "x"', 'admin', 'Pw1', 'a@b.com', 'db', 'u', 'dbpw', 'a.com', '/forum')
        self.assertIn('        name: "Board: \\"x\\""', text)
        self.assertIn('        dbpasswd: "dbpw"', text)
        self.assertIn('        script_path: "/forum"', text)
        self.assertEqual(svc.phpbb_install_args('/php', '/d', '/w/c.yml'), ['/php', '/d/install/phpbbcli.php', 'install',
                                                                           '/w/c.yml'])

    def test_grav_and_ghost(self):
        self.assertIn('hashed_password: "$2y$10$abc"', svc.grav_account('a@b.com', '$2y$10$abc'))
        config = json.loads(svc.ghost_config('https://a.com/', 2345, '/home/a/apps/ghost/content', {'client': 'sqlite3'}))
        self.assertEqual(config['server'], {'host': '127.0.0.1', 'port': 2345})
        self.assertEqual(config['database']['connection']['filename'], '/home/a/apps/ghost/content/data/ghost.db')
        mysql = json.loads(svc.ghost_config('https://a.com/', 1, '/c', {'client': 'mysql', 'name': 'd', 'user': 'u',
                                                                         'password': 'p'}))
        self.assertEqual(mysql['database']['connection']['database'], 'd')
        body = json.loads(svc.ghost_setup_body('Administrator', 'a@b.com', 'pw', 'Blog'))
        self.assertEqual(body['setup'][0]['blogTitle'], 'Blog')


class Targets(SimpleTestCase):
    def setUp(self):
        self.target = tempfile.mkdtemp()

    def _install(self, request):
        with mock.patch.object(actions, '_site', return_value=SITE), \
                mock.patch.object(actions, 'target_dir', return_value=self.target), \
                mock.patch.object(actions.jobs, 'spawn', return_value={'job_id': 'f' * 24}) as spawn:
            return actions.install(SITE.domain, request), spawn

    def test_empty_target_installs(self):
        os.mkdir(os.path.join(self.target, '.well-known'))   # ACME files do not count
        result, spawn = self._install(REQUEST)
        self.assertEqual(result, {'job_id': 'f' * 24})
        self.assertEqual(spawn.call_args[0][:2], ('appcatalog', 'install_run'))

    def test_non_empty_target_is_refused(self):
        open(os.path.join(self.target, 'index.html'), 'w').close()
        with self.assertRaisesRegex(CatalogError, 'not empty.*index.html'):
            self._install(REQUEST)
        with self.assertRaisesRegex(CatalogError, 'type the domain'):
            self._install(dict(REQUEST, overwrite=True))
        result, spawn = self._install(dict(REQUEST, overwrite=True, confirm=SITE.domain))
        self.assertTrue(spawn.call_args[0][2]['request']['overwrite'])

    def test_problem_texts(self):
        self.assertEqual(actions.target_problem(os.path.join(self.target, 'missing')), '')
        link = self.target + '-link'
        os.symlink(self.target, link)
        self.assertIn('symbolic link', actions.target_problem(link))
        path = os.path.join(self.target, 'f')
        open(path, 'w').close()
        self.assertIn('not a directory', actions.target_problem(path))


class OneTimeCredentials(SimpleTestCase):
    def test_shown_once(self):
        directory = tempfile.mkdtemp()
        with mock.patch.object(jobs, 'JOB_DIR', directory):
            job = jobs.Job('a' * 24)
            job.done({'Finish': {'target': '/t', 'credentials': {'admin': {'user': 'admin', 'password': 'Pw1'}}}})
            first = actions.job_status('a' * 24)
            self.assertEqual(first['result']['Finish']['credentials']['admin']['password'], 'Pw1')
            second = actions.job_status('a' * 24)
            self.assertNotIn('credentials', second['result']['Finish'])
            self.assertTrue(second['result']['Finish']['credentials_shown'])
            self.assertNotIn('Pw1', open(os.path.join(directory, 'a' * 24 + '.json')).read())


class Access(SimpleTestCase):
    POLICY = {'appcatalog_for_users': True}

    def test_foreign_site_refused(self):
        with mock.patch('universalAddons.appcatalog.views.privileged.call') as call:
            code, body, _ = post(views.install, dict(REQUEST, domain='other.example.net'), policy=self.POLICY)
        self.assertEqual(code, 403)
        call.assert_not_called()

    def test_disabled_for_users(self):
        code, body, _ = post(views.catalogue, {'domain': 'mine.example.com'})
        self.assertEqual(code, 403)

    def test_owner_starts_a_job_and_may_poll_it(self):
        with mock.patch('universalAddons.appcatalog.views.privileged.call', return_value={'job_id': 'b' * 24}) as call:
            code, body, session = post(views.install, dict(REQUEST, domain='mine.example.com'), policy=self.POLICY)
            self.assertEqual(code, 200)
            self.assertEqual(call.call_args[1]['request']['app'], 'nextcloud')
            code, _, _ = post(views.job, {'job': 'b' * 24}, session=session, policy=self.POLICY)
            self.assertEqual(code, 200)
            code, _, _ = post(views.job, {'job': 'c' * 24}, session=session, policy=self.POLICY)
            self.assertEqual(code, 403)

    def test_ghost_needs_universal_apps_for_users(self):
        with mock.patch('universalAddons.appcatalog.views.privileged.call') as call:
            code, body, _ = post(views.install, dict(REQUEST, app='ghost', domain='mine.example.com'), policy=self.POLICY)
            self.assertEqual(code, 403)
            call.assert_not_called()
            call.return_value = {'job_id': 'b' * 24}
            code, _, _ = post(views.install, dict(REQUEST, app='ghost', domain='mine.example.com'),
                              policy=dict(self.POLICY, apps_for_users=True))
            self.assertEqual(code, 200)


class PageRenders(SimpleTestCase):
    def test_page_renders(self):
        request = RequestFactory().get('/addons/app-catalog/')
        request.session = {}
        html = render_to_string('universalAddons/appcatalog.html', {'request': request, 'site': 'mine.example.com',
                                                                    'is_admin': False, 'panel_brand': 'IndiansCloud'})
        self.assertIn('ua-wrap', html)
        self.assertIn('data-site="mine.example.com"', html)
        self.assertIn('IndiansCloud', html)

    def test_site_tiles(self):
        here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        for rel in ('websiteFunctions/templates/websiteFunctions/website.html',
                    'baseTemplate/templates/baseTemplate/siteWorkspace.html'):
            self.assertIn('/addons/app-catalog/?site={{ domain|urlencode }}', open(os.path.join(here, rel)).read(), rel)
