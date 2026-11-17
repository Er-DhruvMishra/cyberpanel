"""Regression tests for reported website-page UI bugs (PHP list, Git folders, hero header)."""
import os
import re
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from managePHP.phpManager import PHPManager
from websiteFunctions.gitFolders import list_site_folders, parse_site_folders

ROOT = Path(__file__).resolve().parents[1]


class PHPVersionListTests(SimpleTestCase):
    def make_lsws(self, root, names, with_binary=True):
        for name in names:
            bin_dir = Path(root, name, 'bin')
            bin_dir.mkdir(parents=True)
            if with_binary:
                (bin_dir / 'lsphp').write_text('')

    def test_lists_installed_versions_in_version_order(self):
        with tempfile.TemporaryDirectory() as root:
            self.make_lsws(root, ['lsphp85', 'lsphp56', 'lsphp74', 'lsphp80', 'lsphp71', 'lsphp710'])
            self.make_lsws(root, ['lsphp70'], with_binary=False)  # removed install: no binary
            Path(root, 'lsphp.conf').write_text('')
            Path(root, 'conf').mkdir()
            self.assertEqual(PHPManager.findInstalledLSPHPVersions(root),
                             ['PHP 5.6', 'PHP 7.1', 'PHP 7.4', 'PHP 7.10', 'PHP 8.0', 'PHP 8.5'])

    def test_missing_directory_gives_empty_list(self):
        self.assertEqual(PHPManager.findInstalledLSPHPVersions('/nonexistent/lsws'), [])

    def test_find_php_versions_does_not_depend_on_lscpd(self):
        installed = ['PHP 5.6', 'PHP 8.5']
        with mock.patch.object(PHPManager, 'findInstalledLSPHPVersions', return_value=installed), \
                mock.patch('managePHP.phpManager.ProcessUtilities.outputExecutioner') as execute:
            self.assertEqual(PHPManager.findPHPVersions(), installed)
        execute.assert_not_called()

    def test_empty_lscpd_reply_falls_back_to_a_non_empty_list(self):
        with mock.patch.object(PHPManager, 'findInstalledLSPHPVersions', return_value=[]), \
                mock.patch('managePHP.phpManager.ProcessUtilities.outputExecutioner', return_value=''), \
                mock.patch('plogical.CyberCPLogFileWriter.CyberCPLogFileWriter.writeToFile'):
            self.assertTrue(PHPManager.findPHPVersions())

    def test_live_server_versions_when_present(self):
        if not os.path.isdir('/usr/local/lsws/lsphp85'):
            self.skipTest('no LiteSpeed PHP on this host')
        versions = PHPManager.findInstalledLSPHPVersions()
        for expected in ('PHP 5.6', 'PHP 7.1', 'PHP 7.4', 'PHP 8.0', 'PHP 8.5'):
            self.assertIn(expected, versions)

    def test_change_php_select_has_a_default_and_a_visible_cancel_icon(self):
        page = (ROOT / 'websiteFunctions/templates/websiteFunctions/website.html').read_text()
        select = re.search(r'<select ng-model="phpSelectionMaster"[^>]*>', page).group(0)
        self.assertIn('ng-init="phpSelectionMaster', select)
        self.assertIn('currentPHP', select)
        # glyph-icon/icon-close come from a stylesheet the panel no longer loads.
        self.assertNotIn('glyph-icon icon-close', page)


class GitFolderListTests(SimpleTestCase):
    FIND_OUTPUT = '\n'.join([
        '/home/example.com/logs',
        '/home/example.com/laravel_app',
        '/home/example.com/.ssh',
        '/home/example.com/public_html',
        '/home/example.com/Backup',
        '/home/example.com/public_html/sub',
        '/home/other.com/public_html',
        'find: ‘/home/example.com/x’: Permission denied',
        '/home/example.com/bad name',
    ])

    def test_parse_lists_top_level_site_folders(self):
        self.assertEqual(parse_site_folders('/home/example.com', self.FIND_OUTPUT), [
            '/home/example.com/public_html',
            '/home/example.com/Backup',
            '/home/example.com/laravel_app',
        ])

    def test_listing_runs_as_site_user(self):
        execute = mock.Mock(return_value=self.FIND_OUTPUT)
        folders = list_site_folders('example.com', 'examp1234', execute)
        self.assertEqual(folders[0], '/home/example.com/public_html')
        self.assertIn('/home/example.com/laravel_app', folders)
        command, user = execute.call_args.args
        self.assertEqual(user, 'examp1234')
        self.assertTrue(command.startswith('find /home/example.com '))

    def test_public_html_always_offered(self):
        for result in ('', None, 'Connection failed'):
            with self.subTest(result=result):
                self.assertEqual(list_site_folders('example.com', 'u', mock.Mock(return_value=result)),
                                 ['/home/example.com/public_html'])
        self.assertEqual(list_site_folders('example.com', 'u', mock.Mock(side_effect=OSError)),
                         ['/home/example.com/public_html'])

    def test_manage_git_select_shows_a_prompt(self):
        page = (ROOT / 'websiteFunctions/templates/websiteFunctions/manageGIT.html').read_text()
        select = page[page.index('ng-model="folder"'):page.index('</select>', page.index('ng-model="folder"'))]
        self.assertIn('<option value="" disabled>', select)
        self.assertIn('{% for item in folders %}', select)

    def test_manage_git_view_and_folder_check_use_the_listing(self):
        source = (ROOT / 'websiteFunctions/website.py').read_text()
        view = source[source.index('    def manageGIT(self'):source.index('    def folderCheck(self')]
        self.assertIn('list_site_folders(', view)
        check = source[source.index('    def folderCheck(self'):source.index('    def fetchFolderDetails(self')]
        self.assertIn('list_site_folders(', check)


class HeroHeaderContrastTests(SimpleTestCase):
    """#page-title hero cards hardcode white text over var(--bg-gradient)."""

    CSS = ROOT / 'baseTemplate/static/baseTemplate/css/cyberpanel-evergreen.css'

    @staticmethod
    def rule(css, selector):
        match = re.search(re.escape(selector) + r'\s*\{([^}]*)\}', css)
        return match.group(1) if match else ''

    def test_theme_maps_bg_gradient_to_a_light_colour(self):
        css = self.CSS.read_text()
        self.assertIn('--bg-gradient: var(--cp-selection);', css)

    def test_hero_header_text_is_readable_on_that_background(self):
        css = self.CSS.read_text()
        box = self.rule(css, 'html.cp-evergreen #main-content #page-title')
        self.assertIn('color: var(--cp-selection-text) !important', box)
        heading = self.rule(css, 'html.cp-evergreen #main-content #page-title :is(h1, h2, h3, i, .fa, .fas, .far)')
        self.assertIn('color: var(--text-heading) !important', heading)
        text = self.rule(css, 'html.cp-evergreen #main-content #page-title :is(p, span, small)')
        self.assertIn('color: var(--cp-selection-text) !important', text)
        # Dark theme redefines both tokens as a dark surface with light ink.
        dark = css[css.index('html.cp-evergreen[data-theme="dark"] {'):]
        dark = dark[:dark.index('}')]
        self.assertIn('--cp-selection: #2b4230', dark)
        self.assertIn('--cp-selection-text: #dceddc', dark)

    def test_apache_manager_hero_follows_the_theme_background(self):
        page = (ROOT / 'websiteFunctions/templates/websiteFunctions/ApacheManager.html').read_text()
        self.assertRegex(page, r'#page-title \{\s*background: var\(--bg-gradient,')

    def test_reported_pages_use_the_shared_hero(self):
        for name in ('setupStaging', 'manageGIT'):
            with self.subTest(page=name):
                page = (ROOT / ('websiteFunctions/templates/websiteFunctions/%s.html' % name)).read_text()
                self.assertIn('<div id="page-title">', page)
                self.assertRegex(page, r'#page-title \{[^}]*color: white')

    def test_base_template_busts_the_css_cache(self):
        base = (ROOT / 'baseTemplate/templates/baseTemplate/index.html').read_text()
        self.assertIn("cyberpanel-evergreen.css' %}?v=20261116-1", base)


class AddonDomainAsksForWebsite(SimpleTestCase):
    """Addon domains show the website selector (default site preselected) instead of silently
    using the account's default site for the folder."""

    def test_addon_domain_shows_selector(self):
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel in ('websiteFunctions/static/websiteFunctions/websiteFunctions.js', 'static/websiteFunctions/websiteFunctions.js'):
            js = open(os.path.join(root, rel), encoding='utf-8').read()
            block = js[js.index("type == 'Addon Domain'"):][:400]
            self.assertIn('$scope.webselection = false;', block, rel)
            self.assertNotIn('$scope.webselection = true;', block, rel)


class CreateWebsiteOptions(SimpleTestCase):
    """SSL, DKIM and open_basedir are offered on Create Website (on by default) and honoured."""

    def test_checkboxes_present_and_default_on(self):
        import os
        html = open(os.path.join(os.path.dirname(__file__), 'templates', 'websiteFunctions', 'createWebsite.html'),
                    encoding='utf-8').read()
        for model in ('sslCheck', 'dkimCheck', 'openBasedir'):
            self.assertIn('ng-model="%s" ng-init="%s=true"' % (model, model), html)
        self.assertNotIn('Premium Feature', html)

    def test_server_uses_requested_flags_with_on_defaults(self):
        import inspect
        from websiteFunctions.website import WebsiteManager
        source = inspect.getsource(WebsiteManager.submitWebsiteCreation)
        self.assertIn("data.get('ssl', 1)", source)
        self.assertIn("data.get('dkimCheck', 1)", source)
        self.assertIn('" --ssl " + str(sslFlag)', source)
        self.assertNotIn('" --ssl " + str(1)', source)
