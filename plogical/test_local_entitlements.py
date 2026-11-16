"""The vendor licence is gone: no code path contacts it, every gate grants locally, ACLs still apply."""
import ast
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', 'node_modules', '__pycache__'}


def project_files(suffixes):
    for path in ROOT.rglob('*'):
        if path.suffix not in suffixes or not path.is_file():
            continue
        if SKIP_DIRS & set(path.relative_to(ROOT).parts[:-1]):
            continue
        yield path


def no_network():
    """Fail any attempt to reach the network through requests or urllib."""
    trap = mock.Mock(side_effect=AssertionError('network access attempted'))
    return mock.patch.multiple('requests', post=trap, get=trap, request=trap), \
        mock.patch('urllib.request.urlopen', trap), trap


class NoVendorLicenceCalls(SimpleTestCase):
    def test_no_python_code_names_the_licence_endpoint(self):
        """String constants anywhere in executable Python (not comments) must not name Adonpermission."""
        offenders = []
        for path in project_files({'.py'}):
            if path.name.startswith('test_'):
                continue
            try:
                tree = ast.parse(path.read_text(errors='replace'))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                        re.search(r'Adonpermission|CyberpanelAdOns', node.value):
                    offenders.append('%s:%s' % (path.relative_to(ROOT), node.lineno))
        self.assertEqual([], offenders)

    def test_no_script_or_template_posts_to_the_vendor_addon_service(self):
        offenders = [str(p.relative_to(ROOT)) for p in project_files({'.js', '.html', '.sh'})
                     if re.search(r'Adonpermission|CyberpanelAdOns|Billing/AddOnOrderPaypal|order/roundcube',
                                  p.read_text(errors='replace'))]
        self.assertEqual([], offenders)

    def test_real_lookup_grants_every_feature_without_network(self):
        from plogical.acl import ACLManager
        patch_requests, patch_urlopen, trap = no_network()
        with patch_requests, patch_urlopen, \
                mock.patch.object(ACLManager, 'GetServerIP', side_effect=AssertionError('IP must not be read')):
            for feature in ('all', 'wp-manager', 'email-debugger', 'Filemanager', 'roundcube', 'backups-retention'):
                self.assertEqual(1, ACLManager.CheckForPremFeature(feature), feature)
        trap.assert_not_called()


class GatesUseTheLocalAnswer(SimpleTestCase):
    """Each gate helper, with the real ACLManager, is open and makes no network call."""

    def setUp(self):
        patch_requests, patch_urlopen, self.trap = no_network()
        for patcher in (patch_requests, patch_urlopen,
                        mock.patch('plogical.universalAlternatives.preferred_keys', return_value=set())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        self.trap.assert_not_called()

    def test_wordpress_apache_and_root_gates(self):
        from websiteFunctions.wordpressEntitlements import wordpress_manager_available
        from websiteFunctions.apacheEntitlements import apache_manager_available, apache_backend_entitlement_error
        from filemanager.rootEntitlements import require_root_entitlement
        self.assertTrue(wordpress_manager_available())
        self.assertTrue(apache_manager_available())
        self.assertIsNone(apache_backend_entitlement_error({'apacheBackend': 1}))
        require_root_entitlement({})  # no PermissionError
        with self.assertRaises(PermissionError):
            require_root_entitlement({'domainName': 'site.example'})  # still never silently root

    def test_packages_resource_limits_are_available(self):
        from packages.packagesManager import PackagesManager
        self.assertTrue(PackagesManager.checkAddonAccess())

    def test_premium_decorator_runs_the_operation_and_keeps_its_own_acl(self):
        from plogical.premiumEntitlements import premium_entitlement_required

        @premium_entitlement_required('email-debugger', label='Email Debugger', page_redirect='/addons/')
        def page(request):
            return 'rendered' if request.acl.get('admin') == 1 else 'denied by ACL'

        request = RequestFactory().get('/emailPremium/EmailDebugger')
        request.session = {}
        request.acl = {'admin': 1}
        self.assertEqual('rendered', page(request))
        request.acl = {'admin': 0}
        self.assertEqual('denied by ACL', page(request))

    def test_preferred_free_addon_redirect_is_opt_in_and_licence_independent(self):
        from plogical import universalAlternatives as ua
        on = lambda key: True
        self.assertIsNone(ua.preferred_alternative('/dataBases/MysqlManager', on, preferred=set()))
        self.assertEqual('/addons/mysql/',
                         ua.preferred_alternative('/dataBases/MysqlManager', on, preferred={'mysqlmgr'}))
        self.assertEqual('/addons/mysql/', ua.preferred_alternative('/dataBases/MysqlManager', on, preferred=set(),
                                                                    vendor_dependent={'mysqlmgr'}))
        self.assertIsNone(ua.preferred_alternative('/dataBases/MysqlManager', lambda key: False,
                                                   preferred={'mysqlmgr'}), 'add-on missing: keep upstream')
        self.assertIsNone(ua.preferred_alternative('/websites/pricing', on, preferred={'wordpress'}))
        self.assertEqual(frozenset(), ua.VENDOR_DEPENDENT, 'every mapped upstream page now runs locally')


class PreferenceFile(SimpleTestCase):
    def test_preference_file_lists_add_on_keys(self):
        import tempfile
        from plogical import universalAlternatives as ua
        with tempfile.NamedTemporaryFile('w', suffix='.txt') as handle:
            handle.write('# comment\nwordpress\n\nrootfm\n')
            handle.flush()
            self.assertEqual({'wordpress', 'rootfm'}, ua.preferred_keys(handle.name))
        self.assertEqual(set(), ua.preferred_keys('/nonexistent/prefer_free_addons'))


class SalesPagesAreGone(SimpleTestCase):
    def test_vendor_billing_ui_removed(self):
        checks = {
            'websiteFunctions/static/websiteFunctions/websiteFunctions.js': ('BuyAddons', 'AddOnOrderPaypal'),
            'websiteFunctions/templates/websiteFunctions/ApacheManager.html': ('stripe-pricing-table',),
            'manageSSL/templates/manageSSL/v2ManageSSL.html': ('stripe-pricing-table',),
            'webmail/templates/webmail/roundcube.html': ('cyberpersons', 'Buy Roundcube'),
            'emailDelivery/templates/emailDelivery/index.html': ('email/cp/pricing', 'Upgrade Plan'),
            'baseTemplate/templates/baseTemplate/index.html': ('platform.cyberpersons.com', 'Get CyberEdge'),
            'baseTemplate/templates/baseTemplate/hub.html': ('platform.cyberpersons.com',),
            'baseTemplate/templates/baseTemplate/homePage.html': ('Upgrade to CyberPanel Addons',),
            'websiteFunctions/templates/websiteFunctions/website.html': ('upgrade to CyberPanel Add-ons',),
            'websiteFunctions/templates/websiteFunctions/sshAccess.html': ('upgrade to CyberPanel Add-ons',),
        }
        for name, needles in checks.items():
            text = (ROOT / name).read_text()
            for needle in needles:
                self.assertNotIn(needle, text, name)
        self.assertFalse((ROOT / 'websiteFunctions/templates/websiteFunctions/CyberpanelPricing.html').exists())

    def test_ssh_analysis_has_no_addon_upsell(self):
        source = (ROOT / 'baseTemplate/views.py').read_text()
        self.assertNotIn("'addon_required': True", source)
        self.assertNotIn('CheckForPremFeature', source)
