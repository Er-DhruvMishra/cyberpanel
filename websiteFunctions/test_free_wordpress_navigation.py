"""WordPress pages: the local licence answer grants them; the fail-closed branch goes to the dashboard."""
import unittest
try:
    from .test_wordpress_entitlements import load_wordpress_manager
except ImportError:
    from test_wordpress_entitlements import load_wordpress_manager


class WordPressNavigationTests(unittest.TestCase):
    def test_denied_lookup_redirects_to_dashboard_not_a_sales_page(self):
        manager, _, services = load_wordpress_manager()
        services['ACLManager'].CheckForPremFeature.return_value = 0
        for name in ('WPCreate', 'wordpressInstall', 'WPHome'):
            with self.subTest(page=name):
                result = getattr(manager(domain='owned.example'), name)(userID=7)
                self.assertEqual(result.status_code, 302)
                self.assertEqual(result.url, 'index')
        services['httpProc'].assert_not_called()
        services['Administrator'].objects.get.assert_not_called()
        services['ApplicationInstaller'].assert_not_called()


if __name__ == '__main__':
    unittest.main()
