import unittest
from types import SimpleNamespace

from plogical.universalAlternatives import alternative_for, request_from


def request(path):
    return SimpleNamespace(path=path, method='GET', session={})


class Alternatives(unittest.TestCase):
    def test_paid_pages_map_to_free_addons(self):
        on = lambda key: True
        cases = {
            '/websites/ListWPSites': '/addons/wordpress/',
            '/websites/createWordpress': '/addons/wordpress/',
            '/websites/example.com/wordpressInstall': '/addons/wordpress/',
            '/emailPremium/EmailDebugger': '/addons/email-debugger/',
            '/emailPremium/Rspamd': '/addons/rspamd/',
            '/filemanager/Filemanager': '/addons/root-file-manager/',
            '/dataBases/MysqlManager': '/addons/mysql/',
            '/email/EmailLimits': '/addons/email-limits/',
        }
        for path, url in cases.items():
            self.assertEqual(alternative_for(path, on), url, path)

    def test_no_alternative_when_addon_missing_or_page_unrelated(self):
        self.assertIsNone(alternative_for('/dataBases/MysqlManager', lambda key: False))
        self.assertIsNone(alternative_for('/websites/pricing', lambda key: True), 'sales page itself is never hidden')
        self.assertIsNone(alternative_for('/websites/ApacheManager/example.com', lambda key: True))
        self.assertIsNone(alternative_for('', lambda key: True))

    def test_request_found_in_args_kwargs_or_manager(self):
        r = request('/x')
        self.assertIs(request_from((r,), {}), r)
        self.assertIs(request_from((), {'request': r}), r)
        self.assertIs(request_from((SimpleNamespace(request=r),), {}), r)
        self.assertIsNone(request_from((object(),), {}))


if __name__ == '__main__':
    unittest.main()
