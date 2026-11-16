"""The licence lookup is local: every feature is granted, nothing leaves the server."""
import ast
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest import mock


def load_lookup():
    """Run the real CheckForPremFeature body in isolation, with every dependency booby-trapped."""
    source = Path(__file__).with_name('acl.py').read_text()
    tree = ast.parse(source)
    owner = next(node for node in tree.body
                 if isinstance(node, ast.ClassDef) and node.name == 'ACLManager')
    method = next(node for node in owner.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'CheckForPremFeature')
    owner.body = [method]
    module = ast.Module(body=[owner], type_ignores=[])
    trap = mock.Mock(side_effect=AssertionError('must not be used'))
    runtime = mock.Mock(decideServer=trap)
    namespace = {'ProcessUtilities': runtime}
    exec(compile(module, str(Path(__file__).with_name('acl.py')), 'exec'), namespace)
    manager = namespace['ACLManager']
    manager.GetServerIP = mock.Mock(side_effect=AssertionError('the server IP must not be read'))
    return manager, runtime


class PremiumEntitlementLookupTests(unittest.TestCase):
    def setUp(self):
        self.manager, self.runtime = load_lookup()
        self.requests = ModuleType('requests')
        self.requests.post = mock.Mock(side_effect=AssertionError('no vendor request'))
        self.requests.get = mock.Mock(side_effect=AssertionError('no vendor request'))
        patcher = mock.patch.dict(sys.modules, {'requests': self.requests})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_feature_is_granted_as_integer_one(self):
        for feature in ('all', 'wp-manager', 'email-debugger', 'Filemanager', 'roundcube',
                        'backups-retention', 'unknown-feature', '', None):
            with self.subTest(feature=feature):
                result = self.manager.CheckForPremFeature(feature)
                self.assertIs(type(result), int)
                self.assertEqual(1, result)

    def test_no_network_no_server_ip_and_no_platform_detection(self):
        self.manager.CheckForPremFeature('all')
        self.requests.post.assert_not_called()
        self.requests.get.assert_not_called()
        self.manager.GetServerIP.assert_not_called()
        self.runtime.decideServer.assert_not_called()

    def test_method_body_names_no_vendor_endpoint(self):
        tree = ast.parse(Path(__file__).with_name('acl.py').read_text())
        method = next(node for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'ACLManager'
                      for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'CheckForPremFeature')
        statements = [n for n in method.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
        code = '\n'.join(ast.unparse(n) for n in statements)
        self.assertEqual('return 1', code.strip())


if __name__ == '__main__':
    unittest.main()
