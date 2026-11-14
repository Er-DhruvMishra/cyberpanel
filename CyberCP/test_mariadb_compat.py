import unittest
from types import SimpleNamespace

from django.db.backends.mysql import features

from CyberCP import mariadb_compat


class MariaDBCompat(unittest.TestCase):
    def check(self, is_mariadb):
        obj = features.DatabaseFeatures.__new__(features.DatabaseFeatures)
        obj.connection = SimpleNamespace(mysql_is_mariadb=is_mariadb)
        return obj.minimum_database_version

    def test_mariadb_103_allowed_mysql_unchanged(self):
        mariadb_compat.apply()
        self.assertFalse(mariadb_compat.apply(), 'idempotent')
        self.assertEqual(self.check(True), (10, 3))
        self.assertEqual(self.check(False), (8,))


if __name__ == '__main__':
    unittest.main()
