from types import SimpleNamespace
import unittest

import psutil

from serverStatus.views import get_service_memory_usage


class ProcessMemoryUsageTests(unittest.TestCase):

    def test_counts_mariadb_and_mysql_processes(self):
        processes = [
            SimpleNamespace(info={
                'name': 'mariadbd',
                'memory_info': SimpleNamespace(rss=4096),
            }),
            SimpleNamespace(info={
                'name': 'mysql-router',
                'memory_info': SimpleNamespace(rss=2048),
            }),
            SimpleNamespace(info={
                'name': 'unrelated-process',
                'memory_info': SimpleNamespace(rss=8192),
            }),
        ]

        memory_usage = get_service_memory_usage(
            ('mariadbd', 'mysqld', 'mysql'), lambda attrs: processes)

        self.assertEqual(6144, memory_usage)

    def test_skips_processes_that_cannot_be_inspected(self):
        class UnavailableProcess:
            @property
            def info(self):
                raise psutil.AccessDenied(pid=1)

        processes = [
            UnavailableProcess(),
            SimpleNamespace(info={
                'name': 'litespeed',
                'memory_info': SimpleNamespace(rss=1024),
            }),
        ]

        memory_usage = get_service_memory_usage(
            ('litespeed', 'lshttpd'), lambda attrs: processes)

        self.assertEqual(1024, memory_usage)


if __name__ == '__main__':
    unittest.main()


class RootProcessTableTests(unittest.TestCase):
    def test_table_parsing_and_sums(self):
        from serverStatus.views import process_table, unit_memory
        out = '  4096 mariadb.service mysqld\n  1024 lshttpd.service litespeed\n   512 lshttpd.service lsphp\n bad line\n'
        table = process_table(lambda cmd: out)
        self.assertEqual(len(table), 3)
        self.assertEqual(get_service_memory_usage(('mariadbd', 'mysqld'), table=table), 4096 * 1024)
        self.assertEqual(unit_memory(table, 'lshttpd'), 1536 * 1024)
