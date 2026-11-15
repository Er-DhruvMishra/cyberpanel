import json
import os
import tempfile
import time
from unittest import mock

from django.test import SimpleTestCase

from baseTemplate import views


class WordPressCount(SimpleTestCase):
    def setUp(self):
        self.cache = os.path.join(tempfile.mkdtemp(), 'wp.json')
        patcher = mock.patch.object(views, 'WP_COUNT_CACHE', self.cache)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_counts_detected_installs_not_registry_rows(self):
        with mock.patch('universalAddons.privileged.call', return_value={'installs': [{'domain': 'a.com'}, {'domain': 'b.com'}]}):
            self.assertEqual(views._wordpress_installs(None, 34), 2)
            self.assertEqual(views._wordpress_installs(['b.com', 'c.com'], 34), 1)

    def test_fresh_cache_is_used_and_stale_cache_refreshed(self):
        json.dump({'at': time.time(), 'domains': ['x.com']}, open(self.cache, 'w'))
        with mock.patch('universalAddons.privileged.call') as call:
            self.assertEqual(views._wordpress_installs(None, 34), 1)
            call.assert_not_called()
        json.dump({'at': time.time() - 3600, 'domains': ['x.com']}, open(self.cache, 'w'))
        with mock.patch('universalAddons.privileged.call', return_value={'installs': []}) as call:
            self.assertEqual(views._wordpress_installs(None, 34), 0)
            call.assert_called_once()

    def test_falls_back_to_table_count_when_detection_fails(self):
        with mock.patch('universalAddons.privileged.call', side_effect=RuntimeError('no runner')):
            self.assertEqual(views._wordpress_installs(None, 34), 34)
