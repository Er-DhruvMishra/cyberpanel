"""Regression tests for half-created child domains (anuj.shukla.pro, 2026-11-17).

A child domain created with the Apache backend and a PHP version whose PHP-FPM was not
installed failed after its web-server config existed; the cleanup removed the config but
left the database record, so the panel listed a domain that served 404. Re-creating it then
replaced the owner's index.html with the panel placeholder.
"""
import inspect
import os
import tempfile
import unittest
from unittest import mock

from plogical import vhost as vhost_module
from plogical import virtualHostUtilities as vhu


class ApacheFpmPreflight(unittest.TestCase):

    def test_apache_child_refused_before_anything_is_created_when_fpm_missing(self):
        missing = os.path.join(tempfile.mkdtemp(), 'php85', 'php-fpm.d')
        with mock.patch.object(vhu, 'Administrator') as admin, \
                mock.patch.object(vhu, 'Websites') as websites, \
                mock.patch.object(vhu.ProcessUtilities, 'decideServer', return_value=vhu.ProcessUtilities.OLS), \
                mock.patch.object(vhu.ApacheVhost, 'DecidePHPPath', return_value=missing + '/anuj.example.com.conf'), \
                mock.patch.object(vhu.vhost, 'createDirectoryForDomain') as create_dir, \
                mock.patch.object(vhu.ChildDomains, 'save') as save, \
                mock.patch.object(vhu.logging.CyberCPLogFileWriter, 'statusWriter'):
            admin.objects.get.return_value = mock.Mock()
            websites.objects.get.return_value = mock.Mock()
            status, message = vhu.virtualHostUtilities.createDomain(
                'example.com', 'anuj.example.com', 'PHP 8.5', '/home/example.com/anuj.example.com',
                0, 0, 0, 'owner', 1, LimitsCheck=0)
        self.assertEqual(status, 0)
        self.assertIn('PHP-FPM', message)
        create_dir.assert_not_called()
        save.assert_not_called()


class FailedCreationCleanup(unittest.TestCase):

    def test_failure_after_record_saved_deletes_the_record(self):
        source = inspect.getsource(vhu.virtualHostUtilities.createDomain)
        self.assertIn('createdChild = website', source)
        self.assertIn('createdChild.delete()', source)
        self.assertLess(source.index('createdChild = None'), source.index('try:'))


class PlaceholderNeverOverwrites(unittest.TestCase):

    def test_child_placeholder_copy_is_no_clobber(self):
        source = inspect.getsource(vhost_module.vhost.finalizeDomainCreation)
        self.assertIn("cp -n %s %s/index.html", source)

    def test_master_placeholder_skips_existing_index(self):
        source = inspect.getsource(vhost_module.vhost.finalizeVhostCreation)
        self.assertIn('if not os.path.lexists(placeholder)', source)


if __name__ == '__main__':
    unittest.main()


class ChildDomainFileManager(unittest.TestCase):

    def test_child_domain_redirects_to_main_site_file_manager(self):
        from django.test import RequestFactory
        from filemanager import views
        request = RequestFactory().get('/filemanager/anuj.example.com')
        request.session = {'userID': 1}
        child = mock.Mock(); child.master.domain = 'example.com'
        with mock.patch.object(views.Websites.objects, 'filter') as sites, \
                mock.patch('websiteFunctions.models.ChildDomains.objects') as children:
            sites.return_value.exists.return_value = False
            children.filter.return_value.select_related.return_value.first.return_value = child
            response = views.loadFileManagerHome(request, 'anuj.example.com')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/filemanager/example.com')


class SwitchToApachePreflight(unittest.TestCase):

    def test_fpm_checked_before_the_ols_config_is_removed(self):
        source = inspect.getsource(vhu.virtualHostUtilities.switchServer)
        self.assertLess(source.index('if not os.path.isdir(fpmPoolDir)'),
                        source.index('os.remove(completePathToConfigFile)'))


class Placeholder(unittest.TestCase):

    def test_placeholder_is_indianscloud_with_service_links(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'index.html')
        html = open(path, encoding='utf-8').read()
        self.assertNotIn('CyberPanel', html)
        for link in ('https://indianscloud.com/webmail-rc/', 'https://indianscloud.com/contact.php',
                     'https://indianscloud.com:8090/', 'https://indianscloud.com/submitticket.php'):
            self.assertIn(link, html)
        self.assertIn('textContent', html)      # host name is inserted as text, never as HTML
