import unittest
import json

from django.http import HttpResponse
from django.test import RequestFactory

from CyberCP.secMiddleware import secMiddleware


class SecurityMiddlewareTests(unittest.TestCase):

    def test_content_security_policy_is_emitted_as_one_complete_header(self):
        request = RequestFactory().get('/')
        request.session = {}
        response = secMiddleware(lambda unused_request: HttpResponse('ok'))(request)
        policy = response['Content-Security-Policy']

        self.assertIn("default-src 'self'", policy)
        self.assertIn("script-src 'self'", policy)
        self.assertIn('connect-src *', policy)
        self.assertIn("object-src 'none'", policy)
        self.assertIn("base-uri 'self'", policy)
        self.assertIn("frame-ancestors 'self'", policy)

    def test_login_password_allows_common_special_characters(self):
        request = RequestFactory().post(
            '/verifyLogin',
            data=json.dumps({
                'username': 'admin',
                'password': "valid$pass|with;special&chars",
            }),
            content_type='application/json',
        )
        request.session = {}

        response = secMiddleware(
            lambda unused_request: HttpResponse('login-view-reached')
        )(request)

        self.assertEqual(b'login-view-reached', response.content)

    def test_login_username_keeps_command_character_validation(self):
        request = RequestFactory().post(
            '/verifyLogin',
            data=json.dumps({
                'username': 'admin;touch /tmp/example',
                'password': 'valid-password',
            }),
            content_type='application/json',
        )
        request.session = {}

        response = secMiddleware(
            lambda unused_request: HttpResponse('login-view-reached')
        )(request)

        self.assertNotEqual(b'login-view-reached', response.content)
        self.assertIn(b'potentially dangerous characters', response.content)

    def test_database_password_allows_special_characters_on_account_endpoints(self):
        for path in (
            '/dataBases/submitDBCreation',
            '/dataBases/changePassword',
        ):
            request = RequestFactory().post(
                path,
                data=json.dumps({
                    'dbUserName': 'site_user',
                    'dbPassword': "valid $pass|with;'special&chars",
                }),
                content_type='application/json',
            )
            request.session = {'userID': 1}

            response = secMiddleware(
                lambda unused_request: HttpResponse('database-view-reached')
            )(request)

            self.assertEqual(b'database-view-reached', response.content)

    def test_database_password_exemption_does_not_cover_other_fields(self):
        request = RequestFactory().post(
            '/dataBases/submitDBCreation',
            data=json.dumps({
                'dbName': 'site;DROP_DATABASE',
                'dbPassword': 'valid$password',
            }),
            content_type='application/json',
        )
        request.session = {'userID': 1}

        response = secMiddleware(
            lambda unused_request: HttpResponse('database-view-reached')
        )(request)

        self.assertNotEqual(b'database-view-reached', response.content)


class FileManagerFilenameTests(unittest.TestCase):
    """File names like "portfolio (2).zip" must reach the file manager, whose paths are
    always single-quoted; command-chaining characters stay blocked there and elsewhere."""

    def _post(self, path, payload):
        request = RequestFactory().post(path, data=json.dumps(payload), content_type='application/json')
        request.session = {'userID': 1}
        return secMiddleware(lambda unused_request: HttpResponse('view-reached'))(request)

    def test_parentheses_brackets_and_ampersand_reach_the_file_manager(self):
        for name in ('portfolio (2).zip', 'photo [edited].png', 'Tom & Jerry.mp4', "it's.txt"):
            response = self._post('/filemanager/controller', {
                'method': 'deleteFolderOrFile', 'domainName': 'shukla.pro',
                'path': '/home/shukla.pro/anuj.shukla.pro', 'fileAndFolders': [name]})
            self.assertEqual(b'view-reached', response.content, name)

    def test_command_characters_stay_blocked_in_file_manager(self):
        for name in ('a;rm -rf x', 'a && b', 'a | b', 'a$(id)', 'a`id`', 'a > b'):
            response = self._post('/filemanager/controller', {
                'method': 'deleteFolderOrFile', 'domainName': 'shukla.pro',
                'path': '/home/shukla.pro', 'fileAndFolders': [name]})
            self.assertNotEqual(b'view-reached', response.content, name)

    def test_parentheses_still_blocked_outside_the_file_manager(self):
        response = self._post('/websites/submitWebsiteCreation', {'domainName': 'a(b).com'})
        self.assertNotEqual(b'view-reached', response.content)
