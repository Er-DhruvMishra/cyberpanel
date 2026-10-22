import json
import os
import re
import subprocess
import sys
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons import privileged, registry, runner
from universalAddons.emaildebug import views as emaildebug_views

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class PrivilegedBridge(SimpleTestCase):
    def test_command_is_shell_inert(self):
        hostile = {'domain': "x.com; rm -rf / `id` $(id) '\"\n|&<>"}
        command = privileged.build_command('emaildebug', 'dns', hostile)
        self.assertRegex(command, r'^[A-Za-z0-9_/. =-]+$')
        token = command.rsplit(' ', 1)[1]
        self.assertEqual(privileged.decode_args(token), hostile)

    def test_rejects_bad_names_and_encodings(self):
        for module, action in (('emaildebug', 'dns;id'), ('../x', 'dns'), ('Email', 'dns')):
            with self.assertRaises(ValueError):
                privileged.build_command(module, action, {})
        with self.assertRaises(ValueError):
            privileged.decode_args('abc$def')

    def test_parse_output(self):
        good = 'noise\n' + privileged.MARKER + json.dumps({'ok': True, 'result': {'a': 1}})
        self.assertEqual(privileged.parse_output(good), {'a': 1})
        with self.assertRaisesRegex(RuntimeError, 'boom'):
            privileged.parse_output(privileged.MARKER + json.dumps({'ok': False, 'error': 'boom'}))
        with self.assertRaisesRegex(RuntimeError, 'No result'):
            privileged.parse_output('Traceback ...')

    def test_call_uses_executor_and_tuple_output(self):
        seen = []

        def executor(command, retRequired=None):
            seen.append(command)
            return 0, privileged.MARKER + json.dumps({'ok': True, 'result': 'x'})
        self.assertEqual(privileged.call('emaildebug', 'context', executor=executor), 'x')
        self.assertTrue(seen[0].startswith(privileged.PYTHON + ' ' + privileged.RUNNER + ' emaildebug context '))

    def test_runner_end_to_end_as_subprocess(self):
        token = privileged.encode_args({'domain': 'bad domain'})
        out = subprocess.run([sys.executable, os.path.join(REPO, 'universalAddons', 'runner.py'),
                              'emaildebug', 'dns', token], stdout=subprocess.PIPE, universal_newlines=True,
                             cwd='/', env=dict(os.environ, PYTHONPATH=''))
        with self.assertRaisesRegex(RuntimeError, 'Invalid domain'):
            privileged.parse_output(out.stdout)
        self.assertEqual(out.returncode, 1)

    def test_runner_rejects_unknown(self):
        self.assertEqual(runner.main(['runner.py', 'nope', 'x', '']), 1)
        self.assertEqual(runner.main(['runner.py', 'emaildebug', 'nope', '']), 1)


class Registry(SimpleTestCase):
    def test_modules_have_unique_keys_and_ready_ones_have_urls(self):
        keys = [m.key for m in registry.MODULES]
        self.assertEqual(len(keys), len(set(keys)))
        for module in registry.MODULES:
            if module.state == 'ready':
                self.assertTrue(module.url_name)

    def test_requirement_problems(self):
        self.assertEqual(registry.requirement_problems('emaildebug', which=lambda n: '/usr/bin/dig',
                                                       exists=lambda p: True), [])
        problems = registry.requirement_problems('emaildebug', which=lambda n: None, exists=lambda p: False)
        self.assertEqual(len(problems), 2)


class EmailDebuggerViews(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def post(self, view, body, admin=True, method='post'):
        request = getattr(self.factory, method)('/addons/email-debugger/ajax/x', data=json.dumps(body),
                                                content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1 if admin else 0}):
            response = view(request)
        return response.status_code, json.loads(response.content)

    def test_non_admin_rejected(self):
        status, body = self.post(emaildebug_views.dns, {'domain': 'example.com'}, admin=False)
        self.assertEqual((status, body['status']), (403, 0))

    def test_not_logged_in(self):
        request = self.factory.post('/x', data='{}', content_type='application/json')
        request.session = {}
        response = emaildebug_views.dns(request)
        self.assertEqual(response.status_code, 401)

    def test_get_rejected(self):
        request = self.factory.get('/x')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1}):
            self.assertEqual(emaildebug_views.dns(request).status_code, 405)

    def test_invalid_domain_never_reaches_runner(self):
        with mock.patch('universalAddons.privileged.call') as call:
            status, body = self.post(emaildebug_views.dns, {'domain': 'a.com;id'})
        self.assertEqual(status, 400)
        call.assert_not_called()

    def test_dns_passes_validated_domain(self):
        with mock.patch('universalAddons.privileged.call', return_value={'ok': 1}) as call:
            status, body = self.post(emaildebug_views.dns, {'domain': ' Example.COM '})
        self.assertEqual((status, body), (200, {'status': 1, 'result': {'ok': 1}}))
        call.assert_called_once_with('emaildebug', 'dns', domain='example.com')

    def test_runner_error_is_reported(self):
        with mock.patch('universalAddons.privileged.call', side_effect=RuntimeError('No mail log')):
            status, body = self.post(emaildebug_views.logs, {'query': 'x'})
        self.assertEqual(body, {'status': 0, 'error_message': 'No mail log'})

    def test_send_requires_hosted_sender_domain(self):
        with mock.patch.object(emaildebug_views, '_hosted_domains', return_value=['example.com']), \
                mock.patch('universalAddons.privileged.call', return_value={'message_id': 'm'}) as call:
            status, _ = self.post(emaildebug_views.send, {'sender': 'a@other.com', 'recipient': 'b@x.org'})
            self.assertEqual(status, 400)
            call.assert_not_called()
            status, body = self.post(emaildebug_views.send, {'sender': 'a@example.com', 'recipient': 'b@x.org'})
        self.assertEqual(body['result'], {'message_id': 'm'})

    def test_spam_uses_reserved_message_key(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.post(emaildebug_views.spam, {'emailMessage': 'Subject: x\n\nbody'})
        call.assert_called_once_with('emaildebug', 'spam', message='Subject: x\n\nbody')

    def test_urls_avoid_middleware_api_relaxation(self):
        from universalAddons.emaildebug.urls import urlpatterns
        for pattern in urlpatterns:
            self.assertNotIn('api/', str(pattern.pattern))


class Templates(SimpleTestCase):
    def test_templates_compile(self):
        from django.template.loader import get_template
        for name in ('universalAddons/hub.html', 'universalAddons/emaildebug.html'):
            get_template(name)

    def test_js_ids_exist_in_template(self):
        with open(os.path.join(REPO, 'universalAddons/static/universalAddons/emaildebug.js')) as handle:
            ids = set(re.findall(r"\$\('([a-z-]+)'\)", handle.read()))
        with open(os.path.join(REPO, 'universalAddons/templates/universalAddons/emaildebug.html')) as handle:
            html = handle.read()
        missing = [i for i in ids if 'id="%s"' % i not in html and not i.startswith('pane-')]
        self.assertEqual(missing, [])
