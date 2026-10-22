import json
import os
import stat
import subprocess
import tempfile
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, SimpleTestCase

from universalAddons import privileged
from universalAddons.rootfm import views

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def admin(value=1):
    return mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': value})


class RootFMViews(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        patcher = mock.patch.object(views, '_actor', return_value='admin')
        patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, view, body, is_admin=1):
        request = self.factory.post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with admin(is_admin):
            response = view(request)
        return response.status_code, json.loads(response.content)

    def test_every_endpoint_requires_admin(self):
        for name in ('listing', 'read', 'write', 'create', 'rename', 'copy', 'move', 'trash', 'list_trash',
                     'restore', 'purge', 'chmod', 'chown', 'extract', 'compress', 'search', 'du', 'checksum'):
            with mock.patch('universalAddons.privileged.call') as call:
                status, body = self.post(getattr(views, name), {'path': '/tmp'}, is_admin=0)
            self.assertEqual(status, 403, name)
            call.assert_not_called()

    def test_protected_error_is_flagged_for_the_ui(self):
        with mock.patch('universalAddons.privileged.call', side_effect=RuntimeError('PROTECTED:/etc is protected.')):
            status, body = self.post(views.trash, {'paths': ['/etc/x']})
        self.assertEqual(body, {'status': 0, 'error_message': '/etc is protected.', 'protected': 1})

    def test_unlock_must_be_literal_true(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.post(views.trash, {'paths': ['/a'], 'unlock': 'yes'})
            self.post(views.trash, {'paths': ['/a'], 'unlock': True})
        self.assertFalse(call.call_args_list[0][1]['unlock'])
        self.assertTrue(call.call_args_list[1][1]['unlock'])

    def test_write_uses_reserved_content_key_and_sha(self):
        with mock.patch('universalAddons.privileged.call', return_value={'sha256': 'x'}) as call:
            self.post(views.write, {'path': '/tmp/a', 'fileContent': 'a;b|c$d', 'sha256': 'abc'})
        call.assert_called_once_with('rootfm', 'write', path='/tmp/a', content='a;b|c$d', expected_sha256='abc',
                                     unlock=False, actor='admin')

    def test_input_validation(self):
        with mock.patch('universalAddons.privileged.call') as call:
            self.assertEqual(self.post(views.copy, {'paths': 'not-a-list', 'destination': '/x'})[0], 400)
            self.assertEqual(self.post(views.copy, {'paths': ['relative'], 'destination': '/x'})[0], 400)
            self.assertEqual(self.post(views.create, {'directory': '/x', 'name': 'a', 'kind': 'socket'})[0], 400)
            self.assertEqual(self.post(views.compress, {'paths': ['/a'], 'destination': '/', 'name': 'a',
                                                        'format': 'rar'})[0], 400)
        call.assert_not_called()

    def test_upload_spools_privately_then_calls_root(self):
        spool = tempfile.mkdtemp()
        os.chmod(spool, 0o700)
        seen = {}

        def fake_call(module, action, **args):
            path = privileged.spool_path(args['spool_id'], spool)
            seen['mode'] = stat.S_IMODE(os.stat(path).st_mode)
            with open(path, 'rb') as handle:
                seen['data'] = handle.read()
            seen['args'] = args
            return {'name': 'up.txt'}

        request = self.factory.post('/x', data={'directory': '/srv', 'file': SimpleUploadedFile('../up.txt', b'payload')})
        request.session = {'userID': 1}
        with admin(), mock.patch.object(privileged, 'SPOOL_DIR', spool), \
                mock.patch('universalAddons.privileged.call', side_effect=fake_call):
            response = views.upload(request)
        self.assertEqual(json.loads(response.content)['status'], 1)
        self.assertEqual((seen['mode'], seen['data']), (0o600, b'payload'))
        self.assertEqual(seen['args']['name'], 'up.txt')
        self.assertEqual(os.listdir(spool), [])

    def test_upload_rejects_non_admin(self):
        request = self.factory.post('/x', data={'directory': '/srv', 'file': SimpleUploadedFile('a', b'x')})
        request.session = {'userID': 1}
        with admin(0), mock.patch('universalAddons.privileged.call') as call:
            self.assertEqual(views.upload(request).status_code, 403)
        call.assert_not_called()


class SpoolTrust(SimpleTestCase):
    def test_open_spool_rejects_unsafe_files(self):
        spool = tempfile.mkdtemp()
        os.chmod(spool, 0o700)
        uid = os.getuid()
        good = privileged.write_spool(b'{"a": 1}', spool)
        self.assertEqual(privileged.read_spool_args(good, uid, spool), {'a': 1})
        self.assertFalse(os.path.exists(os.path.join(spool, good)))
        # wrong owner
        other = privileged.write_spool(b'{}', spool)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            privileged.open_spool(other, uid + 1, spool)
        # group/world writable file
        os.chmod(os.path.join(spool, other), 0o666)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            privileged.open_spool(other, uid, spool)
        # symlink planted under a valid id
        link_id = privileged.new_spool_id()
        os.symlink('/etc/hostname', os.path.join(spool, link_id))
        with self.assertRaises(OSError):
            privileged.open_spool(link_id, uid, spool)
        # loose directory permissions
        os.chmod(spool, 0o755)
        with self.assertRaisesRegex(ValueError, 'directory'):
            privileged.open_spool(good if False else other, uid, spool)
        for bad in ('../x', 'abc', 'G' * 32):
            with self.assertRaises(ValueError):
                privileged.spool_path(bad, spool)

    def test_large_arguments_go_through_spool(self):
        spool = tempfile.mkdtemp()
        os.chmod(spool, 0o700)
        command = privileged.build_command('rootfm', 'write', {'content': 'x' * 200000}, spool_dir=spool)
        self.assertRegex(command, r' rootfm write --spool [0-9a-f]{32}$')
        self.assertEqual(len(os.listdir(spool)), 1)


class JavaScript(SimpleTestCase):
    def test_all_addon_js_parses(self):
        static = os.path.join(REPO, 'universalAddons', 'static', 'universalAddons')
        for name in os.listdir(static):
            if name.endswith('.js'):
                result = subprocess.run(['node', '--check', os.path.join(static, name)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                self.assertEqual(result.returncode, 0, name + result.stderr)

    def test_template_ids_used_by_js_exist(self):
        import re
        for module in ('emaildebug', 'rootfm', 'rspamd', 'sslv2'):
            with open(os.path.join(REPO, 'universalAddons/static/universalAddons/%s.js' % module)) as handle:
                ids = set(re.findall(r"\$\('([a-z-]+)'\)", handle.read()))
            with open(os.path.join(REPO, 'universalAddons/templates/universalAddons/%s.html' % module)) as handle:
                html = handle.read()
            self.assertEqual(sorted(i for i in ids if 'id="%s"' % i not in html and not i.startswith('pane-')), [],
                             module)
