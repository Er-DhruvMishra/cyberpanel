import json
import os
import tempfile
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons import access, views


class PolicyKeys(SimpleTestCase):
    def test_saves_only_given_switches_and_keeps_other_keys(self):
        path = os.path.join(tempfile.mkdtemp(), 'p.json')
        with open(path, 'w') as handle:
            json.dump({'max_apps_per_site': 7, 'apps_for_users': True}, handle)
        policy = access.save_policy_keys({'terminal_for_users': True}, path)
        self.assertTrue(policy['terminal_for_users'])
        self.assertTrue(policy['apps_for_users'])
        self.assertEqual(policy['max_apps_per_site'], 7)
        self.assertEqual(access.user_modules(policy), ['apps', 'webterm'])

    def test_rejects_unknown_or_non_boolean(self):
        path = os.path.join(tempfile.mkdtemp(), 'p.json')
        for bad in ({'max_apps_per_site': 99}, {'apps_for_users': 'yes'}, {'rootfm_for_users': True}):
            with self.assertRaises(ValueError, msg=bad):
                access.save_policy_keys(bad, path)


class Hub(SimpleTestCase):
    def render(self, admin, policy):
        request = RequestFactory().get('/addons/')
        request.session = {'userID': 4}
        captured = {}

        class Proc:
            def __init__(self, request, template, data, *args):
                captured.update(data)

            def render(self):
                return 'ok'
        with mock.patch('universalAddons.views.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.views.load_policy', return_value=dict(access.DEFAULT_POLICY, **policy)), \
                mock.patch('universalAddons.views.httpProc', Proc):
            views.hub(request)
        return captured

    def test_users_see_only_allowed_addons(self):
        data = self.render(0, {'mssql_for_users': True})
        self.assertEqual([m['key'] for m in data['modules']], ['mssql'])
        self.assertEqual(data['user_access'], [])
        self.assertEqual(self.render(0, {})['modules'], [])

    def test_admin_sees_everything_and_the_access_switches(self):
        data = self.render(1, {'apps_for_users': True, 'backup_for_users': True})
        self.assertGreater(len(data['modules']), 10)
        switches = {a['key']: a['enabled'] for a in data['user_access']}
        self.assertEqual(switches, {
            'wordpress': False, 'backupv2': True, 'sslv2': False, 'htaccess': False, 'emaildebug': False,
            'limits': False, 'apps': True, 'mssql': False, 'emaillimits': False, 'webterm': False,
            'cloudflare': False, 'laravel': False, 'gitdeploy': False,
            'sitetools': False})
        for row in data['user_access']:
            self.assertTrue(row['help'], row['key'])            # a short description of what users get
            self.assertNotEqual(row['title'], row['key'])        # the module's real title
        self.assertEqual([a['switch'] for a in data['user_access']], [s for _, s in access.USER_FEATURES])

    def test_new_switches_open_their_module_to_users(self):
        for key, switch in (('wordpress', 'wordpress_for_users'), ('backupv2', 'backup_for_users'),
                            ('sslv2', 'ssl_for_users'), ('htaccess', 'htaccess_for_users'),
                            ('emaildebug', 'email_debug_for_users'), ('limits', 'limits_for_users')):
            self.assertIs(access.DEFAULT_POLICY[switch], False, switch)
            self.assertEqual([m['key'] for m in self.render(0, {switch: True})['modules']], [key])

    def test_server_wide_modules_have_no_user_switch(self):
        keys = {key for key, _ in access.USER_FEATURES}
        for key in ('rootfm', 'storage', 'sshsec', 'mysqlmgr', 'rspamd', 'apache', 'roundcube'):
            self.assertNotIn(key, keys)

    def test_template_has_select_all_clear_all_and_spaced_labels(self):
        from django.template.loader import get_template
        source = get_template('universalAddons/hub.html').template.source
        for needle in ('id="ua-access-all"', 'id="ua-access-none"', 'class="ua-check"', 'ua-check-help'):
            self.assertIn(needle, source)
        css = open(os.path.join(os.path.dirname(access.__file__), 'static', 'universalAddons', 'addons.css')).read()
        self.assertIn('.ua-check { display: flex; align-items: flex-start; gap: 10px;', css)
        self.assertIn('.ua-row input[type=checkbox], .ua-row input[type=radio] { min-width: 0; }', css)

    def post(self, body, admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 4}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'user_modules': []}) as call:
            response = views.user_access(request)
        return response.status_code, call

    def test_access_endpoint_admin_only_and_validated(self):
        self.assertEqual(self.post({'apps_for_users': True}, admin=0)[0], 403)
        status, call = self.post({'apps_for_users': 'yes'})
        self.assertEqual(status, 400)
        call.assert_not_called()
        status, call = self.post({'webterm_for_users': True, 'terminal_for_users': True, 'max_apps_per_site': 9})
        call.assert_called_once_with('hub', 'set_user_access', values={'terminal_for_users': True})

    def test_select_all_sends_every_switch_in_one_request(self):
        body = {switch: True for _, switch in access.USER_FEATURES}
        status, call = self.post(body)
        self.assertEqual(status, 200)
        call.assert_called_once_with('hub', 'set_user_access', values=body)

    def test_new_switches_can_be_saved(self):
        path = os.path.join(tempfile.mkdtemp(), 'p.json')
        policy = access.save_policy_keys({'wordpress_for_users': True, 'limits_for_users': True}, path)
        self.assertEqual(access.user_modules(policy), ['wordpress', 'limits'])
        policy = access.save_policy_keys({switch: False for _, switch in access.USER_FEATURES}, path)
        self.assertEqual(access.user_modules(policy), [])
