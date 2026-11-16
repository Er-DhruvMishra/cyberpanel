import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from universalAddons.bans import actions, service as sv, views
from universalAddons.tests.helpers import post

STATUS = """Status
|- Number of jail:\t3
`- Jail list:\tdovecot, postfix-sasl, sshd"""

SSHD = """Status for the jail: sshd
|- Filter
|  |- Currently failed:\t44
|  |- Total failed:\t4497
|  `- File list:\t/var/log/secure
`- Actions
   |- Currently banned:\t2
   |- Total banned:\t375
   `- Banned IP list:\t210.206.95.162 2001:db8::7"""

IGNORE = """These IP addresses/networks are ignored:
|- 127.0.0.0/8
|- ::1
`- 157.49.36.44"""

JAIL_LOCAL = """[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 157.49.36.44
banaction = firewallcmd-rich-rules

[sshd]
enabled  = true
logpath  = /var/log/secure

[postfix-sasl]
enabled  = true
filter   = postfix[mode=auth]
port     = smtp,
           submission
"""


class Validation(SimpleTestCase):
    def test_jail_names(self):
        self.assertEqual(sv.check_jail('postfix-sasl', ['postfix-sasl']), 'postfix-sasl')
        for bad in ('sshd; reboot', '../x', '', 'a b', '-t', 'x' * 65, '$(id)'):
            with self.assertRaises(sv.BansError, msg=bad):
                sv.check_jail(bad)
        with self.assertRaisesRegex(sv.BansError, 'no running jail'):
            sv.check_jail('nginx', ['sshd'])

    def test_addresses(self):
        self.assertEqual(sv.check_ip(' 203.0.113.7 '), '203.0.113.7')
        self.assertEqual(sv.check_ip('2001:DB8::7'), '2001:db8::7')
        for bad in ('203.0.113.0/24', '010.1.1.1', 'example.com', '1.2.3.4; rm', '1.2.3', '', '-1.2.3.4'):
            with self.assertRaises(sv.BansError, msg=bad):
                sv.check_ip(bad)
        self.assertEqual(sv.check_entry('198.51.100.0/24'), '198.51.100.0/24')
        with self.assertRaises(sv.BansError):
            sv.check_entry('198.51.100.1/24')    # host bits set


class Parsing(SimpleTestCase):
    def test_status_outputs(self):
        self.assertEqual(sv.parse_jails(STATUS), ['dovecot', 'postfix-sasl', 'sshd'])
        jail = sv.parse_jail_status(SSHD)
        self.assertEqual((jail['currently_failed'], jail['total_failed'], jail['currently_banned'], jail['total_banned']),
                         (44, 4497, 2, 375))
        self.assertEqual(jail['banned'], ['210.206.95.162', '2001:db8::7'])
        self.assertEqual(jail['logs'], ['/var/log/secure'])
        self.assertEqual(sv.parse_ignore(IGNORE), ['127.0.0.0/8', '::1', '157.49.36.44'])

    def test_filters_from_config(self):
        filters = sv.jail_filters(['[DEFAULT]\nfilter = %(__name__)s[mode=%(mode)s]\n', JAIL_LOCAL],
                                  ['sshd', 'postfix-sasl'])
        self.assertEqual(filters, {'sshd': 'sshd', 'postfix-sasl': 'postfix[mode=auth]'})
        self.assertEqual(sv.parse_ini_sections(JAIL_LOCAL)['postfix-sasl']['port'], 'smtp, submission')

    def test_covers(self):
        self.assertEqual(sv.covers(['127.0.0.0/8', '157.49.36.44', 'junk'], '127.0.0.5'), ['127.0.0.0/8'])
        self.assertEqual(sv.covers(['::1'], '1.2.3.4'), [])

    def test_dropin_keeps_what_jail_local_ignores(self):
        text = sv.render_dropin(['198.51.100.4', '2001:db8::/64'])
        self.assertIn('[DEFAULT]', text)
        self.assertIn('ignoreip = %(known/ignoreip)s 198.51.100.4 2001:db8::/64', text)
        self.assertEqual(sv.parse_dropin(text), ['198.51.100.4', '2001:db8::/64'])
        with self.assertRaises(sv.BansError):
            sv.render_dropin(['1.2.3.4\n[sshd]\nenabled = false'])


def fake_client(outputs, calls):
    def runner(argv, **kwargs):
        calls.append(argv)
        key = ' '.join(argv[1:])
        return SimpleNamespace(returncode=0, stdout=outputs.get(key, outputs.get('*', '')))
    return runner


class Actions(SimpleTestCase):
    def setUp(self):
        patch = mock.patch.object(actions.ssh_actions, '_which', return_value='/usr/bin/fail2ban-client')
        patch.start()
        self.addCleanup(patch.stop)

    def test_unban_runs_fail2ban_client_with_argv(self):
        calls = []
        actions.unban('sshd', '210.206.95.162', runner=fake_client({'status': STATUS}, calls))
        self.assertEqual(calls[-1], ['fail2ban-client', 'set', 'sshd', 'unbanip', '210.206.95.162'])
        with self.assertRaises(sv.BansError):
            actions.unban('nginx', '210.206.95.162', runner=fake_client({'status': STATUS}, []))

    def test_ban_refuses_ignored_and_own_addresses(self):
        calls = []
        runner = fake_client({'status': STATUS, 'get sshd ignoreip': IGNORE}, calls)
        with mock.patch.object(actions.ssh_actions, 'server_ips', return_value=['203.0.113.1']):
            with self.assertRaisesRegex(sv.BansError, 'ignore list'):
                actions.ban('sshd', '157.49.36.44', runner=runner)
            with self.assertRaisesRegex(sv.BansError, 'connected from'):
                actions.ban('sshd', '198.51.100.9', client=['198.51.100.9'], runner=runner)
            with self.assertRaisesRegex(sv.BansError, 'belongs to this server'):
                actions.ban('sshd', '203.0.113.1', runner=runner)
            actions.ban('sshd', '198.51.100.10', runner=runner)
        self.assertEqual(calls[-1], ['fail2ban-client', 'set', 'sshd', 'banip', '198.51.100.10'])

    def test_whitelist_is_tested_reloaded_and_rolled_back_if_an_address_is_lost(self):
        directory = tempfile.mkdtemp()
        dropin = os.path.join(directory, 'zz.local')
        calls = []
        state = {'reloaded': False}

        def runner(argv, **kwargs):
            calls.append(argv[1:])
            if argv[1:] == ['status']:
                return SimpleNamespace(returncode=0, stdout='`- Jail list:\tsshd')
            if argv[1:] == ['reload']:
                state['reloaded'] = True
            if argv[1:3] == ['get', 'sshd']:
                # After the reload the old addresses vanish: known/ did not work.
                out = '`- 198.51.100.4' if state['reloaded'] and os.path.exists(dropin) else IGNORE
                return SimpleNamespace(returncode=0, stdout=out)
            return SimpleNamespace(returncode=0, stdout='')
        with self.assertRaisesRegex(sv.BansError, 'undone'):
            actions.set_whitelist(['198.51.100.4'], runner=runner, dropin=dropin, backup_dir=directory)
        self.assertFalse(os.path.exists(dropin))         # rolled back
        self.assertIn(['-t'], calls)

        state['reloaded'] = False

        def good(argv, **kwargs):
            if argv[1:] == ['status']:
                return SimpleNamespace(returncode=0, stdout='`- Jail list:\tsshd')
            if argv[1:3] == ['get', 'sshd']:
                return SimpleNamespace(returncode=0, stdout=IGNORE + ('\n`- 198.51.100.4' if os.path.exists(dropin) else ''))
            return SimpleNamespace(returncode=0, stdout='')
        result = actions.set_whitelist(['198.51.100.4'], runner=good, dropin=dropin, backup_dir=directory)
        self.assertTrue(result['changed'])
        self.assertIn('%(known/ignoreip)s 198.51.100.4', open(dropin).read())
        result = actions.set_whitelist([], runner=good, dropin=dropin, backup_dir=directory)
        self.assertTrue(result['backup'] and os.path.exists(result['backup']))

    def test_rejected_config_is_undone(self):
        directory = tempfile.mkdtemp()
        dropin = os.path.join(directory, 'zz.local')

        def runner(argv, **kwargs):
            if argv[1:] == ['status']:
                return SimpleNamespace(returncode=0, stdout='`- Jail list:\tsshd')
            if argv[1:] == ['-t']:
                return SimpleNamespace(returncode=255, stdout='ERROR bad config')
            return SimpleNamespace(returncode=0, stdout=IGNORE)
        with self.assertRaisesRegex(sv.BansError, 'rejected'):
            actions.set_whitelist(['198.51.100.4'], runner=runner, dropin=dropin, backup_dir=directory)
        self.assertFalse(os.path.exists(dropin))


class Views(SimpleTestCase):
    def test_admin_only(self):
        status, _, _ = post(views.overview, {})
        self.assertEqual(status, 403)

    def test_ipv6_travels_in_an_object_and_is_validated(self):
        with mock.patch('universalAddons.bans.views.privileged.call', return_value={}) as call:
            status, _, _ = post(views.unban, {'q': {'jail': 'sshd', 'ip': '2001:db8::7'}}, admin=True)
            self.assertEqual(status, 200)
            call.assert_called_once_with('bans', 'unban', jail='sshd', ip='2001:db8::7')
            status, _, _ = post(views.unban, {'q': {'jail': 'sshd;id', 'ip': '1.2.3.4'}}, admin=True)
            self.assertEqual(status, 400)
            status, _, _ = post(views.ban, {'jail': 'sshd', 'ip': '1.2.3.4'}, admin=True)
            self.assertEqual(status, 400)
