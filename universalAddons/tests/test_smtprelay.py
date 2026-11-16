import base64
import json
import os
import shutil
import smtplib
import socket
import tempfile
import threading
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons.smtprelay import actions, service as sv, views
from universalAddons.tests import helpers

SECRET = 'S3cr3t pass:with;odd$chars'
DOMAIN_SECRET = 'd0main-Secret!'

MAIN_CF = """# stock settings
myhostname = indianscloud.com
smtp_tls_security_level = may
# CyberMail SMTP Relay Configuration
relayhost = [mail.cyberpersons.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
virtual_transport = dovecot
smtp_tls_policy_maps = hash:/etc/postfix/old_policy,
    hash:/etc/postfix/other_policy
milter_default_action = accept
"""

ALL = {'scope': 'all', 'relay': {'host': 'smtp.relay.example', 'port': 587, 'tls': 'starttls', 'username': 'srv@relay'},
       'domains': [{'domain': 'Shop.Example.com', 'host': 'smtp.shop-relay.example', 'port': 587, 'tls': 'starttls',
                    'username': 'shop'},
                   {'domain': 'blog.example.org', 'username': 'blogger'}]}
SELECTED = {'scope': 'selected', 'relay': {'host': 'smtp.relay.example', 'port': 587, 'tls': 'starttls', 'username': ''},
            'domains': [{'domain': 'only.example.com'}]}


class Validation(SimpleTestCase):
    def test_normalises(self):
        config = sv.validate_config(ALL)
        self.assertEqual([d['domain'] for d in config['domains']], ['blog.example.org', 'shop.example.com'])
        self.assertEqual(config['domains'][0]['host'], '')

    def test_rejects(self):
        bad = [
            {'scope': 'all', 'relay': None},
            {'scope': 'all', 'relay': {'host': 'x;rm -rf', 'port': 587}},
            {'scope': 'all', 'relay': {'host': 'smtp.example.com', 'port': 2526}},
            {'scope': 'all', 'relay': {'host': 'smtp.example.com', 'port': 587, 'tls': 'maybe'}},
            {'scope': 'all', 'relay': {'host': 'smtp.example.com', 'port': 587, 'username': 'a b'}},
            {'scope': 'selected', 'relay': None, 'domains': []},
            {'scope': 'selected', 'relay': None, 'domains': [{'domain': 'a.example.com'}]},
            {'scope': 'all', 'relay': {'host': 'smtp.example.com'}, 'domains': [{'domain': 'a.example.com'}]},
            {'scope': 'all', 'relay': {'host': 'smtp.example.com'}, 'domains': [{'domain': 'a.com', 'username': 'u'},
                                                                                 {'domain': 'A.com', 'username': 'v'}]},
            # implicit TLS is global in main.cf: not with direct delivery, not mixed with STARTTLS relays
            {'scope': 'selected', 'relay': {'host': 'smtp.example.com', 'port': 465, 'tls': 'implicit'},
             'domains': [{'domain': 'a.com'}]},
            {'scope': 'all', 'relay': {'host': 'smtp.example.com', 'port': 465, 'tls': 'implicit'},
             'domains': [{'domain': 'a.com', 'host': 'other.example.com', 'port': 587, 'tls': 'starttls'}]},
        ]
        for data in bad:
            with self.assertRaises(sv.RelayError, msg=data):
                sv.validate_config(data)
        for password in ('a\nb', ' lead', 'trail ', 'x' * 257, 5):
            with self.assertRaises(sv.RelayError):
                sv.clean_password(password)

    def test_implicit_tls_when_everything_relays(self):
        config = sv.validate_config({'scope': 'all', 'relay': {'host': 'smtp.example.com', 'port': 465, 'tls': 'implicit'}})
        self.assertIn(('smtp_tls_wrappermode', 'yes'), sv.managed_values(config))


class MainCf(SimpleTestCase):
    def test_keys_rendered_and_idempotent(self):
        config = sv.validate_config(ALL)
        once = sv.render_main_cf(MAIN_CF, config)
        self.assertEqual(sv.render_main_cf(once, config), once)
        self.assertEqual(once.count(sv.BEGIN), 1)
        block = once[once.index(sv.BEGIN):]
        self.assertIn('relayhost = [smtp.relay.example]:587\n', block)
        self.assertIn('smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\n', block)
        self.assertIn('sender_dependent_relayhost_maps = hash:/etc/postfix/indianscloud_sender_relay\n', block)
        self.assertIn('smtp_sender_dependent_authentication = yes\n', block)
        self.assertIn('smtp_tls_policy_maps = hash:/etc/postfix/indianscloud_relay_tls\n', block)
        self.assertNotIn('smtp_tls_wrappermode', block)
        # every other definition of a managed key is gone (with its continuation line); the rest is kept
        self.assertNotIn('cyberpersons', once)
        self.assertNotIn('CyberMail', once)
        self.assertNotIn('other_policy', once)
        for line in ('myhostname = indianscloud.com\n', 'smtp_tls_security_level = may\n',
                     'virtual_transport = dovecot\n', 'milter_default_action = accept\n', '# stock settings\n'):
            self.assertIn(line, once)
        for key in sv.MANAGED_KEYS:
            self.assertLessEqual(sum(1 for l in once.splitlines() if l.startswith(key + ' =')), 1, key)

    def test_selected_domains_keep_direct_delivery(self):
        out = sv.render_main_cf(MAIN_CF, sv.validate_config(SELECTED), 'lmdb')
        self.assertNotIn('\nrelayhost', out)
        self.assertIn('sender_dependent_relayhost_maps = lmdb:/etc/postfix/indianscloud_sender_relay', out)
        self.assertNotIn('smtp_sasl_auth_enable', out)   # nobody logs in

    def test_disable_removes_everything(self):
        enabled = sv.render_main_cf(MAIN_CF, sv.validate_config(ALL))
        disabled = sv.render_main_cf(enabled, None)
        self.assertNotIn(sv.BEGIN, disabled)
        for key in sv.MANAGED_KEYS:
            self.assertNotIn('\n%s =' % key, '\n' + disabled, key)
        self.assertEqual(sv.render_main_cf(disabled, None), disabled)
        self.assertIn('virtual_transport = dovecot', disabled)

    def test_foreign_settings(self):
        config = sv.validate_config(ALL)
        self.assertIn('relayhost', sv.foreign_settings(MAIN_CF, config))
        self.assertEqual(sv.foreign_settings(sv.render_main_cf(MAIN_CF, config), config), {})
        self.assertEqual(sv.foreign_settings('relayhost =\nsmtp_tls_wrappermode = no\n', config), {})


class Maps(SimpleTestCase):
    def test_maps(self):
        config = sv.validate_config(ALL)
        passwords = sv.resolve_passwords(config, {'global': SECRET, 'domain:shop.example.com': DOMAIN_SECRET,
                                                  'domain:blog.example.org': 'b'}, {})
        maps = sv.render_maps(config, passwords)
        sasl = sv.parse_sasl(maps[sv.SASL_MAP])
        self.assertEqual(sasl, {'[smtp.relay.example]:587': ('srv@relay', SECRET),
                                '@shop.example.com': ('shop', DOMAIN_SECRET), '@blog.example.org': ('blogger', 'b')})
        self.assertIn('@shop.example.com [smtp.shop-relay.example]:587\n', maps[sv.SENDER_MAP])
        self.assertIn('@blog.example.org [smtp.relay.example]:587\n', maps[sv.SENDER_MAP])
        self.assertIn('[smtp.relay.example]:587 encrypt\n', maps[sv.TLS_MAP])
        self.assertIn('[smtp.shop-relay.example]:587 encrypt\n', maps[sv.TLS_MAP])
        none = sv.validate_config({'scope': 'all', 'relay': {'host': '10.0.0.5', 'port': 25, 'tls': 'none'}})
        self.assertIn('[10.0.0.5]:25 none\n', sv.render_maps(none, {})[sv.TLS_MAP])
        self.assertTrue(any('clear text' in w for w in sv.warnings(none)))

    def test_blank_password_keeps_stored_one(self):
        config = sv.validate_config({'scope': 'all', 'relay': {'host': 'smtp.relay.example', 'port': 587, 'username': 'u'}})
        stored = {'[smtp.relay.example]:587': ('u', 'old')}
        self.assertEqual(sv.resolve_passwords(config, {}, stored), {'[smtp.relay.example]:587': ('u', 'old')})
        moved = sv.validate_config({'scope': 'all', 'relay': {'host': 'smtp.relay.example', 'port': 465,
                                                              'tls': 'implicit', 'username': 'u'}})
        self.assertEqual(sv.resolve_passwords(moved, {}, stored)['[smtp.relay.example]:465'][1], 'old')
        renamed = sv.validate_config({'scope': 'all', 'relay': {'host': 'smtp.relay.example', 'port': 587, 'username': 'v'}})
        with self.assertRaisesRegex(sv.RelayError, 'password'):
            sv.resolve_passwords(renamed, {}, stored)


class FakePostfix:
    """Stands in for postconf/postmap/postfix; records calls and can fail `postfix check`/`reload`."""

    def __init__(self, check=0, reload=0):
        self.calls, self.check, self.reload = [], check, reload

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        line = ' '.join(argv)
        if line == 'postconf -h default_database_type':
            return SimpleNamespace(returncode=0, stdout='hash\n')
        if argv[0] == 'postmap':
            with open(argv[1].split(':', 1)[1] + '.db', 'w') as handle:
                handle.write('db')
            return SimpleNamespace(returncode=0, stdout='')
        if line == 'postfix check':
            return SimpleNamespace(returncode=self.check, stdout='postfix: fatal: bad main.cf' if self.check else '')
        if line == 'postfix status':
            return SimpleNamespace(returncode=0, stdout='running')
        if line == 'postfix reload':
            code = self.reload if not any(c == ['postfix', 'reload'] for c in self.calls[:-1]) else 0
            return SimpleNamespace(returncode=code, stdout='reload failed' if code else '')
        if argv[:2] == ['postconf', '-h']:
            return SimpleNamespace(returncode=0, stdout='\n')
        return SimpleNamespace(returncode=0, stdout='')


class Sandbox(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        p = lambda name: os.path.join(self.root, name)  # noqa: E731
        self.main_cf = p('main.cf')
        with open(self.main_cf, 'w') as handle:
            handle.write(MAIN_CF)
        sasl, sender, tls = p('sasl_passwd'), p('indianscloud_sender_relay'), p('indianscloud_relay_tls')
        state = p('state')
        for patch in (mock.patch.object(sv, 'MAIN_CF', self.main_cf), mock.patch.object(sv, 'SASL_MAP', sasl),
                      mock.patch.object(sv, 'SENDER_MAP', sender), mock.patch.object(sv, 'TLS_MAP', tls),
                      mock.patch.object(sv, 'MAP_FILES', (sasl, sender, tls)),
                      mock.patch.object(actions, 'STATE_DIR', state),
                      mock.patch.object(actions, 'CONFIG_FILE', os.path.join(state, 'config.json')),
                      mock.patch.object(actions, 'BACKUP_DIR', os.path.join(state, 'backups')),
                      mock.patch.object(actions, '_sasl_plugin_present', return_value=True),
                      mock.patch.object(actions, 'MAIL_LOGS', (p('maillog'),))):
            patch.start()
            self.addCleanup(patch.stop)
        self.sasl = sasl

    def secrets(self):
        return {'global': SECRET, 'domain:shop.example.com': DOMAIN_SECRET, 'domain:blog.example.org': 'b'}


class Apply(Sandbox):
    def test_apply_writes_and_reloads(self):
        fake = FakePostfix()
        result = actions.apply(ALL, self.secrets(), confirm=True, runner=fake)
        self.assertTrue(result['applied'])
        self.assertIn(['postfix', 'check'], fake.calls)
        self.assertIn(['postfix', 'reload'], fake.calls)
        self.assertEqual(oct(os.stat(self.sasl).st_mode & 0o777), '0o600')
        self.assertEqual(oct(os.stat(self.sasl + '.db').st_mode & 0o777), '0o600')
        self.assertIn(sv.BEGIN, open(self.main_cf).read())
        self.assertTrue(os.path.isfile(os.path.join(result['backup'], 'manifest.json')))
        self.assertNotIn(SECRET, json.dumps(result))
        # a second save with blank passwords keeps them
        actions.apply(ALL, {}, runner=FakePostfix())
        self.assertEqual(sv.parse_sasl(open(self.sasl).read())['[smtp.relay.example]:587'][1], SECRET)

    def test_foreign_settings_need_confirmation(self):
        fake = FakePostfix()
        result = actions.apply(ALL, self.secrets(), runner=fake)
        self.assertIn('needs_confirm', result)
        self.assertEqual(open(self.main_cf).read(), MAIN_CF)
        self.assertNotIn(['postfix', 'check'], fake.calls)

    def test_rollback_when_postfix_check_fails(self):
        fake = FakePostfix(check=1)
        with self.assertRaisesRegex(sv.RelayError, 'postfix check failed'):
            actions.apply(ALL, self.secrets(), confirm=True, runner=fake)
        self.assertEqual(open(self.main_cf).read(), MAIN_CF)
        for path in sv.MAP_FILES:
            self.assertFalse(os.path.exists(path), path)
            self.assertFalse(os.path.exists(path + '.db'), path)
        self.assertNotIn(['postfix', 'reload'], fake.calls)
        self.assertFalse(os.path.exists(actions.CONFIG_FILE))

    def test_rollback_when_reload_fails(self):
        with open(self.sasl, 'w') as handle:
            handle.write('[old.example]:587 a:b\n')
        fake = FakePostfix(reload=1)
        with self.assertRaisesRegex(sv.RelayError, 'did not reload'):
            actions.apply(ALL, self.secrets(), confirm=True, runner=fake)
        self.assertEqual(open(self.main_cf).read(), MAIN_CF)
        self.assertEqual(open(self.sasl).read(), '[old.example]:587 a:b\n')
        self.assertEqual(fake.calls.count(['postfix', 'reload']), 2, 'reloaded again with the old settings')

    def test_disable_restores_direct_delivery(self):
        actions.apply(ALL, self.secrets(), confirm=True, runner=FakePostfix())
        result = actions.disable(runner=FakePostfix())
        text = open(self.main_cf).read()
        self.assertTrue(result['disabled'])
        self.assertNotIn(sv.BEGIN, text)
        self.assertNotIn('relayhost', text)
        self.assertIn(SECRET, open(self.sasl).read(), 'kept for re-enabling unless asked to forget')
        actions.disable(forget=True, runner=FakePostfix())
        self.assertNotIn(SECRET, open(self.sasl).read())
        self.assertIsNone(actions.load_config()['config'])


class NeverReturnsPassword(Sandbox):
    def test_overview(self):
        actions.apply(ALL, self.secrets(), confirm=True, runner=FakePostfix())
        with open(os.path.join(self.root, 'maillog'), 'w') as handle:
            handle.write('Nov 16 10:00:00 h postfix/smtp[1]: ABC: to=<a@b.c>, relay=smtp.relay.example[192.0.2.1]:587, '
                         'status=sent\nNov 16 10:00:01 h postfix/smtpd[2]: connect from x\n')
        popen = mock.Mock(return_value=SimpleNamespace(stdout=iter(['{"queue_name": "deferred", "recipients": '
                                                                    '[{"delay_reason": "connect timed out"}]}']),
                                                       kill=lambda: None, wait=lambda: 0))
        result = actions.overview(runner=FakePostfix(), popen=popen)
        dumped = json.dumps(result)
        for secret in (SECRET, DOMAIN_SECRET):
            self.assertNotIn(secret, dumped)
        self.assertTrue(result['config']['relay']['has_password'])
        self.assertNotIn('password', result['config']['relay'])
        self.assertEqual(result['queue']['by_queue'], {'deferred': 1})
        self.assertEqual(len(result['log']), 1)

    def test_view_sends_passwords_privately(self):
        with mock.patch('universalAddons.privileged.call_private', return_value={'applied': True}) as private, \
                mock.patch('universalAddons.privileged.call') as public:
            status, body, _ = helpers.post(views.save, {'config': ALL, 'secrets': self.secrets()}, admin=True)
        self.assertEqual(status, 200)
        public.assert_not_called()
        self.assertEqual(private.call_args.kwargs['secrets']['global'], SECRET)
        self.assertNotIn(SECRET, json.dumps(body))

    def test_spool_keeps_arguments_off_the_command_line(self):
        from universalAddons import privileged
        spool = tempfile.mkdtemp(dir=self.root)
        command = privileged.build_command('smtprelay', 'apply', {'secrets': {'global': SECRET}}, spool, force_spool=True)
        self.assertIn('--spool', command)
        self.assertNotIn(privileged.encode_args({'secrets': {'global': SECRET}}), command)


class FakeRelay(threading.Thread):
    """A one-connection SMTP server on localhost that accepts AUTH PLAIN."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def run(self):
        conn, _ = self.sock.accept()
        f = conn.makefile('rb')
        conn.sendall(b'220 fake ESMTP\r\n')
        while True:
            line = f.readline().decode().strip()
            if not line:
                break
            verb = line.split()[0].upper()
            if verb == 'EHLO':
                conn.sendall(b'250-fake\r\n250 AUTH PLAIN LOGIN\r\n')
            elif verb == 'AUTH':
                conn.sendall(b'235 ok\r\n')
            elif verb in ('MAIL', 'RCPT'):
                conn.sendall(b'250 ok\r\n')
            elif verb == 'DATA':
                conn.sendall(b'354 go\r\n')
                while f.readline() not in (b'.\r\n', b''):
                    pass
                conn.sendall(b'250 queued as X\r\n')
            elif verb == 'QUIT':
                conn.sendall(b'221 bye\r\n')
                break
        conn.close()
        self.sock.close()


class TestMessage(Sandbox):
    def test_transcript_masks_login(self):
        config = sv.validate_config({'scope': 'all', 'relay': {'host': 'smtp.relay.example', 'port': 25, 'tls': 'none',
                                                              'username': 'srv'}})
        actions.apply(config, {'global': SECRET}, confirm=True, runner=FakePostfix())
        server = FakeRelay()
        server.start()

        def factory(relay, context, recorder):
            return actions._transcript_class(smtplib.SMTP, recorder)('127.0.0.1', server.port, timeout=5)

        result = actions.send_test('admin@example.com', smtp_factory=factory)
        server.join(5)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['authenticated'])
        text = '\n'.join(result['transcript'])
        self.assertIn('C AUTH PLAIN ****', text)
        self.assertIn('S 235 ok', text)
        self.assertIn('<message body,', text)
        self.assertNotIn(SECRET, text)
        self.assertNotIn(base64.b64encode(('\0srv\0' + SECRET).encode()).decode(), text)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_mask_login_exchange(self):
        lines = [('C', 'AUTH LOGIN'), ('S', '334 VXNlcm5hbWU6'), ('C', 'dXNlcg=='), ('S', '334 UGFzc3dvcmQ6'),
                 ('C', 'c2VjcmV0'), ('S', '235 ok'), ('C', 'MAIL FROM:<a@b.c>')]
        masked = sv.mask_transcript(lines)
        self.assertEqual([t for d, t in masked if d == 'C'], ['AUTH LOGIN', '****', '****', 'MAIL FROM:<a@b.c>'])


class Views(SimpleTestCase):
    def test_admin_only(self):
        for view, body in ((views.overview, {}), (views.save, {'config': ALL}), (views.disable, {'confirm': True}),
                           (views.test, {'test': {'to': 'a@example.com'}})):
            with mock.patch('universalAddons.privileged.call') as call, \
                    mock.patch('universalAddons.privileged.call_private') as private:
                status, _, _ = helpers.post(view, body, admin=False)
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()
            private.assert_not_called()
        status, _ = helpers.page(views.page, admin=False)
        self.assertEqual(status, 403)
        status, values = helpers.page(views.page, admin=True)
        self.assertEqual((status, values['_template']), (200, 'universalAddons/smtprelay.html'))

    def test_validation(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.assertEqual(helpers.post(views.test, {'test': {'to': 'not-an-address'}}, admin=True)[0], 400)
            self.assertEqual(helpers.post(views.disable, {}, admin=True)[0], 400)
            self.assertEqual(helpers.post(views.save, {'config': {'scope': 'all'}}, admin=True)[0], 400)
            self.assertEqual(helpers.post(views.save, {'config': ALL, 'secrets': {'global': 'a\nb'}}, admin=True)[0], 400)
            call.assert_not_called()
            helpers.post(views.test, {'test': {'to': 'a@example.com', 'target': 'domain:Shop.Example.com'}}, admin=True)
        call.assert_called_once_with('smtprelay', 'test', to='a@example.com', target='domain:shop.example.com', sender='')


class PageRenders(SimpleTestCase):
    def test_page(self):
        request = RequestFactory().get('/addons/smtp-relay/')
        request.session = {}
        html = render_to_string('universalAddons/smtprelay.html', {'request': request, 'admin': 1})
        self.assertIn('ua-wrap', html)
        self.assertIn('data-base="/addons/smtp-relay/"', html)
        self.assertIn('smtprelay.js', html)
        self.assertIn('SMTP Relay - IndiansCloud', html)
        source = os.path.join(os.path.dirname(__file__), '..', 'templates', 'universalAddons', 'smtprelay.html')
        self.assertNotIn('cyberpersons', open(source).read().lower())


class EmailDeliveryRedirect(SimpleTestCase):
    def get(self, admin):
        from emailDelivery import views as ed
        request = RequestFactory().get('/emailDelivery/')
        request.session = {'userID': 7}
        with mock.patch('plogical.acl.ACLManager.loadedACL', return_value={'admin': 1 if admin else 0}), \
                mock.patch.object(ed.EmailDeliveryManager, 'home', return_value='vendor page') as home:
            return ed.index(request), home

    def test_admin_goes_to_smtp_relay(self):
        response, home = self.get(admin=True)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/addons/smtp-relay/')
        home.assert_not_called()

    def test_others_keep_the_old_refusal(self):
        response, home = self.get(admin=False)
        self.assertEqual(response, 'vendor page')

    def test_menu_no_longer_links_email_delivery(self):
        with open(os.path.join(os.path.dirname(__file__), '..', '..', 'baseTemplate', 'templates', 'baseTemplate',
                               'index.html')) as handle:
            text = handle.read()
        self.assertNotIn('emailDeliveryHome', text)
        self.assertIn('ua-smtprelay', text)


class VendorPagesReplaced(SimpleTestCase):
    """Backup plans and the MailTester link lead to the panel's own add-ons."""

    def test_one_click_backups_redirects_to_backup_v2(self):
        from backup.backupManager import BackupManager
        request = RequestFactory().get('/backup/OneClickBackups?status=success&planName=x')
        request.session = {'userID': 7}
        with mock.patch('requests.get') as get, mock.patch('requests.post') as post, \
                mock.patch('universalAddons.registry.disabled_features', return_value=set()):
            response = BackupManager().OneClickBackups(request, 7)
        self.assertEqual((response.status_code, response['Location']), (302, '/addons/backup/'))
        get.assert_not_called()
        post.assert_not_called()
        with mock.patch('universalAddons.registry.disabled_features', return_value={'backupv2'}):
            self.assertEqual(BackupManager().OneClickBackups(request, 7)['Location'], '/backup/backupDestinations')

    def test_no_purchase_calls_left_in_backup_js(self):
        path = os.path.join(os.path.dirname(__file__), '..', '..', 'backup', 'static', 'backup', 'backup.js')
        code = '\n'.join(l for l in open(path).read().splitlines() if not l.lstrip().startswith('//'))
        self.assertNotIn('platform.cyberpersons.com/Billing', code)

    def test_mail_tester_link(self):
        from mailServer.mailserverManager import MailServerManager
        with mock.patch('universalAddons.registry.disabled_features', return_value=set()), \
                mock.patch('universalAddons.access.load_policy', return_value={'email_debug_for_users': False}):
            self.assertEqual(MailServerManager.emailTesterURL({'admin': 1}), '/addons/email-debugger/')
            self.assertIsNone(MailServerManager.emailTesterURL({'admin': 0}))
        with mock.patch('universalAddons.registry.disabled_features', return_value={'emaildebug'}):
            self.assertIsNone(MailServerManager.emailTesterURL({'admin': 1}))
        path = os.path.join(os.path.dirname(__file__), '..', '..', 'mailServer', 'templates', 'mailServer',
                            'createEmailAccount.html')
        self.assertNotIn('MailTester', open(path).read())
