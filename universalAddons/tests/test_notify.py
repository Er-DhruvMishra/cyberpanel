"""Notification centre: channel secrecy, HMAC signing, de-duplication and rate limits, routing of the
existing backup/SSL e-mails, new-IP sign-ins, server checks, endpoints and the page."""
import hashlib
import hmac
import json
import os
import stat
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from universalAddons.notify import actions, service, views
from universalAddons.tests import helpers

TOKEN = '123456789:AAFakeTelegramTokenForTests_abcdefghij'
SLACK = 'https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX'


class Store(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        patcher = mock.patch.object(service, 'NOTIFY_DIR', os.path.join(self.dir, 'notify'))
        patcher.start()
        self.addCleanup(patcher.stop)


class ChannelSecrecy(Store):
    def test_secrets_are_stored_privately_and_never_returned(self):
        service.save_channel(7, {'type': 'telegram', 'name': 'Phone', 'token': TOKEN, 'chat_id': '-100123'})
        service.save_channel(7, {'type': 'slack', 'url': SLACK})
        view = json.dumps(service.public_view(7))
        self.assertNotIn(TOKEN, view)
        self.assertNotIn(SLACK, view)
        self.assertIn('"secret_set": true', view)
        self.assertIn('-100123', view)   # public settings are shown
        path = service.account_path(7)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
        self.assertIn(TOKEN, open(path).read())

    def test_empty_secret_keeps_the_saved_one_and_type_cannot_change(self):
        channel = service.save_channel(7, {'type': 'telegram', 'token': TOKEN, 'chat_id': '42'})
        service.save_channel(7, {'id': channel['id'], 'type': 'telegram', 'token': '', 'chat_id': '43', 'name': 'New'})
        stored = service.load_account(7)['channels'][0]
        self.assertEqual((stored['secret']['token'], stored['public']['chat_id'], stored['name']), (TOKEN, '43', 'New'))
        with self.assertRaises(service.NotifyError):
            service.save_channel(7, {'id': channel['id'], 'type': 'slack', 'url': SLACK})

    def test_validation(self):
        for spec in ({'type': 'email', 'address': 'nope'}, {'type': 'telegram', 'token': 'x', 'chat_id': '1'},
                     {'type': 'slack', 'url': 'https://evil.example/services/x'},
                     {'type': 'discord', 'url': 'https://discord.com/api/other'},
                     {'type': 'webhook', 'url': 'ftp://x', 'signing_secret': 'a' * 20},
                     {'type': 'webhook', 'url': 'https://example.com/h', 'signing_secret': 'short'},
                     {'type': 'sms'}):
            with self.assertRaises(service.NotifyError, msg=spec):
                service.validate_channel(spec)

    def test_accounts_are_separate(self):
        service.save_channel(7, {'type': 'email', 'address': 'a@example.com'})
        self.assertEqual(service.public_view(8)['channels'], [])
        channel_id = service.load_account(7)['channels'][0]['id']
        with self.assertRaises(service.NotifyError):
            service.delete_channel(8, channel_id)


class Signing(Store):
    def test_hmac_sha256_signature(self):
        expected = hmac.new(b'0123456789abcdefXYZ', b'1700000000.{"a":1}', hashlib.sha256).hexdigest()
        self.assertEqual(service.sign('0123456789abcdefXYZ', 1700000000, '{"a":1}'), 'sha256=' + expected)
        self.assertTrue(service.verify('0123456789abcdefXYZ', 1700000000, b'{"a":1}', 'sha256=' + expected))
        self.assertFalse(service.verify('0123456789abcdefXYZ', 1700000001, b'{"a":1}', 'sha256=' + expected))

    def test_webhook_delivery_is_signed_and_guarded(self):
        channel = service.validate_channel({'type': 'webhook', 'url': 'https://hooks.example.com/in',
                                            'signing_secret': 's3cret-s3cret-s3cret'})
        self.assertFalse(channel['allow_local'])
        seen = {}

        def http(url, **kwargs):
            seen.update(kwargs, url=url)
            return {'status': 204}
        message = service._message('uptime', 'Down', 'body', 'error', 'down', 7)
        service.deliver(channel, message, http=http, now=1700000000)
        headers, body = seen['headers'], seen['body']
        self.assertEqual(headers[service.TIMESTAMP_HEADER], '1700000000')
        self.assertTrue(service.verify('s3cret-s3cret-s3cret', 1700000000, body, headers[service.SIGNATURE_HEADER]))
        self.assertEqual(json.loads(body)['event'], 'uptime')
        self.assertFalse(seen['allow_local'])
        self.assertTrue(service.validate_channel({'type': 'webhook', 'url': 'http://127.0.0.1:9/x',
                                                  'signing_secret': 'x' * 16}, is_admin=True)['allow_local'])


class DedupAndRateLimit(Store):
    def setUp(self):
        super().setUp()
        self.sent = []
        self.kw = {'deliverer': lambda channel, message: self.sent.append((channel['type'], message['title'])),
                   'email_lookup': lambda pk: 'owner@example.com'}

    def test_default_channel_is_the_account_email(self):
        result = service.send(7, 'uptime', 'site down', 'b', 'error', now=1000, **self.kw)
        self.assertEqual((result['sent'], self.sent), (1, [('email', 'site down')]))

    def test_same_state_once_per_30_minutes_and_state_changes_at_once(self):
        send = lambda state, now, **kw: service.send(7, 'uptime', 'x', 'b', key='k', state=state, now=now, **dict(self.kw, **kw))
        self.assertEqual(send('down', 1000)['sent'], 1)
        self.assertEqual(send('down', 1000 + 600)['skipped'], 'duplicate')
        self.assertEqual(send('up', 1000 + 700)['sent'], 1)            # state changed: at once
        self.assertEqual(send('down', 1000 + 800)['sent'], 1)
        self.assertEqual(send('down', 1000 + 800 + 1801)['sent'], 1)   # 30 minutes later
        self.assertEqual(send('down', 5000, window=86400)['skipped'], 'duplicate')

    def test_recovery_needs_an_earlier_alert(self):
        self.assertEqual(service.send(7, 'uptime', 'x', 'b', key='k', state='up', recovery=True, now=10, **self.kw)['skipped'],
                         'no change')
        service.send(7, 'uptime', 'x', 'b', key='k', state='down', now=20, **self.kw)
        self.assertEqual(service.send(7, 'uptime', 'x', 'b', key='k', state='up', recovery=True, now=30, **self.kw)['sent'], 1)

    def test_rate_limit_per_hour(self):
        for index in range(service.RATE_PER_HOUR):
            self.assertEqual(service.send(7, 'uptime', 't%d' % index, 'b', now=1000 + index, **self.kw)['sent'], 1)
        self.assertEqual(service.send(7, 'uptime', 'one more', 'b', now=2000, **self.kw)['skipped'], 'rate limit')
        self.assertEqual(service.send(7, 'uptime', 'later', 'b', now=1000 + 3700, **self.kw)['sent'], 1)
        self.assertEqual(service.send(8, 'uptime', 'other account', 'b', now=2000, **self.kw)['sent'], 1)

    def test_unsubscribed_events_and_failing_channels(self):
        service.save_preferences(7, {'uptime': False})
        self.assertEqual(service.send(7, 'uptime', 'x', 'b', **self.kw)['skipped'], 'unsubscribed')
        with self.assertRaises(service.NotifyError):
            service.save_preferences(7, {'server_disk': False})   # administrator events need is_admin
        service.save_channel(8, {'type': 'email', 'address': 'a@example.com'})
        service.save_channel(8, {'type': 'slack', 'url': SLACK})

        def deliverer(channel, message):
            if channel['type'] == 'slack':
                raise OSError('boom')
        result = service.send(8, 'backup_failure', 'x', 'b', deliverer=deliverer, email_lookup=lambda pk: '')
        self.assertEqual(result['sent'], 1)
        self.assertIn('boom', result['errors'][0])
        self.assertIn('sent to 1 channel', service.public_view(8)['log'][0]['result'])

    def test_test_message_is_rate_limited(self):
        channel = service.save_channel(7, {'type': 'email', 'address': 'a@example.com'})
        delivered = []
        service.test_channel(7, channel['id'], now=100, deliverer=lambda c, m: delivered.append(m))
        with self.assertRaises(service.NotifyError):
            service.test_channel(7, channel['id'], now=105, deliverer=lambda c, m: delivered.append(m))
        self.assertEqual(len(delivered), 1)
        self.assertIn('IndiansCloud', delivered[0]['body'])


class ExistingEmails(Store):
    def test_admins_without_settings_get_the_old_email(self):
        calls = []
        service.notify_admins('backup_failure', 't', 'b', fallback=calls.append,
                              admins=[(1, 'a@example.com'), (2, '')], sender=mock.Mock())
        self.assertEqual(calls, [['a@example.com']])
        calls.clear()
        service.notify_admins('backup_failure', 't', 'b', fallback=calls.append, admins=[(2, '')], sender=mock.Mock())
        self.assertEqual(calls, [['root']])

    def test_admins_with_settings_go_through_their_channels(self):
        service.save_preferences(1, {'uptime': True})
        calls, sender = [], mock.Mock(return_value={'sent': 1})
        service.notify_admins('ssl_expiry', 't', 'b', fallback=calls.append,
                              admins=[(1, 'a@example.com'), (3, 'c@example.com')], sender=sender)
        self.assertEqual(sender.call_args[0][:2], (1, 'ssl_expiry'))
        self.assertEqual(calls, [['c@example.com']])
        calls.clear()
        service.notify_admins('ssl_expiry', 't', 'b', fallback=calls.append, admins=[(1, 'a@example.com')], sender=sender)
        self.assertEqual(calls, [])

    def test_backupv2_failure_mail_unchanged_by_default(self):
        from universalAddons.backupv2 import actions as backup
        with mock.patch.object(backup, '_django'), mock.patch.object(backup, '_hostname', return_value='h.example'), \
                mock.patch.object(service, 'admin_accounts', return_value=[(1, 'a@example.com')]), \
                mock.patch('universalAddons.backupv2.actions.subprocess.run') as run:
            backup._notify_failure('nightly', ['site.com: failed'])
        argv, kwargs = run.call_args
        self.assertEqual(argv[0], ['sendmail', '--', 'a@example.com'])
        self.assertIn('Subject: [IndiansCloud] Backup policy nightly had errors on h.example', kwargs['input'])


class NewIP(Store):
    def test_first_sign_in_is_quiet_then_new_addresses_alert(self):
        self.assertFalse(service.login_seen(7, '203.0.113.5'))
        self.assertFalse(service.login_seen(7, '203.0.113.5'))
        self.assertTrue(service.login_seen(7, '198.51.100.9'))
        self.assertFalse(service.login_seen(7, 'not an ip'))
        self.assertTrue(service.login_seen(7, '2001:db8::5'))
        self.assertFalse(service.login_seen(7, '2001:db8::6'))   # same /64
        sent = []
        self.assertEqual(service.flush_outbox(lambda *a, **k: sent.append(a)), 2)  # 198.51.100.9 and the v6 /64
        self.assertEqual(sent[0][1], 'login_new_ip')
        self.assertIn('198.51.100.9', sent[0][2])
        self.assertEqual(service.flush_outbox(lambda *a, **k: sent.append(a)), 0)


class ServerChecks(Store):
    def setUp(self):
        super().setUp()
        state = mock.patch.object(actions, 'STATE_FILE', os.path.join(self.dir, 'server.json'))
        state.start()
        self.addCleanup(state.stop)

    def test_nobody_opted_in_means_no_work(self):
        self.assertFalse(actions.server_check(measure={'disks': [('/', 99)], 'swap': 99, 'down': []})['checked'])

    def test_alerts_and_recovery(self):
        service.save_preferences(1, {}, {'disk': 90}, is_admin=True)
        sender = mock.Mock(return_value={'sent': 1})
        with mock.patch.object(actions, 'quota_check', return_value=0):
            actions.server_check(measure={'disks': [('/', 95), ('/home', 40)], 'swap': 10, 'down': ['Postfix (postfix)']},
                                 admins=[1, 2], sender=sender)
        calls = {c[1]['key']: c for c in sender.call_args_list}
        self.assertEqual(set(c[0][0] for c in sender.call_args_list), {1})       # only the opted-in admin
        self.assertEqual(calls['server:disk:/'][0][1], 'server_disk')
        self.assertEqual(calls['server:disk:/'][1]['state'], 'high')
        self.assertTrue(calls['server:disk:/home'][1]['recovery'])
        self.assertIn('Postfix', calls['server:services'][0][2])
        self.assertEqual(calls['server:services'][0][1], 'server_service')

    def test_measurements(self):
        meminfo = os.path.join(self.dir, 'meminfo')
        with open(meminfo, 'w') as handle:
            handle.write('MemTotal: 100 kB\nSwapTotal:  1000 kB\nSwapFree:  250 kB\n')
        self.assertEqual(actions.swap_percent(meminfo), 75)
        units = actions.parse_show('Id=postfix.service\nLoadState=loaded\nUnitFileState=enabled\nActiveState=failed\n\n'
                                   'Id=pdns.service\nLoadState=not-found\nUnitFileState=\nActiveState=inactive\n')
        self.assertEqual(units['postfix']['ActiveState'], 'failed')
        run = mock.Mock(return_value=mock.Mock(stdout='Id=postfix.service\nLoadState=loaded\nUnitFileState=enabled\n'
                                                      'ActiveState=failed\n'))
        self.assertEqual(actions.down_services(run), ['Postfix (postfix)'])

    def test_quota(self):
        sender = mock.Mock(return_value={'sent': 1})
        actions.quota_check({7}, sender, rows=[(7, 'a.com', 950, 1000), (8, 'b.com', 990, 1000)])
        self.assertEqual(sender.call_count, 1)
        self.assertEqual(sender.call_args[0][:2], (7, 'disk_quota'))


class Endpoints(Store):
    def test_overview_never_returns_secrets(self):
        status, body, _ = helpers.post(views.channel_save, {'channel': {'type': 'slack', 'url': SLACK}})
        self.assertEqual(status, 200, body)
        self.assertNotIn(SLACK, json.dumps(body))
        status, body, _ = helpers.post(views.overview, {})
        self.assertEqual(body['result']['channels'][0]['secret_set'], True)
        self.assertNotIn(SLACK, json.dumps(body))
        self.assertNotIn('server_disk', json.dumps(body))   # administrator events are not offered to users

    def test_switch_off_refuses_users(self):
        status, _, _ = helpers.post(views.overview, {}, policy={'notify_for_users': False})
        self.assertEqual(status, 403)
        status, body, _ = helpers.post(views.overview, {}, admin=True, policy={'notify_for_users': False})
        self.assertEqual(status, 200)
        self.assertIn('server_disk', json.dumps(body))

    def test_bad_channel_is_400(self):
        status, body, _ = helpers.post(views.channel_save, {'channel': {'type': 'email', 'address': 'x'}})
        self.assertEqual(status, 400)

    def test_page_renders(self):
        from django.template.loader import render_to_string
        from django.test import RequestFactory
        request = RequestFactory().get('/addons/notifications/')
        request.session = {}
        html = render_to_string('universalAddons/notify.html', {'request': request, 'is_admin': True,
                                                                'panel_brand': 'IndiansCloud'})
        self.assertIn('ua-notify', html)
        self.assertIn('/addons/notifications/', html)
        status, values = helpers.page(views.page)
        self.assertEqual((status, values['_template']), (200, 'universalAddons/notify.html'))
