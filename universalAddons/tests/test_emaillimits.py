import json
import os
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import include, path

from universalAddons import access
from universalAddons.emaillimits import actions, service as svc, views

# A URLconf with the panel's URLs plus this module, until it is registered in universalAddons/urls.py.
urlpatterns = [path('addons/email-limits/', include('universalAddons.emaillimits.urls')),
               path('', include('CyberCP.urls'))]


class Validation(unittest.TestCase):
    def test_domains(self):
        self.assertEqual(svc.clean_domain('Example.COM'), 'example.com')
        for bad in ('', None, 'localhost', '-a.com', 'a..b.com', 'a.com;rm', 'a.com/x', 'x' * 60 + '.com', 7, 'a b.com', ' a.com', 'a.com\n'):
            with self.assertRaises(svc.LimitError, msg=bad):
                svc.clean_domain(bad)

    def test_emails(self):
        self.assertEqual(svc.clean_email('Info.Sales+x@Example.com'), 'Info.Sales+x@example.com')
        for bad in ('info', 'a@b@c.com', '.a@b.com', 'a..b@c.com', 'a b@c.com', "a'@c.com", 'a@c.com\n', None, 'a;b@c.com',
                    'a' * 70 + '@c.com', '@c.com'):
            with self.assertRaises(svc.LimitError, msg=bad):
                svc.clean_email(bad)

    def test_limits(self):
        self.assertEqual(svc.clean_limit(0, 'x'), 0)
        self.assertEqual(svc.clean_limit('250', 'x'), 250)
        self.assertEqual(svc.clean_limit(100.0, 'x'), 100)
        for bad in (True, False, -1, 1.5, '1e3', '', None, [], svc.MAX_LIMIT + 1, '12;3'):
            with self.assertRaises(svc.LimitError, msg=bad):
                svc.clean_limit(bad, 'x')

    def test_status_must_be_boolean(self):
        self.assertEqual((svc.clean_status(True), svc.clean_status(False)), (1, 0))
        for bad in (1, 0, 'true', None):
            with self.assertRaises(svc.LimitError):
                svc.clean_status(bad)

    def test_hourly_not_above_monthly(self):
        svc.check_mailbox_limits(100, 100)
        with self.assertRaisesRegex(svc.LimitError, 'hourly'):
            svc.check_mailbox_limits(10, 11)

    def test_site_owner_rules(self):
        svc.mailbox_rule(True, 1, 1, 0, 10 ** 6, 10)  # administrators are not restricted
        svc.mailbox_rule(False, 1, 0, 1, 10, 10)
        svc.mailbox_rule(False, 0, 1, 0, 999, 10)  # domain limit off: nothing is enforced anyway
        with self.assertRaisesRegex(PermissionError, 'switch off'):
            svc.mailbox_rule(False, 1, 1, 0, 10, 10)
        with self.assertRaisesRegex(PermissionError, 'exceed'):
            svc.mailbox_rule(False, 1, 1, 1, 11, 10)


class CacheCommands(unittest.TestCase):
    def test_commands_match_cache_manager(self):
        cases = [
            (['domain_status', 'example.com', 1], 'cyberpanelCleaner purgeLimitDomain example.com 1'),
            (['domain_limit', 'example.com', 5000], 'cyberpanelCleaner updateDomainLimit example.com 5000'),
            (['mailbox_status', 'a@example.com', 0], 'cyberpanelCleaner purgeLimit a@example.com 0'),
            (['mailbox_limits', 'a@example.com', 300, 20], 'cyberpanelCleaner purgeLimitEmail a@example.com 300 20'),
            (['flush'], 'cyberpanelCleaner refreshCounters'),
        ]
        for command, text in cases:
            self.assertEqual(svc.cache_command(command), text)

    def test_rejects_anything_else(self):
        for bad in (['domain_status', 'example.com', 2], ['domain_status', 'example.com', True],
                    ['domain_limit', 'a.com x', 5], ['mailbox_limits', 'a@b.com', 1], ['hourlyCleanup'],
                    ['mailbox_status', 'a@b.com 1\nx', 1], 'domain_status', [], None, ['flush', 1]):
            with self.assertRaises(svc.LimitError, msg=bad):
                svc.cache_command(bad)

    def test_only_changed_fields_are_sent(self):
        self.assertEqual(svc.domain_commands('a.com', {'status': 1, 'monthly': 10}, {'status': 1, 'monthly': 10}), [])
        self.assertEqual(svc.domain_commands('a.com', {}, {'status': 1, 'monthly': 10}),
                         [['domain_status', 'a.com', 1], ['domain_limit', 'a.com', 10]])
        self.assertEqual(svc.mailbox_commands('x@a.com', {'status': 1, 'monthly': 5, 'hourly': 2},
                                              {'status': 1, 'monthly': 5, 'hourly': 3}),
                         [['mailbox_limits', 'x@a.com', 5, 3]])


LIVE_CRON = ('0 * * * * /usr/local/CyberCP/bin/python /usr/local/CyberCP/postfixSenderPolicy/client.py hourlyCleanup >/dev/null 2>&1\n'
             '0 0 1 * * /usr/local/CyberCP/bin/python /usr/local/CyberCP/postfixSenderPolicy/client.py monthlyCleanup >/dev/null 2>&1\n')


class Health(unittest.TestCase):
    def test_cron_detection_and_idempotent_repair(self):
        self.assertEqual(svc.cron_present(LIVE_CRON), {'hourlyCleanup': True, 'monthlyCleanup': True})
        self.assertEqual(svc.cron_repaired(LIVE_CRON), (LIVE_CRON, []))
        commented = '# ' + LIVE_CRON.splitlines()[0] + '\n*/5 * * * * other'
        text, added = svc.cron_repaired(commented)
        self.assertEqual(len(added), 2)
        self.assertTrue(text.startswith(commented + '\n'))
        self.assertEqual(svc.cron_present(text), {'hourlyCleanup': True, 'monthlyCleanup': True})
        self.assertEqual(svc.cron_repaired(text), (text, []))
        self.assertEqual(svc.cron_repaired('')[0].count('\n'), 2)

    def test_policy_hook_detection(self):
        live = {'smtpd_data_restrictions': 'check_policy_service unix:/var/log/policyServerSocket',
                'smtpd_recipient_restrictions': 'permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'}
        self.assertEqual(svc.policy_hooks(live), ['smtpd_data_restrictions'])
        self.assertEqual(svc.policy_hooks({'smtpd_data_restrictions': 'check_policy_service unix:/var/log/policyServerSocketX'}), [])
        self.assertEqual(svc.policy_hooks({'smtpd_recipient_restrictions': 'reject_unauth_destination,'
                                           'check_policy_service unix:/var/log/policyServerSocket, permit'}),
                         ['smtpd_recipient_restrictions'])

    def test_report(self):
        good = {'smtpd_data_restrictions': 'check_policy_service unix:/var/log/policyServerSocket'}
        rows = svc.health_report('active', True, good, LIVE_CRON, False)
        self.assertEqual({r['status'] for r in rows}, {'pass'})
        rows = svc.health_report('inactive', False, {}, '', True)
        self.assertEqual([r['status'] for r in rows], ['fail', 'fail', 'fail', 'fail', 'fail', 'info'])
        self.assertTrue(all(set(r) == {'status', 'title', 'detail', 'fix'} for r in rows))


class FakeCpecs:
    """Behaves like cpecs: on each connection, read+delete the purge file, then answer the request."""

    def __init__(self, root, consume=True):
        self.purge = os.path.join(root, 'purgeCache')
        self.sock_path = os.path.join(root, 's')
        self.seen, self.consume = [], consume
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.sock_path)
        self.server.listen(5)
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            data = conn.recv(64)
            if self.consume and os.path.exists(self.purge):
                with open(self.purge) as handle:
                    self.seen.append(handle.read())
                os.remove(self.purge)
            self.seen.append(data.decode())
            conn.sendall(b'action=dunno\n\n')
            conn.close()

    def client(self):
        return actions.Cpecs(purge_file=self.purge, socket_path=self.sock_path, wait=0.5, settle=0)


class Delivery(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def test_commands_are_delivered_one_by_one(self):
        fake = FakeCpecs(self.root)
        result = actions.sync([['domain_status', 'a.com', 1], ['mailbox_limits', 'x@a.com', 10, 2]],
                              cpecs=fake.client(), state=lambda: 'active')
        self.assertEqual(result, {'delivered': 2})
        commands = [s for s in fake.seen if s.startswith('cyberpanelCleaner')]
        self.assertEqual(commands, ['cyberpanelCleaner purgeLimitDomain a.com 1', 'cyberpanelCleaner purgeLimitEmail x@a.com 10 2'])
        self.assertIn('sasl_username=\n', fake.seen[-1])  # the wake-up request never names a sender
        self.assertFalse(os.path.exists(fake.purge))

    def test_pending_command_is_delivered_first_not_overwritten(self):
        fake = FakeCpecs(self.root)
        with open(fake.purge, 'w') as handle:
            handle.write('cyberpanelCleaner hourlyCleanup')
        fake.client().deliver('cyberpanelCleaner purgeLimit x@a.com 1')
        commands = [s for s in fake.seen if s.startswith('cyberpanelCleaner')]
        self.assertEqual(commands, ['cyberpanelCleaner hourlyCleanup', 'cyberpanelCleaner purgeLimit x@a.com 1'])

    def test_unread_command_is_removed_and_reported(self):
        fake = FakeCpecs(self.root, consume=False)
        with self.assertRaisesRegex(svc.LimitError, 'only 0 of 1'):
            actions.sync([['domain_status', 'a.com', 1]], cpecs=fake.client(), state=lambda: 'active')
        self.assertFalse(os.path.exists(fake.purge))

    def test_symlink_is_never_followed(self):
        fake = FakeCpecs(self.root, consume=False)
        target = os.path.join(self.root, 'target')
        os.symlink(target, fake.purge)
        with self.assertRaises(svc.LimitError):
            fake.client().deliver('cyberpanelCleaner refreshCounters')
        self.assertFalse(os.path.exists(target))

    def test_nothing_delivered_when_cpecs_is_down_or_input_bad(self):
        client = mock.Mock()
        result = actions.sync([['domain_status', 'a.com', 1]], cpecs=client, state=lambda: 'inactive')
        self.assertEqual(result['delivered'], 0)
        with self.assertRaises(svc.LimitError):
            actions.sync([['domain_status', 'a.com', 1], ['evil']], cpecs=client, state=lambda: 'active')
        client.deliver.assert_not_called()
        self.assertEqual(actions.refresh(cpecs=client, state=lambda: 'failed')['flushed'], False)

    def test_runner_actions_take_no_injectable_arguments(self):
        with self.assertRaises(TypeError):
            actions.ACTIONS['set_policy'](enabled=True, path='/etc/passwd')
        with self.assertRaises(TypeError):
            actions.ACTIONS['sync'](commands=[], cpecs='x')


class Policy(unittest.TestCase):
    def test_set_policy_keeps_other_keys(self):
        path = os.path.join(tempfile.mkdtemp(), 'policy.json')
        with open(path, 'w') as handle:
            json.dump({'apps_for_users': True, 'max_apps_per_site': 5}, handle)
        actions.set_policy(True, path=path)
        with open(path) as handle:
            self.assertEqual(json.load(handle), {'apps_for_users': True, 'max_apps_per_site': 5, 'email_limits_for_users': True})
        with self.assertRaises(svc.LimitError):
            actions.set_policy('yes', path=path)


MAIL_DOMAIN = SimpleNamespace(domain='shop.example.com', domainOwner_id=1, childOwner_id=None,
                              domainOwner=SimpleNamespace(domain='shop.example.com'))


class AccessControl(SimpleTestCase):
    def post(self, view, body, admin=0, owns=True, policy=None, mail_domain=MAIL_DOMAIN):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 7}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('loginSystem.models.Administrator.objects.get', return_value=object()), \
                mock.patch('universalAddons.access.ACLManager.checkOwnership', return_value=1 if owns else 0) as own, \
                mock.patch('universalAddons.access.load_policy', return_value=dict(access.DEFAULT_POLICY, **(policy or {}))), \
                mock.patch('universalAddons.emaillimits.views.ACLManager.findAllSites', return_value=['shop.example.com']), \
                mock.patch.object(svc, 'get_mail_domain', return_value=mail_domain), \
                mock.patch.object(svc, 'overview', return_value=[]) as overview, \
                mock.patch.object(svc, 'detail', return_value={}), \
                mock.patch.object(svc, 'domain_emails', return_value=['a@shop.example.com', 'b@shop.example.com']), \
                mock.patch.object(svc, 'save_domain', return_value=[]) as save_domain, \
                mock.patch.object(svc, 'save_mailboxes', return_value=[['mailbox_status', 'a@shop.example.com', 1]]) as save, \
                mock.patch('universalAddons.privileged.call', return_value={'delivered': 1}) as call:
            response = view(request)
        self.calls = SimpleNamespace(own=own, overview=overview, save=save, save_domain=save_domain, call=call)
        return response.status_code, json.loads(response.content)

    USER = {'email_limits_for_users': True}
    MAILBOX = {'domain': 'shop.example.com', 'mailbox': 'a@shop.example.com', 'enabled': True, 'monthly': 100, 'hourly': 10}

    def test_users_blocked_until_admin_enables(self):
        for view in (views.overview, views.detail, views.save_mailbox, views.apply_all, views.refresh):
            status, body = self.post(view, self.MAILBOX)
            self.assertEqual(status, 403, view.__name__)
            self.calls.save.assert_not_called()
            self.calls.call.assert_not_called()

    def test_user_overview_is_limited_to_owned_sites(self):
        status, body = self.post(views.overview, {}, policy=self.USER)
        self.assertEqual(status, 200)
        self.calls.overview.assert_called_once_with(['shop.example.com'])
        self.post(views.overview, {}, admin=1)
        self.calls.overview.assert_called_once_with(None)

    def test_user_cannot_touch_a_foreign_or_unknown_domain(self):
        for view in (views.detail, views.save_mailbox, views.apply_all):
            status, body = self.post(view, self.MAILBOX, owns=False, policy=self.USER)
            self.assertEqual(status, 403, view.__name__)
            self.calls.save.assert_not_called()
            status, unknown = self.post(view, self.MAILBOX, policy=self.USER, mail_domain=None)
            self.assertEqual((status, unknown['error_message']), (403, body['error_message']), 'no existence oracle')

    def test_ownership_is_checked_on_the_owning_website(self):
        child = SimpleNamespace(domain='mail.child.com', domainOwner_id=None, childOwner_id=3,
                                childOwner=SimpleNamespace(domain='mail.child.com'))
        self.post(views.detail, {'domain': 'mail.child.com'}, policy=self.USER, mail_domain=child)
        self.assertEqual(self.calls.own.call_args[0][0], 'mail.child.com')

    def test_mailbox_must_belong_to_the_domain(self):
        status, body = self.post(views.save_mailbox, dict(self.MAILBOX, mailbox='a@other.com'), policy=self.USER)
        self.assertEqual(status, 400)
        self.calls.save.assert_not_called()

    def test_input_validation(self):
        for bad in ({'enabled': 1}, {'enabled': 'true'}, {'monthly': -1}, {'monthly': '10; rm'}, {'hourly': True},
                    {'monthly': 10 ** 9}, {'mailbox': 'a@shop.example.com\nx'}, {'domain': '../etc'}, {'mailbox': ['x']}):
            status, body = self.post(views.save_mailbox, dict(self.MAILBOX, **bad), admin=1)
            self.assertEqual(status, 400, bad)
            self.calls.save.assert_not_called()

    def test_save_mailbox_pushes_to_cpecs(self):
        status, body = self.post(views.save_mailbox, self.MAILBOX, policy=self.USER)
        self.assertEqual(status, 200)
        self.calls.save.assert_called_once_with(MAIL_DOMAIN, [('a@shop.example.com', 1, 100, 10)], False)
        self.calls.call.assert_called_once_with('emaillimits', 'sync', commands=[['mailbox_status', 'a@shop.example.com', 1]])
        self.assertEqual(body['result']['sync'], {'delivered': 1})

    def test_apply_all_covers_every_mailbox(self):
        status, body = self.post(views.apply_all, {'domain': 'shop.example.com', 'enabled': False, 'monthly': 50, 'hourly': 5},
                                 admin=1)
        self.assertEqual((status, body['result']['updated']), (200, 2))
        self.assertEqual(self.calls.save.call_args[0][1], [('a@shop.example.com', 0, 50, 5), ('b@shop.example.com', 0, 50, 5)])
        self.assertIs(self.calls.save.call_args[0][2], True)

    def test_failed_push_is_reported_not_hidden(self):
        with mock.patch('universalAddons.privileged.call', side_effect=RuntimeError('cpecs gone')):
            result = views._sync([['flush']])
        self.assertEqual(result, {'delivered': 0, 'error': 'cpecs gone'})
        self.assertEqual(views._sync([]), {'delivered': 0})

    def test_admin_only_endpoints(self):
        for view in (views.save_domain, views.health, views.repair_cron, views.policy):
            status, body = self.post(view, {'domain': 'shop.example.com', 'enabled': True, 'monthly': 10}, policy=self.USER)
            self.assertEqual(status, 403, view.__name__)
            self.calls.call.assert_not_called()
            self.calls.save_domain.assert_not_called()

    def test_save_domain_and_policy_as_admin(self):
        status, body = self.post(views.save_domain, {'domain': 'shop.example.com', 'enabled': True, 'monthly': 500}, admin=1)
        self.assertEqual(status, 200)
        self.calls.save_domain.assert_called_once_with(MAIL_DOMAIN, 1, 500)
        self.assertEqual(self.post(views.policy, {'enabled': 'yes'}, admin=1)[0], 400)
        self.post(views.policy, {'enabled': True}, admin=1)
        self.calls.call.assert_called_once_with('emaillimits', 'set_policy', enabled=True)

    def test_get_is_refused(self):
        request = RequestFactory().get('/x')
        request.session = {'userID': 7}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1}):
            self.assertEqual(views.overview(request).status_code, 405)


@override_settings(ROOT_URLCONF='universalAddons.tests.test_emaillimits')
class PageRenders(SimpleTestCase):
    def test_page_renders(self):
        request = RequestFactory().get('/addons/email-limits/')
        request.session = {}
        context = {'request': request, 'is_admin': True, 'enabled': True, 'for_users': True}
        html = render_to_string('universalAddons/emaillimits.html', context)
        for needle in ('ua-wrap', 'data-base="/addons/email-limits/"', 'el-health', 'id="el-policy" checked'):
            self.assertIn(needle, html)
        user = render_to_string('universalAddons/emaillimits.html', dict(context, is_admin=False))
        self.assertNotIn('el-health', user)
        disabled = render_to_string('universalAddons/emaillimits.html', dict(context, is_admin=False, enabled=False))
        self.assertIn('has not enabled email limits', disabled)


class Database(SimpleTestCase):
    """The ORM layer against real tables (the panel apps ship no migrations, so create just these)."""
    databases = {'default'}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from django.db import connection
        from loginSystem.models import ACL, Administrator
        from packages.models import Package
        from websiteFunctions.models import ChildDomains, Websites
        cls.models = svc._models()
        cls.tables = (ACL, Administrator, Package, Websites, ChildDomains) + cls.models
        with connection.schema_editor() as editor:
            for model in cls.tables:
                editor.create_model(model)

    @classmethod
    def tearDownClass(cls):
        from django.db import connection
        with connection.schema_editor() as editor:
            for model in reversed(cls.tables):
                editor.delete_model(model)
        super().tearDownClass()

    def setUp(self):
        Domains, EUsers, DomainLimits, EmailLimits = self.models
        from django.db import connection
        with connection.cursor() as cursor:  # raw: Django's cascade would visit tables these tests lack
            for model in reversed(self.tables):
                cursor.execute('DELETE FROM "%s"' % model._meta.db_table)
        from loginSystem.models import ACL, Administrator
        from packages.models import Package
        from websiteFunctions.models import ChildDomains, Websites
        acl = ACL.objects.create(id=1, name='user')
        admin = Administrator.objects.create(userName='u', password='x', firstName='u', lastName='u', email='u@x.com',
                                             type=3, owner=1, acl=acl)
        package = Package.objects.create(admin=admin, packageName='p', diskSpace=1, bandwidth=1)
        site = Websites.objects.create(admin=admin, package=package, domain='shop.example.com', adminEmail='u@x.com',
                                       phpSelection='8.1', ssl=0, externalApp='shop')
        child = ChildDomains.objects.create(master=site, domain='blog.shop.example.com', path='/x', phpSelection='8.1', ssl=0)
        self.domain = Domains.objects.create(domain='shop.example.com', domainOwner=site)
        self.child = Domains.objects.create(domain='blog.shop.example.com', childOwner=child)
        self.other = Domains.objects.create(domain='other.com')
        DomainLimits.objects.create(domain=self.domain, limitStatus=1, monthlyLimit=1000, monthlyUsed=7)
        for name in ('a', 'b'):
            user = EUsers.objects.create(email='%s@shop.example.com' % name, emailOwner=self.domain, password='x')
            EmailLimits.objects.create(email=user, limitStatus=1, monthlyLimits=100, hourlyLimit=10, monthlyUsed=3)
        EUsers.objects.create(email='new@shop.example.com', emailOwner=self.domain, password='x')
        EUsers.objects.create(email='x@other.com', emailOwner=self.other, password='x')

    def test_overview_and_detail(self):
        rows = {r['domain']: r for r in svc.overview()}
        self.assertEqual((rows['shop.example.com']['mailboxes'], rows['shop.example.com']['limited_mailboxes'],
                          rows['shop.example.com']['used'], rows['shop.example.com']['status']), (3, 2, 7, 1))
        self.assertTrue(rows['other.com']['missing'])
        self.assertEqual(rows['blog.shop.example.com']['site'], 'blog.shop.example.com')
        owned = [r['domain'] for r in svc.overview(['shop.example.com', 'blog.shop.example.com'])]
        self.assertEqual(owned, ['blog.shop.example.com', 'shop.example.com'])
        self.assertEqual(svc.overview([]), [])
        detail = svc.detail(self.domain)
        self.assertEqual([m['email'] for m in detail['mailboxes']],
                         ['a@shop.example.com', 'b@shop.example.com', 'new@shop.example.com'])
        self.assertTrue(detail['mailboxes'][2]['missing'])
        self.assertTrue(any('not limited at all' in w for w in detail['warnings']))

    def test_save_creates_missing_rows_and_returns_changes_only(self):
        commands = svc.save_mailboxes(self.domain, [('a@shop.example.com', 1, 100, 10), ('new@shop.example.com', 1, 50, 5)], False)
        self.assertEqual(commands, [['mailbox_status', 'new@shop.example.com', 1], ['mailbox_limits', 'new@shop.example.com', 50, 5]])
        row = self.models[3].objects.get(email_id='new@shop.example.com')
        self.assertEqual((row.limitStatus, row.monthlyLimits, row.hourlyLimit), (1, 50, 5))
        self.assertEqual(svc.save_domain(self.domain, 1, 1000), [])
        self.assertEqual(svc.save_domain(self.other, 1, 20), [['domain_status', 'other.com', 1], ['domain_limit', 'other.com', 20]])

    def test_all_or_nothing_and_foreign_mailboxes(self):
        with self.assertRaisesRegex(svc.LimitError, 'not a mailbox'):
            svc.save_mailboxes(self.domain, [('a@shop.example.com', 1, 70, 7), ('x@other.com', 1, 1, 1)], True)
        with self.assertRaises(PermissionError):
            svc.save_mailboxes(self.domain, [('b@shop.example.com', 1, 60, 6), ('a@shop.example.com', 0, 1, 1)], False)
        limits = self.models[3].objects.order_by('email_id')
        self.assertEqual([(r.limitStatus, r.monthlyLimits) for r in limits], [(1, 100), (1, 100)])
