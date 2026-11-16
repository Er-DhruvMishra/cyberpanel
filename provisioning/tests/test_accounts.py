import base64
import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import RequestFactory
from django.utils import timezone

from loginSystem.models import Administrator
from provisioning import api_views, tokens
from provisioning.models import AccountSuspension, SsoTicket
from provisioning.tests.helpers import PanelTestCase, api_post, fake_server, make_world
from websiteFunctions.models import Websites


class Base(PanelTestCase):
    def setUp(self):
        cache.clear()
        make_world(self)
        _, self.tok_a = tokens.create_token(self.res_a, 'whmcs', ['provisioning'])
        _, self.tok_admin = tokens.create_token(self.admin, 'whmcs', ['provisioning'])
        _, self.tok_a_read = tokens.create_token(self.res_a, 'ro', ['read'])

    def call(self, view, body, token=None):
        with fake_server():
            return api_post(view, body, token=token or self.tok_a)

    def state(self, domain):
        return Websites.objects.get(domain=domain).state


class IsolationTests(Base):
    """A reseller can act only on its own accounts; an administrator on all."""

    def test_reseller_cannot_touch_another_resellers_accounts(self):
        for view, body in [
            (api_views.suspend_account, {'username': 'user_b'}),
            (api_views.unsuspend_account, {'username': 'user_b'}),
            (api_views.terminate_account, {'username': 'user_b'}),
            (api_views.change_password, {'username': 'user_b', 'password': 'NewPass123'}),
            (api_views.change_package, {'username': 'user_b', 'package': 'reseller_a_Gold'}),
            (api_views.account_usage, {'username': 'user_b'}),
            (api_views.account_info, {'username': 'user_b'}),
            (api_views.create_sso, {'username': 'user_b'}),
            (api_views.suspend_account, {'username': 'reseller_b'}),
        ]:
            status, data = self.call(view, body)
            self.assertEqual((status, data['status']), (403, 0), view.__name__)
        self.assertEqual(self.state('b1.example.com'), 1)
        self.assertEqual(Administrator.objects.get(userName='user_b').state, 'ACTIVE')
        self.assertTrue(Administrator.objects.filter(userName='user_b').exists())

    def test_list_accounts_scoped(self):
        _, data = self.call(api_views.list_accounts, {})
        self.assertEqual(sorted(a['username'] for a in data['accounts']), ['reseller_a', 'user_a'])
        _, data = self.call(api_views.list_accounts, {}, token=self.tok_admin)
        self.assertEqual(len(data['accounts']), 5)

    def test_read_token_cannot_provision(self):
        status, data = self.call(api_views.suspend_account, {'username': 'user_a'}, token=self.tok_a_read)
        self.assertEqual((status, data['status']), (403, 0))
        status, data = self.call(api_views.list_accounts, {}, token=self.tok_a_read)
        self.assertEqual(data['status'], 1)

    def test_admin_account_cannot_be_suspended_by_api(self):
        _, data = self.call(api_views.suspend_account, {'username': 'admin'}, token=self.tok_admin)
        self.assertEqual(data['status'], 0)


class SuspendTests(Base):
    def test_suspend_and_unsuspend_account(self):
        status, data = self.call(api_views.suspend_account, {'username': 'user_a', 'reason': 'Overdue'})
        self.assertEqual(data['status'], 1, data)
        self.assertEqual(sorted(data['suspended_sites']), ['a1.example.com', 'a2.example.com'])
        self.assertEqual(Administrator.objects.get(userName='user_a').state, 'SUSPENDED')
        self.assertEqual((self.state('a1.example.com'), self.state('a2.example.com')), (0, 0))
        self.assertEqual(self.state('b1.example.com'), 1)
        _, data = self.call(api_views.unsuspend_account, {'username': 'user_a'})
        self.assertEqual(data['status'], 1, data)
        self.assertEqual(Administrator.objects.get(userName='user_a').state, 'ACTIVE')
        self.assertEqual((self.state('a1.example.com'), self.state('a2.example.com')), (1, 1))
        self.assertFalse(AccountSuspension.objects.exists())

    def test_unsuspend_leaves_individually_suspended_site(self):
        Websites.objects.filter(domain='a2.example.com').update(state=0)    # suspended on its own
        _, data = self.call(api_views.suspend_account, {'username': 'user_a'})
        self.assertEqual(data['suspended_sites'], ['a1.example.com'])
        self.call(api_views.unsuspend_account, {'username': 'user_a'})
        self.assertEqual((self.state('a1.example.com'), self.state('a2.example.com')), (1, 0))

    def test_suspended_account_cannot_log_in(self):
        from plogical import hashPassword
        from loginSystem.views import verifyLogin
        Administrator.objects.filter(pk=self.user_a.pk).update(password=hashPassword.hash_password('Secret123!'))
        self.call(api_views.suspend_account, {'username': 'user_a'})
        request = RequestFactory().post('/verifyLogin', data=json.dumps({'username': 'user_a', 'password': 'Secret123!'}),
                                        content_type='application/json', REMOTE_ADDR='203.0.113.5')
        request.session = mock.MagicMock()
        request.session.__getitem__.side_effect = KeyError
        body = json.loads(verifyLogin(request).content)
        self.assertEqual(body['loginStatus'], 0)
        self.assertIn('suspended', body['error_message'])

    def test_suspending_reseller_cascades_and_reverses(self):
        _, data = self.call(api_views.suspend_account, {'username': 'reseller_a'}, token=self.tok_admin)
        self.assertEqual(data['status'], 1, data)
        self.assertEqual(data['suspended_accounts'], ['user_a'])
        self.assertEqual(Administrator.objects.get(userName='user_a').state, 'SUSPENDED')
        self.assertEqual(self.state('a1.example.com'), 0)
        _, data = self.call(api_views.unsuspend_account, {'username': 'reseller_a'}, token=self.tok_admin)
        self.assertEqual(data['unsuspended_accounts'], ['user_a'])
        self.assertEqual(Administrator.objects.get(userName='user_a').state, 'ACTIVE')
        self.assertEqual(self.state('a1.example.com'), 1)

    def test_suspend_logs_out_existing_sessions(self):
        from django.contrib.sessions.backends.db import SessionStore
        session = SessionStore()
        session['userID'] = self.user_a.pk
        session.save()
        self.call(api_views.suspend_account, {'username': 'user_a'})
        self.assertFalse(SessionStore().exists(session.session_key))


class UsageTests(Base):
    def test_usage_per_site_and_total(self):
        _, data = self.call(api_views.account_usage, {'username': 'user_a'})
        usage = data['usage'][0]
        self.assertEqual(usage['username'], 'user_a')
        by_site = {s['domain']: s for s in usage['sites']}
        self.assertEqual(by_site['a1.example.com']['disk_mb'], 120.5)
        self.assertEqual(by_site['a1.example.com']['bandwidth_mb'], 300)
        self.assertEqual(by_site['a1.example.com']['disk_limit_mb'], 2000)
        self.assertEqual(usage['total'], {'disk_mb': 130.5, 'disk_limit_mb': 4000,
                                          'bandwidth_mb': 305, 'bandwidth_limit_mb': 0})

    def test_usage_of_all_managed_accounts(self):
        _, data = self.call(api_views.account_usage, {}, token=self.tok_a_read)
        self.assertEqual(sorted(u['username'] for u in data['usage']), ['reseller_a', 'user_a'])


class PasswordPackageCreateTerminateTests(Base):
    def test_change_password_by_token(self):
        from plogical import hashPassword
        encoded = base64.b64encode('N3w$ecret;|pw'.encode()).decode()
        _, data = self.call(api_views.change_password, {'username': 'user_a', 'passwordB64': encoded})
        self.assertEqual(data['status'], 1, data)
        self.assertTrue(hashPassword.check_password(Administrator.objects.get(userName='user_a').password,
                                                    'N3w$ecret;|pw'))
        _, data = self.call(api_views.change_password, {'username': 'user_a', 'password': 'short'})
        self.assertEqual(data['status'], 0)

    def test_change_package(self):
        from packages.models import Package
        Package.objects.create(admin=self.res_a, packageName='reseller_a_Silver', diskSpace=500, bandwidth=500)
        _, data = self.call(api_views.change_package, {'username': 'user_a', 'package': 'Silver'})
        self.assertEqual(data['status'], 1, data)
        self.assertEqual(Websites.objects.get(domain='a1.example.com').package.packageName, 'reseller_a_Silver')
        _, data = self.call(api_views.change_package, {'username': 'user_a', 'package': 'Default'})
        self.assertEqual(data['status'], 0)    # the admin's package is not the reseller's to use

    def test_create_account_with_website(self):
        _, data = self.call(api_views.create_account, {
            'username': 'newcust', 'email': 'c@example.com', 'passwordB64': base64.b64encode(b'Pa$$word12').decode(),
            'domain': 'www.new.example.com', 'package': 'Gold', 'php': 'PHP 8.2'})
        self.assertEqual(data['status'], 1, data)
        account = Administrator.objects.get(userName='newcust')
        self.assertEqual(account.owner, self.res_a.pk)
        self.assertEqual(account.acl.name, 'user')
        self.assertEqual(Websites.objects.get(domain='new.example.com').admin_id, account.pk)
        _, data = self.call(api_views.create_account, {
            'username': 'newcust', 'email': 'c@example.com', 'password': 'Password12', 'domain': 'x.example.com',
            'package': 'Gold'})
        self.assertEqual(data['status'], 0)
        self.assertIn('already exists', data['error_message'])

    def test_create_rolls_back_account_when_site_fails(self):
        from django.http import HttpResponse
        failing = lambda self, userID=None, data=None, conversionPreflight=None: HttpResponse(
            json.dumps({'createWebSiteStatus': 0, 'error_message': 'Invalid domain.'}))
        with mock.patch('websiteFunctions.website.WebsiteManager.submitWebsiteCreation', failing):
            _, data = api_post(api_views.create_account, {
                'username': 'brokencust', 'email': 'c@example.com', 'password': 'Password12',
                'domain': 'bad.example.com', 'package': 'Gold'}, token=self.tok_a)
        self.assertEqual((data['status'], data['error_message']), (0, 'Invalid domain.'))
        self.assertFalse(Administrator.objects.filter(userName='brokencust').exists())

    def test_reseller_cannot_create_admin(self):
        _, data = self.call(api_views.create_account, {
            'username': 'evil', 'email': 'e@example.com', 'password': 'Password12', 'acl': 'admin'})
        self.assertEqual(data['status'], 0)
        self.assertFalse(Administrator.objects.filter(userName='evil').exists())

    def test_terminate(self):
        _, data = self.call(api_views.terminate_account, {'username': 'user_a'})
        self.assertEqual(data['status'], 1, data)
        self.assertFalse(Administrator.objects.filter(userName='user_a').exists())
        self.assertFalse(Websites.objects.filter(domain__startswith='a').exists())
        _, data = self.call(api_views.terminate_account, {'username': 'user_a'})
        self.assertEqual((data['status'], data.get('already_absent')), (1, True))

    def test_terminate_refuses_reseller_with_customers(self):
        _, data = self.call(api_views.terminate_account, {'username': 'reseller_a'}, token=self.tok_admin)
        self.assertEqual(data['status'], 0)
        self.assertTrue(Administrator.objects.filter(userName='reseller_a').exists())


class SsoTests(Base):
    def redeem(self, url_or_ticket, ip='198.51.100.20'):
        from provisioning.api_views import redeem_sso
        ticket = url_or_ticket.split('ticket=')[-1]
        request = RequestFactory().get('/api/v2/sso/redeem', {'ticket': ticket}, REMOTE_ADDR=ip)
        from django.contrib.sessions.backends.db import SessionStore
        request.session = SessionStore()
        response = redeem_sso(request)
        return response, request.session

    def test_ticket_logs_in_once(self):
        _, data = self.call(api_views.create_sso, {'username': 'user_a', 'redirect': '/websites/listWebsites'})
        self.assertEqual(data['status'], 1, data)
        self.assertEqual(data['expires_in'], 60)
        self.assertIn('/api/v2/sso/redeem?ticket=', data['url'])
        response, session = self.redeem(data['url'])
        self.assertEqual((response.status_code, response['Location']), (302, '/websites/listWebsites'))
        self.assertEqual(session['userID'], self.user_a.pk)
        self.assertEqual(session['ipAddr'], '198.51.100.20')
        response, session = self.redeem(data['url'])
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('userID', session)

    def test_ticket_expires_after_60_seconds(self):
        _, data = self.call(api_views.create_sso, {'username': 'user_a'})
        SsoTicket.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        response, session = self.redeem(data['url'])
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('userID', session)

    def test_ticket_stored_hashed(self):
        _, data = self.call(api_views.create_sso, {'username': 'user_a'})
        ticket = data['url'].split('ticket=')[1]
        self.assertNotEqual(SsoTicket.objects.get().ticket_hash, ticket)

    def test_admin_sso_and_restrictions(self):
        _, data = self.call(api_views.create_sso, {}, token=self.tok_admin)     # AdminSingleSignOn: self
        self.assertEqual(data['status'], 1)
        _, data = self.call(api_views.create_sso, {'redirect': 'https://evil.example/'})
        self.assertEqual(data['status'], 0)
        self.call(api_views.suspend_account, {'username': 'user_a'})
        _, data = self.call(api_views.create_sso, {'username': 'user_a'})
        self.assertEqual(data['status'], 0)

    def test_head_request_does_not_consume(self):
        from provisioning.api_views import redeem_sso
        _, data = self.call(api_views.create_sso, {'username': 'user_a'})
        request = RequestFactory().head('/api/v2/sso/redeem', {'ticket': data['url'].split('ticket=')[1]})
        request.session = {}
        redeem_sso(request)
        response, _ = self.redeem(data['url'])
        self.assertEqual(response.status_code, 302)
