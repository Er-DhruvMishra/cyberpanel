"""The v1 endpoints keep working with passwords and the old apiToken, and also accept personal
Bearer tokens."""
import json

from django.core.cache import cache
from django.test import RequestFactory

from api import views as v1
from loginSystem.models import Administrator
from plogical import hashPassword
from plogical.securityUtils import ensure_api_token
from provisioning import tokens
from provisioning.tests.helpers import PanelTestCase, fake_server, make_world
from websiteFunctions.models import Websites


def post(view, body, authorization=None):
    extra = {'REMOTE_ADDR': '203.0.113.5'}
    if authorization:
        extra['HTTP_AUTHORIZATION'] = authorization
    request = RequestFactory().post('/api/x', data=json.dumps(body), content_type='application/json', **extra)
    from django.contrib.sessions.backends.db import SessionStore
    request.session = SessionStore()
    with fake_server():
        response = view(request)
    return json.loads(response.content.decode())


class LegacyApiTests(PanelTestCase):
    def setUp(self):
        cache.clear()
        make_world(self)
        Administrator.objects.filter(pk=self.res_a.pk).update(password=hashPassword.hash_password('ResellerPw1'))
        _, self.bearer = tokens.create_token(self.res_a, 'whmcs', ['provisioning'])
        self.bearer = 'Bearer ' + self.bearer

    def test_verify_conn_still_issues_legacy_token(self):
        data = post(v1.verifyConn, {'adminUser': 'reseller_a', 'adminPass': 'ResellerPw1'})
        self.assertEqual(data['verifyConn'], 1)
        self.assertTrue(data['apiToken'].startswith('Basic cp_api_v1_'))

    def test_password_auth_still_works(self):
        data = post(v1.changeUserPassAPI, {'adminUser': 'reseller_a', 'adminPass': 'ResellerPw1',
                                           'websiteOwner': 'reseller_a', 'ownerPassword': 'Changed123'})
        self.assertEqual(data['changeStatus'], 1)
        data = post(v1.changeUserPassAPI, {'adminUser': 'reseller_a', 'adminPass': 'wrong',
                                           'websiteOwner': 'reseller_a', 'ownerPassword': 'Changed123'})
        self.assertEqual(data['changeStatus'], 0)

    def test_legacy_api_token_still_accepted_where_it_was(self):
        account = Administrator.objects.get(pk=self.res_a.pk)
        ensure_api_token(account)
        data = post(v1.getPackagesListAPI, {'adminUser': 'reseller_a'}, authorization=account.token)
        self.assertIsInstance(data, list)
        # ... and still refused where it was refused before
        data = post(v1.submitWebsiteStatus, {'adminUser': 'reseller_a', 'websiteName': 'a1.example.com',
                                             'state': 'Suspend'}, authorization=account.token)
        self.assertEqual(data['websiteStatus'], 0)

    def test_bearer_token_on_provisioning_endpoints(self):
        data = post(v1.submitWebsiteStatus, {'websiteName': 'a1.example.com', 'state': 'Suspend'},
                    authorization=self.bearer)
        self.assertEqual(data['websiteStatus'], 1)
        self.assertEqual(Websites.objects.get(domain='a1.example.com').state, 0)
        data = post(v1.changeUserPassAPI, {'websiteOwner': 'user_a', 'ownerPassword': 'Changed123'},
                    authorization=self.bearer)
        self.assertEqual(data['changeStatus'], 0)    # v1 rule kept: only admins change others' passwords
        data = post(v1.getUserInfo, {'username': 'user_b'}, authorization=self.bearer)
        self.assertEqual(data['status'], 0)          # another reseller's account is invisible
        data = post(v1.getUserInfo, {'username': 'user_a'}, authorization=self.bearer)
        self.assertEqual(data['status'], 1)

    def test_bearer_create_website(self):
        data = post(v1.createWebsite, {'domainName': 'legacy.example.com', 'ownerEmail': 'o@example.com',
                                       'packageName': 'reseller_a_Gold', 'websiteOwner': 'legacyowner',
                                       'ownerPassword': 'Password12', 'phpSelection': 'PHP 8.1'},
                    authorization=self.bearer)
        self.assertEqual(data['createWebSiteStatus'], 1, data)
        self.assertEqual(Websites.objects.get(domain='legacy.example.com').admin.userName, 'legacyowner')
        # an existing account of another reseller cannot receive the site
        data = post(v1.createWebsite, {'domainName': 'steal.example.com', 'ownerEmail': 'o@example.com',
                                       'packageName': 'reseller_a_Gold', 'websiteOwner': 'user_b',
                                       'ownerPassword': 'Password12'}, authorization=self.bearer)
        self.assertEqual(data['createWebSiteStatus'], 0)

    def test_bearer_must_match_admin_user_if_given(self):
        data = post(v1.submitWebsiteStatus, {'adminUser': 'reseller_b', 'websiteName': 'b1.example.com',
                                             'state': 'Suspend'}, authorization=self.bearer)
        self.assertEqual(data['websiteStatus'], 0)
        self.assertEqual(Websites.objects.get(domain='b1.example.com').state, 1)

    def test_read_scope_refused_on_v1_writes(self):
        _, read = tokens.create_token(self.res_a, 'ro', ['read'])
        data = post(v1.submitWebsiteStatus, {'websiteName': 'a1.example.com', 'state': 'Suspend'},
                    authorization='Bearer ' + read)
        self.assertEqual(data['websiteStatus'], 0)
