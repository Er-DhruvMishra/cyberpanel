from datetime import timedelta

from django.core.cache import cache
from django.test import RequestFactory
from django.utils import timezone

from provisioning import api_views, tokens
from provisioning.models import ApiToken
from provisioning.tests.helpers import PanelTestCase, api_post, make_world


def bearer_request(token, ip='203.0.113.5'):
    return RequestFactory().post('/api/v2/verify', data='{}', content_type='application/json',
                                 HTTP_AUTHORIZATION='Bearer %s' % token, REMOTE_ADDR=ip)


class TokenTests(PanelTestCase):
    def setUp(self):
        cache.clear()
        make_world(self)

    def test_hashed_at_rest_and_shown_once(self):
        token, plaintext = tokens.create_token(self.res_a, 'WHMCS', ['provisioning'])
        self.assertRegex(plaintext, tokens.TOKEN_RE.pattern)
        secret = plaintext.rsplit('_', 1)[1]
        row = ApiToken.objects.get(pk=token.pk)
        self.assertEqual(row.token_hash, tokens.hash_secret(secret))
        self.assertNotIn(secret, ' '.join(str(v) for v in row.__dict__.values()))
        described = tokens.describe(row, 'reseller_a')
        self.assertNotIn(secret, str(described))
        self.assertTrue(described['prefix'].startswith('ictk_' + row.key_id))

    def test_authenticates_and_records_last_use(self):
        token, plaintext = tokens.create_token(self.res_a, 'x', ['read'])
        owner, used = tokens.authenticate(bearer_request(plaintext), 'read')
        self.assertEqual(owner.pk, self.res_a.pk)
        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)
        self.assertEqual(token.last_used_ip, '203.0.113.5')

    def test_wrong_secret_rejected(self):
        _, plaintext = tokens.create_token(self.res_a, 'x', ['read'])
        forged = plaintext[:-4] + ('AAAA' if not plaintext.endswith('AAAA') else 'BBBB')
        with self.assertRaises(tokens.TokenError):
            tokens.authenticate(bearer_request(forged), 'read')

    def test_scopes(self):
        _, read_only = tokens.create_token(self.res_a, 'r', ['read'])
        _, prov = tokens.create_token(self.res_a, 'p', ['provisioning'])
        with self.assertRaises(tokens.TokenError) as ctx:
            tokens.authenticate(bearer_request(read_only), 'provisioning')
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(tokens.authenticate(bearer_request(prov), 'read')[0].pk, self.res_a.pk)
        with self.assertRaises(ValueError):
            tokens.create_token(self.res_a, 'bad', ['root'])

    def test_expiry(self):
        token, plaintext = tokens.create_token(self.res_a, 'x', ['read'], expires_days=1)
        self.assertTrue(timedelta(hours=23) < token.expires_at - timezone.now() <= timedelta(days=1))
        ApiToken.objects.filter(pk=token.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(tokens.TokenError) as ctx:
            tokens.authenticate(bearer_request(plaintext), 'read')
        self.assertIn('expired', ctx.exception.message)
        with self.assertRaises(ValueError):
            tokens.create_token(self.res_a, 'x', ['read'], expires_days=99999)

    def test_ip_allowlist(self):
        _, plaintext = tokens.create_token(self.res_a, 'x', ['read'], allowed_ips='198.51.100.0/24\n2001:db8::1')
        self.assertEqual(tokens.authenticate(bearer_request(plaintext, '198.51.100.77'), 'read')[0].pk, self.res_a.pk)
        tokens.authenticate(bearer_request(plaintext, '2001:db8::1'), 'read')
        with self.assertRaises(tokens.TokenError) as ctx:
            tokens.authenticate(bearer_request(plaintext, '203.0.113.9'), 'read')
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(ValueError):
            tokens.create_token(self.res_a, 'x', ['read'], allowed_ips='not-an-ip')

    def test_revoke(self):
        token, plaintext = tokens.create_token(self.res_a, 'x', ['read'])
        tokens.revoke_token(token, self.res_a)
        with self.assertRaises(tokens.TokenError) as ctx:
            tokens.authenticate(bearer_request(plaintext), 'read')
        self.assertIn('revoked', ctx.exception.message)

    def test_api_access_flag_still_gates_tokens(self):
        _, plaintext = tokens.create_token(self.user_a, 'x', ['read'])    # user_a has api=0
        with self.assertRaises(tokens.TokenError) as ctx:
            tokens.authenticate(bearer_request(plaintext), 'read')
        self.assertEqual(ctx.exception.status, 403)

    def test_suspended_owner_rejected(self):
        _, plaintext = tokens.create_token(self.res_a, 'x', ['read'])
        self.res_a.state = 'SUSPENDED'
        self.res_a.save()
        with self.assertRaises(tokens.TokenError):
            tokens.authenticate(bearer_request(plaintext), 'read')

    def test_rate_limit_after_failures(self):
        for _ in range(tokens.FAILURE_LIMIT):
            with self.assertRaises(tokens.TokenError):
                tokens.authenticate(bearer_request('ictk_0000000000000000_' + 'A' * 43), 'read')
        _, plaintext = tokens.create_token(self.res_a, 'x', ['read'])
        with self.assertRaises(tokens.TokenError) as ctx:
            tokens.authenticate(bearer_request(plaintext), 'read')
        self.assertEqual(ctx.exception.status, 429)
        # another address is unaffected
        tokens.authenticate(bearer_request(plaintext, '198.51.100.1'), 'read')

    def test_v2_verify_needs_no_otp_for_token(self):
        self.res_a.twoFA = 1
        self.res_a.secretKey = 'JBSWY3DPEHPK3PXP'
        self.res_a.save()
        _, plaintext = tokens.create_token(self.res_a, 'x', ['read'])
        status, body = api_post(api_views.verify, {}, token=plaintext)
        self.assertEqual((status, body['status'], body['auth']), (200, 1, 'token'))

    def test_v2_password_auth_still_requires_otp(self):
        from plogical import hashPassword
        self.res_a.password = hashPassword.hash_password('Secret123!')
        self.res_a.twoFA = 1
        self.res_a.secretKey = 'JBSWY3DPEHPK3PXP'
        self.res_a.save()
        status, body = api_post(api_views.verify, {'adminUser': 'reseller_a', 'adminPass': 'Secret123!'})
        self.assertEqual(body['status'], 0)
        self.assertIn('Two-factor', body['error_message'])
