import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from universalAddons.emaildebug import service as s  # noqa: E402

SERVER_IP = '203.0.113.10'


class FakeResolver:
    def __init__(self, records):
        self.records = records

    def query(self, name, rtype):
        return list(self.records.get((name.lower(), rtype), []))


def good_zone(overrides=None):
    records = {
        ('example.com', 'MX'): ['10 mail.example.com'],
        ('mail.example.com', 'A'): [SERVER_IP],
        ('example.com', 'TXT'): ['v=spf1 a mx ip4:%s ~all' % SERVER_IP, 'google-site-verification=x'],
        ('example.com', 'A'): [SERVER_IP],
        ('default._domainkey.example.com', 'TXT'): ['v=DKIM1; k=rsa; p=ABCDEF123'],
        ('_dmarc.example.com', 'TXT'): ['v=DMARC1; p=quarantine; rua=mailto:d@example.com'],
        ('10.113.0.203.in-addr.arpa', 'PTR'): ['mail.example.com'],
    }
    records.update(overrides or {})
    return FakeResolver(records)


class DnsChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(self.tmp.name, 'example.com'))
        with open(os.path.join(self.tmp.name, 'example.com', 'default.txt'), 'w') as handle:
            handle.write('default._domainkey IN TXT ( "v=DKIM1; k=rsa; "\n "p=ABCDEF" "123" )')

    def tearDown(self):
        self.tmp.cleanup()

    def statuses(self, resolver):
        report = s.domain_report(resolver, 'example.com', [SERVER_IP], SERVER_IP, 'mail.example.com',
                                 key_dir=self.tmp.name)
        return {item['id']: item['status'] for item in report}

    def test_healthy_domain_passes(self):
        self.assertEqual(self.statuses(good_zone()),
                         {'mx': 'pass', 'mailhost': 'pass', 'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'})

    def test_missing_records_fail(self):
        resolver = FakeResolver({})
        result = self.statuses(resolver)
        self.assertEqual(result['mx'], 'fail')
        self.assertEqual(result['spf'], 'fail')
        self.assertEqual(result['dkim'], 'fail')
        self.assertEqual(result['dmarc'], 'warn')

    def test_spf_not_authorising_server_fails(self):
        resolver = good_zone({('example.com', 'TXT'): ['v=spf1 ip4:198.51.100.1 -all']})
        check = s.check_spf(resolver, 'example.com', SERVER_IP)
        self.assertEqual(check['status'], 'fail')
        self.assertIn('ip4:%s' % SERVER_IP, check['fix'])

    def test_spf_include_and_multiple_records(self):
        resolver = good_zone({
            ('example.com', 'TXT'): ['v=spf1 include:_spf.host.net -all'],
            ('_spf.host.net', 'TXT'): ['v=spf1 ip4:203.0.113.0/24 -all'],
        })
        self.assertEqual(s.check_spf(resolver, 'example.com', SERVER_IP)['status'], 'pass')
        resolver = good_zone({('example.com', 'TXT'): ['v=spf1 a -all', 'v=spf1 mx -all']})
        self.assertEqual(s.check_spf(resolver, 'example.com', SERVER_IP)['status'], 'fail')

    def test_spf_lookup_limit(self):
        chain = {('example.com', 'TXT'): ['v=spf1 ' + ' '.join('include:i%d.test' % i for i in range(11)) + ' -all']}
        for i in range(11):
            chain[('i%d.test' % i, 'TXT')] = ['v=spf1 -all']
        check = s.check_spf(good_zone(chain), 'example.com', SERVER_IP)
        self.assertEqual(check['status'], 'fail')
        self.assertIn('limit 10', check['detail'])

    def test_spf_plus_all_warns(self):
        resolver = good_zone({('example.com', 'TXT'): ['v=spf1 +all']})
        self.assertEqual(s.check_spf(resolver, 'example.com', SERVER_IP)['status'], 'warn')

    def test_dkim_mismatch(self):
        resolver = good_zone({('default._domainkey.example.com', 'TXT'): ['v=DKIM1; p=OTHERKEY']})
        self.assertEqual(s.check_dkim(resolver, 'example.com', key_dir=self.tmp.name)['status'], 'fail')

    def test_dmarc_policy_none_is_info(self):
        resolver = good_zone({('_dmarc.example.com', 'TXT'): ['v=DMARC1; p=none']})
        self.assertEqual(s.check_dmarc(resolver, 'example.com')['status'], 'info')

    def test_ptr_fcrdns(self):
        self.assertEqual(s.check_ptr(good_zone(), SERVER_IP, 'mail.example.com')['status'], 'pass')
        self.assertEqual(s.check_ptr(good_zone(), SERVER_IP, 'other.example.com')['status'], 'warn')
        broken = good_zone({('mail.example.com', 'A'): ['198.51.100.9']})
        self.assertEqual(s.check_ptr(broken, SERVER_IP, 'mail.example.com')['status'], 'fail')
        self.assertEqual(s.check_ptr(FakeResolver({}), SERVER_IP, 'x')['status'], 'fail')

    def test_dnsbl(self):
        resolver = good_zone({
            ('10.113.0.203.zen.spamhaus.org', 'A'): ['127.0.0.2'],
            ('10.113.0.203.bl.spamcop.net', 'A'): ['127.255.255.254'],
        })
        results = {r['id']: r['status'] for r in s.check_dnsbl(resolver, SERVER_IP)}
        self.assertEqual(results['dnsbl:zen.spamhaus.org'], 'fail')
        self.assertEqual(results['dnsbl:bl.spamcop.net'], 'info')
        self.assertEqual(results['dnsbl:b.barracudacentral.org'], 'pass')

    def test_validators(self):
        self.assertTrue(s.valid_domain('mail.example.co.uk'))
        for bad in ('', 'localhost', '-a.com', 'a..com', 'a.com;rm -rf', 'a.com/x'):
            self.assertFalse(s.valid_domain(bad), bad)
        self.assertTrue(s.valid_email('a.b+c@example.com'))
        self.assertFalse(s.valid_email('a@b'))
        self.assertFalse(s.valid_email('a b@example.com'))


class DigResolverTests(unittest.TestCase):
    def test_parses_txt_chunks_and_strips_dots(self):
        outputs = {'TXT': '"v=spf1 " "a ~all"\n', 'MX': '10 mail.example.com.\n', 'A': ';; timeout\n1.2.3.4\n'}

        def runner(argv, **kwargs):
            self.assertNotIn('shell', kwargs)
            return SimpleNamespace(stdout=outputs[argv[-1]], returncode=0)

        resolver = s.DigResolver(runner=runner)
        self.assertEqual(resolver.query('example.com', 'TXT'), ['v=spf1 a ~all'])
        self.assertEqual(resolver.query('example.com', 'MX'), ['10 mail.example.com'])
        self.assertEqual(resolver.query('example.com', 'A'), ['1.2.3.4'])


LOG = """\
Oct 22 10:00:01 host postfix/smtpd[100]: 4AB12C3D4E: client=unknown[198.51.100.7], sasl_method=LOGIN, sasl_username=user@example.com
Oct 22 10:00:01 host postfix/cleanup[101]: 4AB12C3D4E: message-id=<abc@example.com>
Oct 22 10:00:01 host postfix/qmgr[102]: 4AB12C3D4E: from=<user@example.com>, size=1234, nrcpt=2 (queue active)
Oct 22 10:00:02 host postfix/smtp[103]: 4AB12C3D4E: to=<a@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.0.1]:25, delay=1.2, delays=0.1/0/0.5/0.6, dsn=2.0.0, status=sent (250 2.0.0 OK 1700000000 x)
Oct 22 10:00:03 host postfix/smtp[103]: 4AB12C3D4E: to=<b@yahoo.com>, relay=mta.yahoo.com[1.2.3.4]:25, delay=2, delays=0.1/0/1/1, dsn=4.7.0, status=deferred (host mta.yahoo.com[1.2.3.4] said: 421 4.7.0 [TSS04] Messages from 203.0.113.10 temporarily deferred)
Oct 22 10:00:04 host postfix/qmgr[102]: 4AB12C3D4E: removed
Oct 22 10:01:00 host postfix/smtpd[104]: warning: unknown[192.0.2.55]: SASL LOGIN authentication failed: UGFzc3dvcmQ6
Oct 22 10:01:05 host postfix/smtpd[104]: warning: unknown[192.0.2.55]: SASL LOGIN authentication failed: UGFzc3dvcmQ6
2026-10-22T10:02:00.123456+05:30 host postfix/smtp[105]: 5BC23D4E5F: to=<c@example.org>, relay=none, delay=0.1, delays=0/0/0.1/0, dsn=5.1.2, status=bounced (Host or domain name not found)
Oct 22 10:03:00 host dovecot: imap-login: Login: user=<x>
"""


class LogParsing(unittest.TestCase):
    def setUp(self):
        self.messages, self.sasl = s.build_messages(LOG.splitlines())

    def test_trace(self):
        record = self.messages['4AB12C3D4E']
        self.assertEqual(record['from'], 'user@example.com')
        self.assertEqual(record['sasl_username'], 'user@example.com')
        self.assertEqual(record['message_id'], 'abc@example.com')
        self.assertTrue(record['removed'])
        self.assertEqual([(d['to'], d['status']) for d in record['deliveries']],
                         [('a@gmail.com', 'sent'), ('b@yahoo.com', 'deferred')])
        self.assertIn('temporarily deferred', record['deliveries'][1]['reason'])

    def test_iso_timestamps_and_sasl_failures(self):
        self.assertEqual(self.messages['5BC23D4E5F']['deliveries'][0]['status'], 'bounced')
        self.assertEqual(self.sasl['192.0.2.55'], 2)

    def test_search(self):
        self.assertEqual([m['qid'] for m in s.search_messages(self.messages, 'yahoo')], ['4AB12C3D4E'])
        self.assertEqual([m['qid'] for m in s.search_messages(self.messages, status='bounced')], ['5BC23D4E5F'])
        self.assertEqual(s.search_messages(self.messages, 'nobody@nowhere'), [])

    def test_summary(self):
        summary = s.log_summary(self.messages, self.sasl)
        self.assertEqual(summary['statuses'], {'sent': 1, 'deferred': 1, 'bounced': 1})
        self.assertEqual(summary['top_senders'][0], ('user@example.com', 2))
        self.assertEqual(summary['sasl_failures'], [('192.0.2.55', 2)])
        self.assertTrue(all('203.0.113.10' not in reason for reason, _ in summary['top_problems']))

    def test_non_postfix_lines_ignored(self):
        self.assertIsNone(s.parse_line('Oct 22 10:03:00 host dovecot: imap-login: Login'))

    def test_read_log_tail_drops_partial_first_line(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as handle:
            handle.write('first line that is long\nsecond\nthird\n')
        try:
            path, lines = s.read_log_tail((handle.name,), max_bytes=13)
            self.assertEqual(path, handle.name)
            self.assertEqual(lines, ['second', 'third'])
        finally:
            os.unlink(handle.name)


class ReadTailMidLine(unittest.TestCase):
    def test_window_starting_mid_line_drops_fragment(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as handle:
            handle.write('aaaa\nbbbb\ncccc\n')
        try:
            self.assertEqual(s.read_log_tail((handle.name,), max_bytes=12)[1], ['bbbb', 'cccc'])
            self.assertEqual(s.read_log_tail((handle.name,), max_bytes=10)[1], ['bbbb', 'cccc'])
            self.assertEqual(s.read_log_tail((handle.name,), max_bytes=10 ** 6)[1], ['aaaa', 'bbbb', 'cccc'])
        finally:
            os.unlink(handle.name)


class PortChecks(unittest.TestCase):
    def _tls_server(self, common_name):
        import datetime
        import socket
        import ssl
        import threading
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), False)
                .sign(key, hashes.SHA256()))
        directory = tempfile.mkdtemp()
        cert_path, key_path = os.path.join(directory, 'c.pem'), os.path.join(directory, 'k.pem')
        with open(cert_path, 'wb') as handle:
            handle.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, 'wb') as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)

        def serve():
            connection, _ = listener.accept()
            try:
                context.wrap_socket(connection, server_side=True).close()
            except OSError:
                pass
            listener.close()
        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    def test_self_signed_tls_is_reported(self):
        port = self._tls_server('mail.example.com')
        check = s.check_port('127.0.0.1', port, 'mail.example.com', timeout=5, mode='tls')
        self.assertEqual(check['status'], 'warn', check)
        self.assertIn('self-signed', check['detail'])
        self.assertIn('mail.example.com', check['detail'])

    def test_closed_port_fails(self):
        import socket
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        self.assertEqual(s.check_port('127.0.0.1', port, timeout=2)['status'], 'fail')


class QueueSpamAndSend(unittest.TestCase):
    def test_queue_summary(self):
        lines = '\n'.join([
            '{"queue_name": "deferred", "arrival_time": 1000, "recipients": [{"address": "a@yahoo.com"}]}',
            '{"queue_name": "active", "arrival_time": 2000, "recipients": [{"address": "b@yahoo.com"}, {"address": "c@x.org"}]}',
            'not json',
        ])
        summary = s.queue_summary(runner=lambda argv, **kw: SimpleNamespace(stdout=lines, returncode=0))
        self.assertEqual(summary['count'], 2)
        self.assertEqual(summary['queues'], {'deferred': 1, 'active': 1})
        self.assertEqual(summary['top_destinations'][0], ('yahoo.com', 2))

    def test_spam_score_spamassassin(self):
        def runner(argv, **kwargs):
            self.assertEqual(argv, ['spamc', '-R'])
            return SimpleNamespace(stdout='7.5/5.0\nContent analysis details:\n', stderr='', returncode=1)
        out = s.spam_score('Subject: x\n\nhi', runner=runner, which=lambda name: name == 'spamc')
        self.assertEqual(out['engine'], 'SpamAssassin')
        self.assertEqual(out['score'], {'score': 7.5, 'threshold': 5.0})

    def test_spam_score_without_engine(self):
        self.assertIn('error', s.spam_score('x', which=lambda name: None))

    def test_send_test_message_validates_and_uses_argv(self):
        with self.assertRaises(ValueError):
            s.send_test_message('bad', 'to@example.com', 'h')
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stderr='')
        message_id = s.send_test_message('from@example.com', 'to@example.org', 'mail.example.com', runner=runner)
        argv, kwargs = calls[0]
        self.assertEqual(argv, ['sendmail', '-f', 'from@example.com', '--', 'to@example.org'])
        self.assertIn('Message-ID: <%s>' % message_id, kwargs['input'])
        self.assertTrue(message_id.endswith('@mail.example.com'))


if __name__ == '__main__':
    unittest.main()
