import json
import os
import tempfile
import unittest

from baseTemplate import buildRequests as br

GOOD = {'name': 'Asha Rao', 'email': 'Asha@Example.com', 'phone': '+91 98765 43210', 'company': 'Rao & Sons (Pvt)',
        'service': 'Android app', 'budget': br.BUDGETS[2], 'deadline': 'Q1: before March',
        'details': 'A delivery app: customers order, riders track; see https://example.com/spec for details.'}


class FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout=None):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


class BuildRequests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        FakeSMTP.sent = []

    def test_validation(self):
        req = br.validate(GOOD)
        self.assertEqual(req['email'], 'asha@example.com')
        for key, bad in (('name', 'A'), ('email', 'nope'), ('phone', 'call me'), ('service', 'Hacking'),
                         ('budget', 'a million'), ('details', 'too short'), ('company', 'x\ny')):
            with self.assertRaises(br.RequestError, msg=key):
                br.validate(dict(GOOD, **{key: bad}))

    def test_vendor_recipient_refused(self):
        self.assertFalse(br.usable_recipient('usman@cyberpersons.com'))
        with self.assertRaises(br.RequestError):
            br.save_settings('admin@cyberpanel.net', os.path.join(self.dir, 's.json'))
        self.assertEqual(br.save_settings('Owner@Example.org', os.path.join(self.dir, 's.json'))['recipient'],
                         'owner@example.org')

    def test_submit_saves_then_mails_with_reply_to(self):
        log = os.path.join(self.dir, 'r.jsonl')
        meta = {'panel_user': 'admin', 'ip': '203.0.113.5', 'time': 'now'}
        mailed, _ = br.submit(br.validate(GOOD), meta, 'noreply@panel.example.com', {'recipient': 'owner@example.org'},
                              smtp=FakeSMTP, log_path=log)
        self.assertTrue(mailed)
        msg = FakeSMTP.sent[0]
        self.assertEqual(msg['To'], 'owner@example.org')
        self.assertIn('asha@example.com', msg['Reply-To'])
        self.assertIn('Rao & Sons (Pvt)', msg.get_content())
        self.assertEqual(json.loads(open(log).read())['service'], 'Android app')
        self.assertEqual(oct(os.stat(log).st_mode & 0o777), '0o600')

    def test_not_mailed_without_recipient_but_kept(self):
        log = os.path.join(self.dir, 'r.jsonl')
        mailed, note = br.submit(br.validate(GOOD), {'panel_user': 'a', 'ip': 'x', 'time': 't'}, 'n@x.com',
                                 {'recipient': 'usman@cyberpersons.com'}, smtp=FakeSMTP, log_path=log)
        self.assertFalse(mailed)
        self.assertEqual(FakeSMTP.sent, [])
        self.assertTrue(os.path.getsize(log) > 0)

    def test_no_header_injection(self):
        with self.assertRaises(br.RequestError):  # line breaks in header-bound fields are refused outright
            br.validate(dict(GOOD, name='Eve\nBcc: x@evil.example'))
        req = br.validate(dict(GOOD, name='Eve <eve@x> Bcc: y@evil.example'))
        msg = br.render_message(req, {'panel_user': 'a', 'ip': 'x', 'time': 't'}, 'o@example.org', 'n@example.com')
        self.assertIsNone(msg['Bcc'])
        self.assertEqual(msg['To'], 'o@example.org')

    def test_rate_limit(self):
        session = {}
        results = [br.rate_limited(session, now=1000 + i) for i in range(br.MAX_PER_HOUR + 1)]
        self.assertEqual(results, [False] * br.MAX_PER_HOUR + [True])
        self.assertFalse(br.rate_limited(session, now=1000 + 3700))


if __name__ == '__main__':
    unittest.main()
