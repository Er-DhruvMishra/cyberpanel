import gzip
import io
import json
import os
import shutil
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import include, path

from universalAddons.sshsec import actions, service as sv, views

# The page needs its URL name; this test urlconf adds the module until universalAddons/urls.py does.
from CyberCP.urls import urlpatterns as _base_urls  # noqa: E402
urlpatterns = list(_base_urls) + [path('addons/ssh-security/', include('universalAddons.sshsec.urls'))]

NOW = time.mktime((2026, 11, 14, 12, 0, 0, 0, 0, -1))

EL_LOG = b"""Nov 14 10:00:01 host sshd[1001]: Invalid user admin from 203.0.113.5 port 40000
Nov 14 10:00:01 host sshd[1001]: pam_unix(sshd:auth): check pass; user unknown
Nov 14 10:00:03 host sshd[1001]: Failed password for invalid user admin from 203.0.113.5 port 40000 ssh2
Nov 14 10:00:04 host sshd[1001]: Received disconnect from 203.0.113.5 port 40000:11: Bye Bye [preauth]
Nov 14 10:00:04 host sshd[1001]: Disconnected from invalid user admin 203.0.113.5 port 40000 [preauth]
Nov 14 10:01:00 host sshd[1002]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root
Nov 14 10:01:00 host sshd[1002]: Failed password for root from 203.0.113.5 port 40002 ssh2
Nov 14 10:01:02 host sshd[1002]: Disconnecting authenticating user root 203.0.113.5 port 40002: Too many authentication failures [preauth]
Nov 14 10:02:00 host sshd[1003]: Connection closed by 198.51.100.9 port 5555 [preauth]
Nov 14 10:02:01 host sshd[1004]: Connection closed by 198.51.100.9 port 5556 [preauth]
Nov 14 10:02:02 host sshd[1005]: Connection reset by 198.51.100.9 port 5557 [preauth]
Nov 14 10:02:03 host sshd[1006]: Unable to negotiate with 198.51.100.9 port 5558: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]
Nov 14 10:02:04 host sshd[1007]: Connection closed by 198.51.100.9 port 5559 [preauth]
Nov 14 10:03:00 host sshd[1010]: Accepted publickey for deploy from 192.0.2.10 port 6000 ssh2: RSA SHA256:AbCdEf
Nov 14 10:03:00 host sshd[1010]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Nov 14 10:03:30 host sshd[1010]: Received disconnect from 192.0.2.10 port 6000:11: disconnected by user
Nov 14 10:03:30 host sshd[1010]: Disconnected from user deploy 192.0.2.10 port 6000
Nov 14 10:04:00 host sshd[1011]: Did not receive identification string from 198.51.100.9 port 5560
Nov 14 10:05:00 host sshd[1012]: message repeated 2 times: [ Failed password for root from 203.0.113.5 port 40010 ssh2]
Nov 14 10:05:00 host systemd[1]: Started Session 5 of user root.
Nov 14 10:09:00 host sshd-session[2004]: Failed publickey for git from 203.0.113.77 port 3 ssh2: ED25519 SHA256:x
"""

DEBIAN_LOG = b"""2026-11-14T10:07:01.123456+00:00 web sshd[2001]: Invalid user test from 2001:db8::bad port 50000
2026-11-14T10:07:02.123456+00:00 web sshd[2001]: Failed password for invalid user test from 2001:db8::bad port 50000 ssh2
2026-11-14T10:07:03.123456+00:00 web sshd[2001]: Connection closed by invalid user test 2001:db8::bad port 50000 [preauth]
Nov 14 10:08:00 web sshd[2002]: Accepted password for alice from ::ffff:192.0.2.20 port 1 ssh2
Nov 14 10:08:30 web CRON[9]: pam_unix(cron:session): session closed for user root
"""


def analyse(*blobs):
    analyzer = sv.Analyzer(NOW - 86400)
    for blob in blobs:
        sv.scan_stream(io.BytesIO(blob), analyzer, NOW - 86400, 10 ** 9, NOW)
    return analyzer.result()


def fake_runner(responses, calls):
    def runner(argv, **kwargs):
        calls.append(list(argv))
        for prefix, (code, out) in responses.items():
            if ' '.join(argv).startswith(prefix):
                return SimpleNamespace(returncode=code, stdout=out)
        return SimpleNamespace(returncode=0, stdout='')
    return runner


FIREWALL_UP = {
    'systemctl is-active firewalld': (0, 'active\n'),
    'systemctl is-active fail2ban': (3, 'inactive\n'),
    'firewall-cmd --get-default-zone': (0, 'public\n'),
    'firewall-cmd --get-active-zones': (0, 'public\n  interfaces: eth0 eth1\n'),
    'ip -o addr show': (0, '1: lo    inet 127.0.0.1/8 scope host lo\n'
                           '2: eth0    inet 150.241.245.94/24 brd 150.241.245.255 scope global eth0\n'
                           '2: eth0    inet6 2001:db8:1::5/64 scope global\n'
                           '3: eth1    inet 10.210.100.2/24 scope global eth1\n'),
}


class LogParsing(SimpleTestCase):
    def test_el_format(self):
        r = analyse(EL_LOG)
        ips = {row['ip']: row for row in r['top_ips']}
        attacker = ips['203.0.113.5']
        self.assertEqual((attacker['failed'], attacker['invalid'], attacker['root']), (4, 1, 3))
        self.assertEqual(attacker['probes'], 0, 'closes after auth attempts are not probes')
        self.assertIn('admin', attacker['users'])
        scanner = ips['198.51.100.9']
        self.assertEqual((scanner['probes'], scanner['failed']), (6, 0))
        self.assertEqual(scanner['kinds'], ['scan'])
        self.assertIn('198.51.100.9', [s['ip'] for s in r['scans']])
        self.assertNotIn('192.0.2.10', ips, 'a normal logout is not an attack')
        self.assertEqual(ips['203.0.113.77']['failed'], 1, 'OpenSSH 9.8 sshd-session lines')
        self.assertEqual(r['successful'], [{'user': 'deploy', 'ip': '192.0.2.10', 'method': 'publickey', 'count': 1,
                                            'last': int(time.mktime((2026, 11, 14, 10, 3, 0, 0, 0, -1))),
                                            'blocked_by': []}])
        users = {u['user']: u for u in r['top_users']}
        self.assertTrue(users['admin']['invalid'])
        self.assertFalse(users['root']['invalid'])
        self.assertEqual(users['root']['failed'], 3)
        self.assertEqual(r['totals']['root_failed'], 3)
        self.assertEqual(r['totals']['invalid_user'], 1)
        self.assertEqual(r['totals']['accepted'], 1)

    def test_debian_iso_ipv6_and_mapped(self):
        r = analyse(DEBIAN_LOG)
        ips = {row['ip']: row for row in r['top_ips']}
        self.assertEqual((ips['2001:db8::bad']['failed'], ips['2001:db8::bad']['invalid']), (1, 1))
        self.assertEqual(ips['2001:db8::bad']['probes'], 0)
        self.assertEqual([(s['user'], s['ip'], s['method']) for s in r['successful']],
                         [('alice', '192.0.2.20', 'password')])
        self.assertEqual(r['earliest'], 1794650821)  # 2026-11-14T10:07:01Z, timezone-independent

    def test_journal_short_iso_offset_and_cutoff(self):
        line = b'2026-11-14T15:38:00+0530 host sshd[3]: Failed password for root from 203.0.113.5 port 1 ssh2\n'
        self.assertEqual(sv.line_time(line), 1794650880)  # 10:08:00Z
        old = b'Nov 10 10:00:00 host sshd[4]: Failed password for root from 203.0.113.9 port 1 ssh2\n'
        self.assertEqual(analyse(old)['top_ips'], [], 'outside the window')

    def test_syslog_year_inference(self):
        jan = time.mktime((2027, 1, 2, 0, 0, 0, 0, 0, -1))
        stamp = sv.line_time(b'Dec 31 23:00:00 host sshd[1]: x', jan)
        self.assertEqual(time.localtime(stamp).tm_year, 2026)
        self.assertIsNone(sv.line_time(b'garbage line'))

    def test_probe_without_pid_and_garbage_ip(self):
        analyzer = sv.Analyzer(0)
        analyzer.feed(NOW, 'Connection closed by 198.51.100.1 port 1 [preauth]')
        analyzer.feed(NOW, 'Failed password for root from not-an-ip port 1 ssh2')
        r = analyzer.result()
        self.assertEqual([(i['ip'], i['probes']) for i in r['top_ips']], [('198.51.100.1', 1)])


class BoundedReading(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def big_log(self, path, days=3):
        start = NOW - days * 86400
        with open(path, 'wb') as handle:
            for n in range(days * 2400):
                stamp = time.localtime(start + n * 36)
                prefix = time.strftime('%b %e %H:%M:%S', stamp).encode()
                handle.write(prefix + b' host systemd[1]: noise noise noise noise\n')
                handle.write(prefix + b' host sshd[%d]: Failed password for root from 203.0.113.%d port 1 ssh2\n' % (
                    n, n % 200))

    def test_seek_skips_old_data(self):
        log = os.path.join(self.root, 'secure')
        self.big_log(log)
        analyzer = sv.Analyzer(NOW - 86400)
        coverage, truncated = actions.read_files(analyzer, NOW - 86400, [log], NOW)
        self.assertFalse(truncated)
        self.assertLess(coverage[0]['bytes'], coverage[0]['size'] * 0.5, 'bisection skipped the older days')
        self.assertAlmostEqual(analyzer.result()['totals']['failed'], 2400, delta=2)

    def test_budget_reads_newest_part_only(self):
        log = os.path.join(self.root, 'secure')
        self.big_log(log)
        analyzer = sv.Analyzer(NOW - 3 * 86400)
        coverage, truncated = actions.read_files(analyzer, NOW - 3 * 86400, [log], NOW, per_file=50000)
        self.assertTrue(truncated)
        self.assertLessEqual(coverage[0]['bytes'], 50000)
        self.assertGreater(analyzer.result()['earliest'], NOW - 86400)

    def test_rotated_files_newest_first(self):
        base = os.path.join(self.root, 'secure')
        for name, age in (('secure', 0), ('secure-20261108', 2), ('secure.1.gz', 5), ('secure-old', 1),
                          ('secure-20260101', 90)):
            p = os.path.join(self.root, name)
            opener = gzip.open if name.endswith('.gz') else open
            with opener(p, 'wb') as handle:
                handle.write(b'')
            os.utime(p, (NOW - age * 86400, NOW - age * 86400))
        found = [os.path.basename(p) for p in actions.log_files(NOW - 30 * 86400, (base,))]
        self.assertEqual(found, ['secure', 'secure-20261108', 'secure.1.gz'])

    def test_gzip_rotated_file(self):
        p = os.path.join(self.root, 'auth.log.2.gz')
        with gzip.open(p, 'wb') as handle:
            handle.write(EL_LOG)
        analyzer = sv.Analyzer(NOW - 86400)
        actions.read_files(analyzer, NOW - 86400, [p], NOW)
        self.assertEqual(analyzer.result()['totals']['failed'], 5)

    def test_journal_fallback_is_bounded(self):
        calls = []

        class Popen:
            def __init__(self, argv, **kwargs):
                calls.append(argv)
                self.stdout = io.BytesIO(b'2026-11-14T10:00:00+0000 host sshd[5]: Invalid user x from 203.0.113.8 port 2\n' * 1000)

            def kill(self):
                pass

            def wait(self):
                return 0
        analyzer = sv.Analyzer(0)
        coverage, truncated = actions.read_journal(analyzer, NOW - 86400, budget=8000, popen=Popen)
        self.assertTrue(truncated)
        self.assertIn('-r', calls[0])
        self.assertEqual(calls[0][calls[0].index('--since') + 1],
                         time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(NOW - 86400)))
        self.assertLess(analyzer.result()['totals']['invalid_user'], 1000)


class Targets(SimpleTestCase):
    def test_valid(self):
        self.assertEqual(str(sv.parse_target('203.0.113.7')), '203.0.113.7/32')
        self.assertEqual(str(sv.parse_target('203.0.113.0/24')), '203.0.113.0/24')
        self.assertEqual(str(sv.parse_target('2001:db8::/48')), '2001:db8::/48')
        self.assertEqual(str(sv.parse_target('::ffff:203.0.113.7')), '203.0.113.7/32')
        self.assertEqual(sv.decode_target('2001-db8--1'), '2001:db8::1')

    def test_invalid(self):
        for bad in ('203.0.113.7/24', '1.2.3', '1.2.3.4; rm -rf /', '010.1.2.3', '1.2.3.04', '0.0.0.0/0',
                    '10.0.0.0/8', '1.2.3.4/33', '1.2.3.4/024', '2001:db8::/16', 'fe80::1%eth0', '', None,
                    'example.com', '1.2.3.4 5', '1.2.3.4/'):
            with self.assertRaises(sv.SSHSecError, msg=repr(bad)):
                sv.parse_target(bad)

    def test_refusals(self):
        def check(target, client=('198.51.100.20',), server=('150.241.245.94', '2001:db8:1::5')):
            return sv.block_checks(sv.parse_target(target), client, server)
        self.assertTrue(check('198.51.100.20')[0], 'own client address')
        self.assertTrue(check('198.51.100.0/24')[0], 'network containing the client')
        self.assertTrue(check('150.241.245.0/24')[0], 'server address')
        self.assertTrue(check('2001:db8:1::/48')[0], 'server IPv6')
        self.assertTrue(check('127.0.0.1')[0])
        self.assertTrue(check('::1')[0])
        self.assertTrue(check('169.254.1.1')[0])
        refusals, confirm = check('10.1.2.3')
        self.assertEqual(refusals, [])
        self.assertTrue(confirm, 'private ranges need confirmation')
        self.assertEqual(check('203.0.113.9'), ([], []))

    def test_client_ips_follow_cyberpanel(self):
        meta = {'REMOTE_ADDR': '127.0.0.1', 'HTTP_CF_CONNECTING_IP': '198.51.100.20',
                'HTTP_X_FORWARDED_FOR': '198.51.100.30, 10.0.0.1'}
        self.assertEqual(sv.client_ips(meta), ['198.51.100.20', '127.0.0.1', '198.51.100.30'])
        self.assertEqual(sv.client_ips({'REMOTE_ADDR': '::ffff:198.51.100.20'}), ['198.51.100.20'])

    def test_reason(self):
        self.assertEqual(sv.validate_reason(' brute force #3 '), 'brute force #3')
        for bad in ('a;b', 'x' * 201, 'a:b', '<script>'):
            with self.assertRaises(sv.SSHSecError):
                sv.validate_reason(bad)


class Firewall(SimpleTestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.patches = [mock.patch.object(actions, 'STATE_DIR', self.state),
                        mock.patch.object(actions, 'REGISTRY', os.path.join(self.state, 'blocked.json'))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.state)

    def test_argv(self):
        net = sv.parse_target('2001:db8::/48')
        self.assertEqual(sv.firewall_argvs('add', 'public', net), [
            ['firewall-cmd', '--permanent', '--zone=public', '--add-rich-rule=rule family="ipv6" source address="2001:db8::/48" drop'],
            ['firewall-cmd', '--zone=public', '--add-rich-rule=rule family="ipv6" source address="2001:db8::/48" drop']])
        with self.assertRaises(sv.SSHSecError):
            sv.firewall_argvs('add', 'public; reboot', net)

    def test_block_and_unblock(self):
        calls = []
        runner = fake_runner(FIREWALL_UP, calls)
        result = actions.block('203.0.113.0/24', 'bots', client=['198.51.100.20'], by='admin', runner=runner)
        self.assertEqual(result['blocked']['target'], '203.0.113.0/24')
        writes = [c for c in calls if any('rich-rule' in a for a in c)]
        self.assertEqual(writes, sv.firewall_argvs('add', 'public', sv.parse_target('203.0.113.0/24')))
        self.assertFalse(any('--reload' in c for c in calls), 'a reload would drop fail2ban bans')
        with open(actions.REGISTRY) as handle:
            entry = json.load(handle)['entries'][0]
        self.assertEqual((entry['reason'], entry['by'], entry['zone']), ('bots', 'admin', 'public'))
        self.assertEqual(oct(os.stat(actions.REGISTRY).st_mode & 0o777), '0o600')
        with self.assertRaisesRegex(sv.SSHSecError, 'already'):
            actions.block('203.0.113.0/24', runner=runner)
        listing = actions.blocklist(fake_runner(dict(FIREWALL_UP, **{
            'firewall-cmd --zone=public --list-rich-rules': (0, sv.rich_rule(sv.parse_target('203.0.113.0/24')) + '\n')}), []))
        self.assertTrue(listing['entries'][0]['active'])
        calls.clear()
        self.assertTrue(actions.unblock('203.0.113.0/24', runner=runner)['was_registered'])
        self.assertEqual([c for c in calls if any('rich-rule' in a for a in c)],
                         sv.firewall_argvs('remove', 'public', sv.parse_target('203.0.113.0/24')))
        self.assertEqual(actions.load_registry(), [])

    def test_refusals_as_root(self):
        calls = []
        runner = fake_runner(FIREWALL_UP, calls)
        for target in ('150.241.245.94', '2001:db8:1::5', '198.51.100.20', '127.0.0.5'):
            with self.assertRaises(sv.SSHSecError, msg=target):
                actions.block(target, client=['198.51.100.20'], runner=runner)
        self.assertEqual(actions.block('192.168.50.0/24', runner=runner)['needs_confirm'][0][:15], '192.168.50.0/24')
        self.assertFalse(any('rich-rule' in ' '.join(c) for c in calls))
        with self.assertRaisesRegex(sv.SSHSecError, 'belongs to this server'):
            actions.block('10.210.100.0/24', confirm=True, runner=runner)
        self.assertIn('blocked', actions.block('192.168.50.0/24', confirm=True, runner=runner))

    def test_no_firewalld_no_blocking(self):
        calls = []
        runner = fake_runner({'systemctl is-active firewalld': (3, 'inactive\n')}, calls)
        with self.assertRaisesRegex(sv.SSHSecError, 'not running'):
            actions.block('203.0.113.9', runner=runner)
        self.assertFalse(any(c[0] == 'firewall-cmd' for c in calls))

    def test_parse_existing_blocks(self):
        rules = sv.parse_rich_rules(
            'rule family="ipv4" source address="218.238.5.110" port port="ssh" protocol="tcp" reject type="icmp-port-unreachable"\n'
            'rule family="ipv4" source address="146.19.125.70" drop\n'
            'rule family="ipv4" source address="0.0.0.0/0" port port="443" protocol="tcp" accept\n'
            'rule family="ipv6" port port="25" protocol="tcp" accept\n'
            'rule family="ipv4" source ipset="cp-ssh-blocklist" drop\n')
        self.assertEqual([(str(r.get('network', r.get('ipset'))), r['action'], r['port']) for r in rules],
                         [('218.238.5.110/32', 'reject', 'ssh'), ('146.19.125.70/32', 'drop', ''),
                          ('cp-ssh-blocklist', 'drop', '')])
        index = sv.BlockIndex()
        index.add(rules[1]['network'], 'firewalld drop')
        for ip in sv.parse_f2b_banned('`- Banned IP list:\t196.13.245.7 46.167.243.134'):
            index.add(ip, 'fail2ban sshd')
        self.assertEqual(index.labels('146.19.125.70'), ['firewalld drop'])
        self.assertEqual(index.labels('46.167.243.134'), ['fail2ban sshd'])
        self.assertEqual(sv.parse_f2b_jails('`- Jail list:\tdovecot, postfix, sshd'), ['dovecot', 'postfix', 'sshd'])


class Audit(SimpleTestCase):
    CONFIG = ('port 22\nlistenaddress [::]:22\nmaxauthtries 3\npermitrootlogin yes\npubkeyauthentication yes\n'
              'passwordauthentication yes\nkbdinteractiveauthentication no\nx11forwarding yes\npermitemptypasswords no\n')

    def test_this_kind_of_server(self):
        f2b = {'installed': True, 'running': True, 'jail': True, 'ignoreip': ['127.0.0.0/8', '::1', '157.49.36.44'],
               'maxretry': '5', 'bantime': '14400', 'findtime': '3600'}
        rows = {r['id']: r for r in sv.audit(sv.parse_sshd_t(self.CONFIG), f2b, 0, ['198.51.100.20'])}
        self.assertEqual({k: r['status'] for k, r in rows.items()}, {
            'permitrootlogin': 'warn', 'passwordauthentication': 'warn', 'port': 'info', 'maxauthtries': 'pass',
            'pubkeyauthentication': 'pass', 'x11forwarding': 'warn', 'allowusers': 'info', 'fail2ban': 'pass'})
        self.assertIn('no authorized_keys', rows['passwordauthentication']['fix'])
        self.assertIn('198.51.100.20', rows['fail2ban']['fix'])
        rows = {r['id']: r for r in sv.audit(sv.parse_sshd_t('permitrootlogin prohibit-password\npasswordauthentication no\n'
                                                             'allowusers alice bob\nmaxauthtries 6\n'),
                                             {'installed': True, 'running': True, 'jail': False})}
        self.assertEqual((rows['permitrootlogin']['status'], rows['passwordauthentication']['status'],
                          rows['allowusers']['value'], rows['maxauthtries']['status'], rows['fail2ban']['value']),
                         ('pass', 'pass', 'alice bob', 'warn', 'not enabled'))

    def test_enable_jail(self):
        root = tempfile.mkdtemp()
        jail = os.path.join(root, 'jail.d', 'cp-sshd.local')
        base = {'systemctl is-active fail2ban': (0, 'active\n'), 'fail2ban-client status': (0, '`- Jail list:\tpostfix\n'),
                '/usr/sbin/sshd -T': (0, 'port 2222\nport 22\n')}
        try:
            with mock.patch.object(actions, '_which', side_effect=lambda n: '/usr/sbin/' + n):
                calls = []
                result = actions.enable_f2b_sshd(fake_runner(base, calls), jail)
                self.assertTrue(result['changed'])
                with open(jail) as handle:
                    self.assertIn('[sshd]\nenabled = true\nport = 2222,22\n', handle.read())
                order = [' '.join(c) for c in calls if c[0] == 'fail2ban-client' and c[1] in ('-t', 'reload')]
                self.assertEqual(order, ['fail2ban-client -t', 'fail2ban-client reload'])
                os.unlink(jail)
                calls = []
                with self.assertRaisesRegex(sv.SSHSecError, 'undone'):
                    actions.enable_f2b_sshd(fake_runner(dict(base, **{'fail2ban-client -t': (1, 'ERROR')}), calls), jail)
                self.assertFalse(os.path.exists(jail))
                self.assertFalse(any(c[:2] == ['fail2ban-client', 'reload'] for c in calls))
                active = dict(base, **{'fail2ban-client status': (0, '`- Jail list:\tsshd\n')})
                self.assertFalse(actions.enable_f2b_sshd(fake_runner(active, []), jail)['changed'])
                self.assertFalse(os.path.exists(jail), 'an active jail is never overridden')
        finally:
            shutil.rmtree(root)


class Views(SimpleTestCase):
    def post(self, view, body, admin=1, meta=None):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json',
                                        **(meta or {'REMOTE_ADDR': '198.51.100.20'}))
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'ok': 1}) as call, \
                mock.patch.object(views, '_actor', return_value='admin'):
            response = view(request)
        return response.status_code, json.loads(response.content), call

    def test_admin_only(self):
        for view in (views.overview, views.analyze, views.audit, views.blocklist, views.block, views.unblock,
                     views.enable_jail, views.job):
            status, _, call = self.post(view, {'window': '24h', 'addr': '203.0.113.9'}, admin=0)
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()

    def test_block_validation(self):
        status, body, call = self.post(views.block, {'addr': '198.51.100.20'})
        self.assertEqual(status, 400)
        self.assertIn('lock you out', body['error_message'])
        call.assert_not_called()
        for bad in ({'addr': '1.2.3.4/8'}, {'addr': ['1.2.3.4']}, {'addr': '203.0.113.9', 'reason': 'x;y'}, {}):
            self.assertEqual(self.post(views.block, bad)[0], 400, bad)
        status, _, call = self.post(views.block, {'addr': '2001-db8--/48', 'reason': 'bots', 'confirm': True})
        self.assertEqual(status, 200)
        call.assert_called_once_with('sshsec', 'block', target='2001:db8::/48', reason='bots',
                                     client=['198.51.100.20'], confirm=True, by='admin')

    def test_analyze_and_jail(self):
        self.assertEqual(self.post(views.analyze, {'window': '1y'})[0], 400)
        status, _, call = self.post(views.analyze, {'window': '7d'})
        call.assert_called_once_with('sshsec', 'analyze', window='7d', client=['198.51.100.20'])
        self.assertEqual(self.post(views.enable_jail, {})[0], 400)
        self.assertEqual(self.post(views.job, {'job': '../x'})[0], 400)


@override_settings(ROOT_URLCONF='universalAddons.tests.test_sshsec')
class PageRenders(SimpleTestCase):
    def test_page(self):
        request = RequestFactory().get('/addons/ssh-security/')
        request.session = {}
        html = render_to_string('universalAddons/sshsec.html', {'request': request, 'admin': 1})
        self.assertIn('ua-wrap', html)
        self.assertIn('data-base="/addons/ssh-security/"', html)
        self.assertIn('sshsec.js', html)
