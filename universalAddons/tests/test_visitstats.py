"""Visitor statistics: report access checks, safe log opening, GoAccess command line, the built-in
summary, rate limits, endpoints and the page."""
import os
import tempfile
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons import privileged
from universalAddons.tests import helpers
from universalAddons.visitstats import service, views

LINES = [
    '203.0.113.5 - - [15/Nov/2026:10:00:00 +0000] "GET /index.php?x=1 HTTP/1.1" 200 1024 "https://google.com/" "Mozilla/5.0"',
    '203.0.113.5 - - [15/Nov/2026:10:00:05 +0000] "GET /about HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    '198.51.100.7 - - [16/Nov/2026:11:00:00 +0000] "GET /missing HTTP/1.1" 404 0 "-" "curl/8"',
    '198.51.100.7 - - [16/Nov/2026:11:00:01 +0000] "POST /index.php HTTP/1.1" 302 - "https://a.example/<script>" "curl/8"',
    'garbage line',
]


class ReportAccess(SimpleTestCase):
    def refusal(self, domain, **who):
        request = RequestFactory().get('/x')
        request.session = {'userID': 7}
        with helpers.caller(**who):
            return views.report_refusal(request, domain)

    def test_owner_needs_the_switch_and_the_site(self):
        on = {'visitstats_for_users': True}
        self.assertIsNone(self.refusal('mine.example.com', policy=on))
        self.assertEqual(self.refusal(helpers.FOREIGN, policy=on).status_code, 403)
        self.assertEqual(self.refusal('mine.example.com').status_code, 403)          # switch off
        self.assertEqual(self.refusal('../etc/passwd', policy=on).status_code, 403)
        self.assertIsNone(self.refusal(helpers.FOREIGN, admin=True))
        request = RequestFactory().get('/x')
        request.session = {}
        self.assertEqual(views.report_refusal(request, 'mine.example.com').status_code, 401)

    def get_report(self, domain, **who):
        request = RequestFactory().get('/x', {'site': domain})
        request.session = {'userID': 7}
        with helpers.caller(**who), mock.patch.object(privileged, 'call') as call:
            call.side_effect = self.stage
            response = views.report(request)
        return response, call

    def stage(self, module, action, **args):
        spool_id = privileged.write_spool(b'<html>report</html>', self.spool)
        return {'spool_id': spool_id}

    def test_report_is_served_sandboxed_and_only_to_the_owner(self):
        self.spool = tempfile.mkdtemp()
        with mock.patch.object(privileged, 'SPOOL_DIR', self.spool):
            response, call = self.get_report(helpers.FOREIGN, policy={'visitstats_for_users': True})
            self.assertEqual(response.status_code, 403)
            call.assert_not_called()
            response, call = self.get_report('mine.example.com', policy={'visitstats_for_users': True})
        self.assertEqual(response.status_code, 200)
        call.assert_called_once_with('visitstats', 'stage_report', domain='mine.example.com')
        self.assertEqual(b''.join(response.streaming_content), b'<html>report</html>')
        self.assertIn('sandbox', response['Content-Security-Policy'])
        self.assertNotIn('allow-same-origin', response['Content-Security-Policy'])
        self.assertEqual(response['X-Frame-Options'], 'SAMEORIGIN')
        self.assertEqual(os.listdir(self.spool), [])   # the staged copy is gone

    def test_endpoints_check_ownership(self):
        on = {'visitstats_for_users': True}
        with mock.patch.object(privileged, 'call') as call:
            self.assertEqual(helpers.post(views.generate, {'site': helpers.FOREIGN}, policy=on)[0], 403)
            self.assertEqual(helpers.post(views.options, {'site': helpers.FOREIGN, 'anonymize': True}, policy=on)[0], 403)
            self.assertEqual(helpers.post(views.overview, {})[0], 403)          # switch off
            self.assertEqual(helpers.post(views.install, {}, policy=on)[0], 403)  # administrators only
            call.assert_not_called()
            call.return_value = {'job_id': 'a' * 24}
            status, body, session = helpers.post(views.generate, {'site': 'mine.example.com'}, policy=on)
            self.assertEqual(status, 200)
            self.assertEqual(call.call_args, mock.call('visitstats', 'generate', domain='mine.example.com',
                                                       rate_limit=True))
            helpers.post(views.overview, {}, policy=on)
            self.assertEqual(call.call_args[1]['domains'], sorted(helpers.OWNED))


class Logs(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.fd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def test_links_and_hard_links_are_refused(self):
        target = os.path.join(self.dir, 'secret')
        with open(target, 'w') as handle:
            handle.write('root:x:0:0\n')
        os.symlink(target, os.path.join(self.dir, 'a.com.access_log'))
        with self.assertRaises(OSError):
            service.open_log_file(self.fd, 'a.com.access_log')
        os.link(target, os.path.join(self.dir, 'b.com.access_log'))
        with self.assertRaises(service.StatsError):
            service.open_log_file(self.fd, 'b.com.access_log')
        with open(os.path.join(self.dir, 'c.com.access_log'), 'w') as handle:
            handle.write(LINES[0] + '\n')
        fd = service.open_log_file(self.fd, 'c.com.access_log')
        self.assertEqual(list(service.read_lines([fd]))[0].decode().strip(), LINES[0])
        os.close(fd)

    def test_site_home_must_be_under_home(self):
        self.assertEqual(service.log_names('/home/a.com'), ('/home/a.com', 'logs', 'a.com.access_log'))
        for bad in ('/etc', '/home/a.com/../x', '/tmp/a.com'):
            with self.assertRaises(service.StatsError):
                service.log_names(bad)


class Reports(SimpleTestCase):
    def test_goaccess_command(self):
        argv = service.goaccess_command('/usr/bin/goaccess', (1, 10, 2), [5, 6], '/r/db', '/r/out.html', True, 'a.com')
        self.assertIn('--log-format=COMBINED', argv)
        self.assertIn('--anonymize-ip', argv)
        self.assertEqual(argv[argv.index('--persist'):argv.index('--persist') + 3],
                         ['--persist', '--restore', '--db-path=/r/db'])
        self.assertEqual(argv[-2:], ['/dev/fd/5', '/dev/fd/6'])
        self.assertEqual(argv[:6], ['nice', '-n', '19', 'ionice', '-c', '3'])
        old = service.goaccess_command('/usr/bin/goaccess', (1, 3, 0), [5], '/r/db', '/o', False, 'a.com')
        self.assertNotIn('--persist', old)
        self.assertNotIn('--anonymize-ip', old)
        self.assertEqual(service.goaccess_version('GoAccess - 1.10.2.\nFor more details'), (1, 10, 2))

    def test_builtin_summary(self):
        summary = service.summarise(LINES, anonymize=True)
        self.assertEqual((summary['hits'], summary['unparsed'], summary['visits']), (4, 1, 2))
        self.assertEqual(dict(summary['statuses']), {'200': 2, '302': 1, '404': 1})
        self.assertEqual(summary['ips'][0][0], '203.0.113.0')
        self.assertIn(('/index.php', 2), summary['pages'])
        self.assertNotIn('/missing', dict(summary['pages']))
        raw = service.summarise(LINES, anonymize=False)
        self.assertEqual(raw['ips'][0][0], '203.0.113.5')
        html = service.summary_html(summary, 'a.com', generated=0)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('anonymised', html)
        self.assertEqual(service.anonymize_ip('2001:db8:1:2::5'), '2001:db8:1::')

    def test_rate_limit_and_meta(self):
        base = tempfile.mkdtemp()
        self.assertTrue(service.load_meta('a.com', base)['anonymize'])   # anonymised by default
        service.save_meta('a.com', {'requested': 1000, 'anonymize': False}, base)
        meta = service.load_meta('a.com', base)
        self.assertFalse(meta['anonymize'])
        self.assertEqual(service.rate_limited(meta, 1000 + 60), service.ON_DEMAND_INTERVAL - 60)
        self.assertEqual(service.rate_limited(meta, 1000 + service.ON_DEMAND_INTERVAL), 0)
        self.assertEqual(oct(os.stat(base).st_mode & 0o777), '0o700')
        with self.assertRaises(service.StatsError):
            service.site_dir('../x', base)

    def test_root_side_generate_is_rate_limited(self):
        from universalAddons.visitstats import actions
        base = tempfile.mkdtemp()
        with mock.patch.object(service, 'REPORT_DIR', base), mock.patch.object(actions, '_site'), \
                mock.patch.object(actions.jobs, 'spawn', return_value={'job_id': 'b' * 24}) as spawn:
            actions.generate('a.com')
            with self.assertRaisesRegex(service.StatsError, 'requested recently'):
                actions.generate('a.com')
            actions.generate('a.com', rate_limit=False)
        self.assertEqual(spawn.call_count, 2)


class Page(SimpleTestCase):
    def test_page_renders(self):
        from django.template.loader import render_to_string
        html = render_to_string('universalAddons/visitstats.html', {'is_admin': True, 'site': 'a.com',
                                                                    'panel_brand': 'IndiansCloud'})
        self.assertIn('ua-visitstats', html)
        self.assertIn('/addons/visitor-stats/report', html)
        self.assertIn('sandbox="allow-scripts allow-popups"', html)
        self.assertEqual(helpers.page(views.page)[0], 403)
        status, values = helpers.page(views.page, policy={'visitstats_for_users': True})
        self.assertEqual((status, values['_template']), (200, 'universalAddons/visitstats.html'))
