"""Autoresponders & Spam Rules: Sieve rendering and escaping, date bounds, ordering, spam rules,
the root-side writer (temporary mail tree, sievec mocked), ownership and the page."""
import datetime
import json
import os
import re
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons.autoresponder import actions, service as svc, views
from universalAddons.autoresponder.service import SieveError

TODAY = datetime.date(2026, 11, 16)
LIVE_MAILSCANNER = '''
%org-name% = yoursite
Spam Header = X-%org-name%-MailScanner-SpamCheck:
Spam Score Header = X-%org-name%-MailScanner-SpamScore:
Spam Score Character = s
SpamScore Number Instead Of Stars = no
Required SpamAssassin Score = 6
High SpamAssassin Score = 10
Spam Actions = deliver header "X-Spam-Status: Yes"
High Scoring Spam Actions = store
'''
LIVE_DOVECONF = '''mail_plugins = zlib
protocols = imap pop3
protocol lda {
  auth_socket_path = /var/run/dovecot/auth-master
  mail_plugins = zlib
}
'''


def settings(vacation=None, spam=None):
    return svc.clean_settings({'vacation': vacation or {}, 'spam': spam or {}}, TODAY)


def sieve_strings(script):
    """Decode every quoted string of a script the way a Sieve parser does (RFC 5228 2.4.2)."""
    out, i = [], 0
    while i < len(script):
        c = script[i]
        if c == '#':
            i = script.find('\n', i)
            i = len(script) if i < 0 else i
            continue
        if c == '"':
            value, i = [], i + 1
            while script[i] != '"':
                if script[i] == '\\':
                    i += 1
                value.append(script[i])
                i += 1
            out.append(''.join(value))
        i += 1
    return out


class Escaping(SimpleTestCase):
    def test_quote_escapes_backslash_and_quote(self):
        self.assertEqual(svc.quote('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(svc.quote('x\x00y'), '"xy"')

    def test_body_round_trips_through_a_sieve_parser(self):
        body = 'Hello "friend",\nC:\\path\\ and \\" tricky\n.\n} { stop; "\nEnd'
        subject = 'Out of office: "away" \\ back soon'
        script = svc.render(settings({'enabled': True, 'body': body, 'subject': subject}), 'me@example.com')
        strings = sieve_strings(script)
        self.assertIn(body, strings)
        self.assertIn(subject, strings)
        # Nothing of the body leaks out of its string: outside strings there is no "stop".
        self.assertNotIn('stop', re.sub(r'"(?:\\.|[^"\\])*"', '""', script))

    def test_crlf_and_control_characters_are_cleaned(self):
        clean = svc.clean_vacation({'enabled': True, 'body': 'a\r\nb\rc\x07d', 'subject': 'x\ny\tz'})
        self.assertEqual(clean['body'], 'a\nb\ncd')
        self.assertEqual(clean['subject'], 'x y z')

    def test_limits(self):
        with self.assertRaises(SieveError):
            svc.clean_vacation({'body': 'x' * (svc.MAX_BODY + 1)})
        with self.assertRaises(SieveError):
            svc.clean_vacation({'enabled': True, 'body': '   '})
        with self.assertRaises(SieveError):
            svc.clean_vacation({'days': 0})
        with self.assertRaises(SieveError):
            svc.clean_vacation({'days': True})
        with self.assertRaises(SieveError):
            svc.clean_vacation({'addresses': ['not an address']})

    def test_aliases_become_addresses(self):
        script = svc.render(settings({'enabled': True, 'body': 'b', 'addresses': 'Sales@Example.com, info@example.com'}),
                            'me@example.com')
        self.assertIn(':addresses ["sales@example.com", "info@example.com"]', script)
        self.assertIn(':days 7', script)


class DateBounds(SimpleTestCase):
    def test_end_before_start_is_refused(self):
        with self.assertRaisesRegex(SieveError, 'before the start'):
            svc.clean_vacation({'start': '2026-12-10', 'end': '2026-12-01'})

    def test_invalid_dates(self):
        for value in ('2026-02-30', '16/11/2026', '2026-1-1'):
            with self.assertRaises(SieveError):
                svc.clean_vacation({'start': value})

    def test_past_end_refused_only_when_enabled(self):
        with self.assertRaisesRegex(SieveError, 'past'):
            svc.clean_vacation({'enabled': True, 'body': 'b', 'end': '2026-11-01'}, TODAY)
        self.assertEqual(svc.clean_vacation({'enabled': False, 'end': '2026-11-01'}, TODAY)['end'], '2026-11-01')

    def test_rendered_bounds(self):
        script = svc.render(settings({'enabled': True, 'body': 'b', 'start': '2026-11-20', 'end': '2026-11-30'}), 'a@b.com')
        self.assertIn('if allof(currentdate :value "ge" "date" "2026-11-20", currentdate :value "le" "date" "2026-11-30")',
                      script)
        self.assertIn('"date"', script.split('\n')[3])
        self.assertIn('"relational"', script.split('\n')[3])
        only_start = svc.render(settings({'enabled': True, 'body': 'b', 'start': '2026-11-20'}), 'a@b.com')
        self.assertIn('if currentdate :value "ge" "date" "2026-11-20" {', only_start)
        open_ended = svc.render(settings({'enabled': True, 'body': 'b'}), 'a@b.com')
        self.assertNotIn('currentdate', open_ended)
        self.assertNotIn('"date"', open_ended)

    def test_active_today(self):
        v = svc.clean_vacation({'enabled': True, 'body': 'b', 'start': '2026-11-16', 'end': '2026-11-16'})
        self.assertTrue(svc.vacation_active(v, TODAY))
        self.assertFalse(svc.vacation_active(v, TODAY + datetime.timedelta(days=1)))


class SpamRules(SimpleTestCase):
    def setUp(self):
        self.headers = svc.mailscanner_headers(LIVE_MAILSCANNER)

    def test_live_mailscanner_headers(self):
        self.assertEqual(self.headers['score_header'], 'X-yoursite-MailScanner-SpamScore')
        self.assertEqual(self.headers['flags'][0], ['X-Spam-Status', 'Yes*'])
        self.assertEqual(self.headers['required'], 6.0)
        self.assertEqual(self.headers['high_actions'], 'store')
        self.assertFalse(self.headers['score_numeric'])

    def test_move_spam(self):
        script = svc.render(settings(spam={'move_spam': True}), 'a@b.com', self.headers)
        self.assertIn('header :matches "X-Spam-Status" "Yes*"', script)
        self.assertIn('header :matches "X-Spam-Flag" "YES"', script)
        self.assertIn('fileinto :create "INBOX.Junk";', script)
        self.assertIn('require ["fileinto", "mailbox"];', script)

    def test_star_threshold_junk_and_discard(self):
        junk = svc.render(settings(spam={'threshold': 5}), 'a@b.com', self.headers)
        self.assertIn('header :matches "X-yoursite-MailScanner-SpamScore" "sssss*"', junk)
        self.assertIn('fileinto :create "INBOX.Junk"', junk)
        discard = svc.render(settings(spam={'move_spam': True, 'threshold': 8, 'threshold_action': 'discard'}),
                             'a@b.com', self.headers)
        self.assertLess(discard.index('discard;'), discard.index('fileinto :create'))  # discard threshold first
        self.assertIn('"ssssssss*"', discard)

    def test_numeric_score_header(self):
        headers = svc.mailscanner_headers(LIVE_MAILSCANNER.replace('Instead Of Stars = no', 'Instead Of Stars = yes'))
        script = svc.render(settings(spam={'threshold': 7}), 'a@b.com', headers)
        self.assertIn(':comparator "i;ascii-numeric"', script)
        self.assertIn('not header :matches "X-yoursite-MailScanner-SpamScore" "-*"', script)
        self.assertIn('"comparator-i;ascii-numeric"', script)

    def test_lists(self):
        clean = svc.clean_spam({'move_spam': True, 'allow': ['Boss@Corp.com', '@partner.org'],
                                'block': 'spam.example\n@junk.net x@y.com'})
        self.assertEqual(clean['allow'], ['boss@corp.com', '@partner.org'])
        self.assertEqual(clean['block'], ['@spam.example', '@junk.net', 'x@y.com'])
        script = svc.render({'vacation': dict(svc.DEFAULT_VACATION), 'spam': clean}, 'a@b.com', self.headers)
        self.assertIn('if anyof(address :all :is "from" "x@y.com", address :domain :is "from" ["spam.example", '
                      '"junk.net"]) {', script)
        self.assertIn('if not anyof(address :all :is "from" "boss@corp.com", address :domain :is "from" '
                      '"partner.org") {', script)
        with self.assertRaisesRegex(SieveError, 'both lists'):
            svc.clean_spam({'allow': ['a@b.com'], 'block': ['A@b.com']})
        for bad in ('a"b@c.com', 'x@y', '@'):
            with self.assertRaises(SieveError):
                svc.clean_sender(bad)

    def test_folder_validation(self):
        with self.assertRaises(SieveError):
            svc.clean_spam({'folder': 'a"b'})
        with self.assertRaises(SieveError):
            svc.clean_spam({'folder': 'inbox'})
        script = svc.render(settings(spam={'move_spam': True, 'folder': 'Spam Mail'}), 'a@b.com')
        self.assertIn('"INBOX.Spam Mail"', script)


class Ordering(SimpleTestCase):
    def test_block_then_spam_then_vacation(self):
        script = svc.render(settings({'enabled': True, 'body': 'away'},
                                     {'move_spam': True, 'block': ['@bad.com'], 'allow': ['@good.com']}), 'a@b.com')
        positions = [script.index(marker) for marker in ('# 1. Block', '# 2. Spam', '# 3. Autoresponder')]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(svc.MANAGED_ORDER, ('block', 'spam', 'vacation'))
        # The blocked/spam branches end the script; the autoresponder keeps (no fileinto/discard after it).
        tail = script[script.index('# 3. Autoresponder'):]
        self.assertNotIn('discard', tail)
        self.assertNotIn('fileinto', tail)
        self.assertNotIn('keep;', tail)

    def test_nothing_on_renders_nothing(self):
        self.assertIsNone(svc.render(settings(), 'a@b.com'))
        self.assertIsNone(svc.render(settings({'enabled': False, 'body': 'x'}), 'a@b.com'))

    def test_require_line_lists_only_what_is_used(self):
        script = svc.render(settings({'enabled': True, 'body': 'b'}), 'a@b.com')
        self.assertIn('require "vacation";', script)

    def test_dropin_uses_sieve_before_and_keeps_personal_scripts(self):
        text = svc.dovecot_dropin()
        self.assertIn('sieve_before = /home/vmail/%d/%n/sieve-managed/managed.sieve', text)
        self.assertIn('sieve = file:/home/vmail/%d/%n/sieve;active=/home/vmail/%d/%n/.dovecot.sieve', text)
        self.assertIn('mail_home = /home/vmail/%d/%n', text)
        self.assertIn('mail_plugins = $mail_plugins sieve', text)
        self.assertIn('!include_try %s' % svc.DROPIN_PATH, text)

    def test_live_dovecot_problems(self):
        problems = svc.dovecot_problems(LIVE_DOVECONF, False, 'protocols = imap pop3\n')
        joined = ' '.join(problems)
        for phrase in ('Pigeonhole', 'protocol lda', 'sieve_before', 'home directory', 'does not include'):
            self.assertIn(phrase, joined)
        ready = LIVE_DOVECONF.replace('  mail_plugins = zlib\n', '  mail_plugins = zlib sieve\n') + \
            'mail_home = /home/vmail/%d/%n\nplugin {\n  sieve_before = /home/vmail/%d/%n/sieve-managed/managed.sieve\n}\n'
        self.assertEqual(svc.dovecot_problems(ready, True, '!include_try %s\n' % svc.DROPIN_PATH), [])


class Writer(SimpleTestCase):
    """actions.save/status against a temporary /home/vmail tree owned by the test user."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, 'b.com', 'a'))
        self.dir = os.path.join(self.root, 'b.com', 'a', svc.MANAGED_DIR)

    def _compiler(self, ok=True):
        def run(argv, **kwargs):
            self.argv, self.kwargs = argv, kwargs
            if ok:
                open(argv[2], 'w').write('binary')
            return SimpleNamespace(returncode=0 if ok else 1, stdout='' if ok else 'line 3: error: unknown command')
        return run

    def test_save_compiles_as_vmail_and_installs(self):
        result = actions.save('a@b.com', {'vacation': {'enabled': True, 'body': 'away'}}, root=self.root, today=TODAY,
                              sievec='/usr/bin/sievec', runner=self._compiler())
        self.assertTrue(result['compiled'])
        self.assertEqual(self.kwargs['user'], os.getuid())
        self.assertEqual(sorted(os.listdir(self.dir)), sorted([svc.BINARY_NAME, svc.SCRIPT_NAME, svc.SETTINGS_NAME]))
        self.assertIn('vacation', open(os.path.join(self.dir, svc.SCRIPT_NAME)).read())
        self.assertEqual(oct(os.stat(self.dir).st_mode & 0o777), '0o700')
        status = actions.status('a@b.com', root=self.root, today=TODAY)
        self.assertTrue(status['settings']['vacation']['enabled'])
        self.assertTrue(status['vacation_active'])

    def test_failed_compile_keeps_the_previous_script(self):
        actions.save('a@b.com', {'vacation': {'enabled': True, 'body': 'first'}}, root=self.root, today=TODAY,
                     sievec='/usr/bin/sievec', runner=self._compiler())
        with self.assertRaisesRegex(SieveError, 'did not compile'):
            actions.save('a@b.com', {'vacation': {'enabled': True, 'body': 'second'}}, root=self.root, today=TODAY,
                         sievec='/usr/bin/sievec', runner=self._compiler(ok=False))
        self.assertIn('"first"', open(os.path.join(self.dir, svc.SCRIPT_NAME)).read())
        self.assertNotIn('.tmp', ' '.join(os.listdir(self.dir)))

    def test_without_pigeonhole_saves_and_says_so(self):
        result = actions.save('a@b.com', {'spam': {'move_spam': True}}, root=self.root, today=TODAY, sievec='')
        self.assertFalse(result['compiled'])
        self.assertIn('Pigeonhole', result['note'])

    def test_all_off_removes_the_script(self):
        actions.save('a@b.com', {'spam': {'move_spam': True}}, root=self.root, today=TODAY, sievec='')
        result = actions.save('a@b.com', {}, root=self.root, today=TODAY, sievec='')
        self.assertIsNone(result['script'])
        self.assertEqual(os.listdir(self.dir), [svc.SETTINGS_NAME])

    def test_refuses_symlinked_mailbox_dirs(self):
        other = tempfile.mkdtemp()
        os.symlink(other, os.path.join(self.root, 'b.com', 'link'))
        with self.assertRaises(OSError):
            actions.save('link@b.com', {'spam': {'move_spam': True}}, root=self.root, today=TODAY, sievec='')
        self.assertEqual(os.listdir(other), [])

    def test_missing_mailbox_dir(self):
        with self.assertRaisesRegex(SieveError, 'does not exist yet'):
            actions.save('nobody@b.com', {}, root=self.root, today=TODAY, sievec='')


# ----------------------------------------------------------------------------- ownership (web side)

def _mailbox(email, site):
    owner = SimpleNamespace(domain=site)
    return SimpleNamespace(email=email, emailOwner_id=email.split('@')[1],
                           emailOwner=SimpleNamespace(domainOwner_id=1, domainOwner=owner, childOwner_id=None))


def call(view, body, acl, owned=('mine.com',), boxes=None):
    boxes = boxes or {'me@mine.com': _mailbox('me@mine.com', 'mine.com'),
                      'x@other.net': _mailbox('x@other.net', 'other.net')}
    request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
    request.session = {'userID': 7}

    class Query:
        def get(self, email):
            from mailServer.models import EUsers
            if email not in boxes:
                raise EUsers.DoesNotExist()
            return boxes[email]

    def owns(domain, admin, acl_):
        return 1 if acl_.get('admin') == 1 or domain in owned else 0

    with mock.patch('universalAddons.autoresponder.views.ACLManager.loadedACL', return_value=acl), \
            mock.patch('universalAddons.access.ACLManager.checkOwnership', side_effect=owns), \
            mock.patch('loginSystem.models.Administrator.objects.get', return_value=SimpleNamespace(pk=7)), \
            mock.patch('mailServer.models.EUsers.objects.select_related', return_value=Query()), \
            mock.patch('universalAddons.autoresponder.views.privileged.call',
                       return_value={'ok': True}) as privileged_call:
        response = view(request)
    return response.status_code, json.loads(response.content), privileged_call


class Ownership(SimpleTestCase):
    USER = {'admin': 0, 'emailForwarding': 1}

    def test_owner_reads_own_mailbox(self):
        code, body, privileged_call = call(views.get, {'email': 'me@mine.com'}, self.USER)
        self.assertEqual((code, body['status']), (200, 1))
        privileged_call.assert_called_once_with('autoresponder', 'status', email='me@mine.com')

    def test_foreign_and_unknown_mailboxes_look_the_same(self):
        for email in ('x@other.net', 'ghost@mine.com'):
            code, body, privileged_call = call(views.save, {'email': email, 'vacation': {}}, self.USER)
            self.assertEqual(code, 403)
            self.assertIn('You do not manage', body['error_message'])
            privileged_call.assert_not_called()

    def test_acl_without_email_permission_is_refused(self):
        code, body, _ = call(views.get, {'email': 'me@mine.com'}, {'admin': 0, 'emailForwarding': 0})
        self.assertEqual(code, 403)

    def test_admin_any_mailbox_and_health_admin_only(self):
        code, _, _ = call(views.get, {'email': 'x@other.net'}, {'admin': 1})
        self.assertEqual(code, 200)
        code, _, _ = call(views.health, {}, self.USER)
        self.assertEqual(code, 403)

    def test_save_validates_before_calling_root(self):
        code, body, privileged_call = call(views.save, {'email': 'me@mine.com',
                                                        'vacation': {'start': '2026-12-02', 'end': '2026-12-01'}},
                                           self.USER)
        self.assertEqual(code, 400)
        privileged_call.assert_not_called()
        code, body, privileged_call = call(views.save, {'email': 'me@mine.com', 'spam': {'move_spam': True}}, self.USER)
        self.assertEqual(code, 200)
        sent = privileged_call.call_args[1]['settings']
        self.assertTrue(sent['spam']['move_spam'])


class PageRenders(SimpleTestCase):
    def test_page_renders(self):
        request = RequestFactory().get('/addons/autoresponder/')
        request.session = {}
        html = render_to_string('universalAddons/autoresponder.html', {
            'request': request, 'is_admin': True, 'mailbox': 'me@mine.com', 'max_body': 8000, 'max_subject': 200,
            'panel_brand': 'IndiansCloud'})
        self.assertIn('ua-wrap', html)
        self.assertIn('IndiansCloud', html)
        self.assertIn('ar-dropin', html)
        self.assertTrue(re.search(r'data-base="/addons/autoresponder/"', html))
