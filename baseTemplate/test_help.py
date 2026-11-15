"""Local help centre (baseTemplate/help) and the guard against links to cyberpanel.net."""
import re
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.http import HttpResponse
from django.template.loader import get_template
from django.conf import settings
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import reverse

from baseTemplate import helpCentre, views

ROOT = Path(__file__).resolve().parents[1]


class CapturingProc:
    """Stands in for plogical.httpProc: records the template and data, renders nothing."""
    calls = []

    def __init__(self, request, template, data=None, function=None):
        CapturingProc.calls.append((template, data, function))

    def render(self):
        return HttpResponse('rendered')


def get(path, session=None):
    request = RequestFactory().get(path)
    request.session = {'userID': 1} if session is None else session
    return request


class HelpViews(SimpleTestCase):
    def setUp(self):
        CapturingProc.calls = []
        patcher = mock.patch('baseTemplate.views.httpProc', CapturingProc)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_urls(self):
        self.assertEqual(reverse('helpIndex'), '/base/help/')
        self.assertEqual(reverse('help', args=['dkim']), '/base/help/dkim')

    def test_index_lists_every_article(self):
        response = views.helpIndex(get('/base/help/'))
        self.assertEqual(response.status_code, 200)
        template, data, function = CapturingProc.calls[0]
        self.assertEqual(template, 'baseTemplate/helpIndex.html')
        self.assertIsNone(function)  # every signed-in user may read help
        listed = [a['slug'] for c in data['categories'] for a in c['articles']]
        on_disk = sorted(p.stem for p in helpCentre.HELP_DIR.glob('*.md'))
        self.assertEqual(sorted(listed), on_disk)
        self.assertEqual(len(listed), len(set(listed)))
        self.assertGreaterEqual(len(listed), 40)
        for category in data['categories']:
            for article in category['articles']:
                self.assertTrue(article['title'] and article['summary'], article['slug'])

    def test_categories_name_only_existing_files(self):
        for _, slugs in helpCentre.CATEGORIES:
            for slug in slugs:
                self.assertIsNotNone(helpCentre.article_path(slug), slug)

    def test_known_slug_renders(self):
        response = views.helpArticle(get('/base/help/dkim'), 'dkim')
        self.assertEqual(response.status_code, 200)
        template, data, _ = CapturingProc.calls[0]
        self.assertEqual(template, 'baseTemplate/helpArticle.html')
        self.assertEqual(data['article']['title'], 'DKIM')
        self.assertIn('<h2>Steps</h2>', data['article']['html'])
        self.assertIn('<a href="/addons/email-debugger/">Email Debugger</a>', data['article']['html'])

    def test_unknown_slug_is_404(self):
        response = views.helpArticle(get('/base/help/no-such-topic'), 'no-such-topic')
        self.assertEqual(response.status_code, 404)
        self.assertIsNone(CapturingProc.calls[0][1]['article'])

    def test_change_log_carries_commits_or_fallback(self):
        with mock.patch('baseTemplate.helpCentre.recent_commits', return_value=None):
            views.helpArticle(get('/base/help/change-logs'), 'change-logs')
        data = CapturingProc.calls[0][1]
        self.assertIsNone(data['commits'])
        self.assertTrue(data['commits_url'].startswith('https://github.com/'))

    def test_login_required(self):
        for call in (lambda r: views.helpIndex(r), lambda r: views.helpArticle(r, 'dkim'),
                     lambda r: views.helpArticle(r, 'no-such-topic')):
            response = call(get('/base/help/', session={}))
            self.assertEqual(response.status_code, 302)
        self.assertEqual(CapturingProc.calls, [])


def _templates_without_db():
    """TEMPLATES with the cosmetic context processor (which reads the database) left out."""
    templates = []
    for engine in settings.TEMPLATES:
        engine = dict(engine, OPTIONS=dict(engine.get('OPTIONS', {})))
        engine['OPTIONS']['context_processors'] = [
            p for p in engine['OPTIONS'].get('context_processors', []) if not p.endswith('cosmetic_context')]
        templates.append(engine)
    return templates


@override_settings(TEMPLATES=_templates_without_db())
class HelpTemplates(SimpleTestCase):
    """The real templates parse and render inside the panel layout."""

    def render(self, name, context):
        request = get('/base/help/')
        return get_template(name).render(context, request)

    def test_index_template(self):
        html = self.render('baseTemplate/helpIndex.html', {'categories': helpCentre.index()})
        self.assertIn('href="/base/help/dkim"', html)
        self.assertIn('Help centre', html)

    def test_article_and_not_found_templates(self):
        html = self.render('baseTemplate/helpArticle.html', {'article': helpCentre.load_article('email-queue')})
        self.assertIn('Mail queue', html)
        html = self.render('baseTemplate/helpArticle.html', {'article': None})
        self.assertIn('href="/base/help/"', html)
        self.assertIn('Browse all help topics', html)

    def test_change_log_template(self):
        commits = [{'hash': 'abc1234', 'date': '2026-11-01', 'subject': 'Fix <b>things</b>'}]
        html = self.render('baseTemplate/helpArticle.html', {
            'article': helpCentre.load_article('change-logs'), 'commits': commits,
            'commits_url': helpCentre.CHANGELOG_FALLBACK})
        self.assertIn('abc1234', html)
        self.assertIn('Fix &lt;b&gt;things&lt;/b&gt;', html)


class Slugs(SimpleTestCase):
    def test_only_lowercase_digits_and_hyphens(self):
        self.assertTrue(helpCentre.valid_slug('mail-server-ssl'))
        for bad in ('', '../urls', '..', '.', 'a/b', 'a\\b', 'DKIM', 'dkim.md', 'dkim ', '%2e%2e', 'dkim\x00',
                    '/etc/passwd', 'a' * 81, None, 5):
            self.assertFalse(helpCentre.valid_slug(bad), repr(bad))
            self.assertIsNone(helpCentre.load_article(bad), repr(bad))

    def test_no_path_traversal(self):
        # A file outside the help directory is never loaded, whatever the slug looks like.
        self.assertTrue((ROOT / 'baseTemplate' / 'urls.py').exists())
        for slug in ('../urls', '..%2furls', 'help/../../baseTemplate/urls'):
            self.assertIsNone(helpCentre.load_article(slug))
        with mock.patch('baseTemplate.views.httpProc', CapturingProc):
            self.assertEqual(views.helpArticle(get('/base/help/x'), '../urls').status_code, 404)

    def test_every_template_help_link_exists(self):
        pattern = re.compile(r"""\{%\s*url\s+['"]help['"]\s+['"]([^'"]+)['"]\s*%\}""")
        found = 0
        for path in ROOT.rglob('*.html'):
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith('static/') or '/static/' in rel:
                continue
            for slug in pattern.findall(path.read_text(encoding='utf-8', errors='ignore')):
                found += 1
                self.assertIsNotNone(helpCentre.article_path(slug), '%s links to missing help/%s' % (rel, slug))
        self.assertGreater(found, 50)


class Markdown(SimpleTestCase):
    def test_html_is_escaped(self):
        out = helpCentre.render_markdown(
            '# <img src=x onerror=alert(1)>\n\n<script>alert(1)</script> & "q"\n\n'
            '- <b>item</b>\n\n```\n<?php echo 1; ?>\n```\n\n`<i>code</i>` **<u>bold</u>**')
        self.assertNotIn('<script', out)
        self.assertNotIn('<img', out)
        self.assertNotIn('<b>', out)
        self.assertNotIn('<u>', out)
        self.assertNotIn('<?php', out)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;q&quot;', out)
        self.assertIn('<pre><code>&lt;?php echo 1; ?&gt;</code></pre>', out)
        self.assertIn('<code>&lt;i&gt;code&lt;/i&gt;</code>', out)
        self.assertIn('<strong>&lt;u&gt;bold&lt;/u&gt;</strong>', out)

    def test_links_only_with_safe_targets(self):
        out = helpCentre.render_markdown('[a](javascript:alert(1)) [b](//evil.example) [c](/base/help/) '
                                         '[d](https://example.com/x?a=1&b="2") [e](data:text/html,x)')
        self.assertNotIn('javascript:', out.replace('javascript:alert(1)', ''))
        self.assertNotIn('href="javascript', out)
        self.assertNotIn('href="//', out)
        self.assertNotIn('href="data', out)
        self.assertIn('<a href="/base/help/">c</a>', out)
        self.assertIn('href="https://example.com/x?a=1&amp;b=&quot;2&quot;"', out)

    def test_structure(self):
        out = helpCentre.render_markdown('## Steps\n\n1. One\n2. Two\n   continued\n\n- x\n- y\n\nText\nmore')
        self.assertIn('<h2>Steps</h2>', out)
        self.assertIn('<ol><li>One</li><li>Two continued</li></ol>', out)
        self.assertIn('<ul><li>x</li><li>y</li></ul>', out)
        self.assertIn('<p>Text more</p>', out)


class ChangeLog(SimpleTestCase):
    def test_reads_git_subjects(self):
        repo = tempfile.mkdtemp()
        Path(repo, '.git').mkdir()
        run = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout='abc1234\x1f2026-11-01\x1fAdd help centre\nbad line\n'))
        commits = helpCentre.recent_commits(repo=repo, run=run)
        self.assertEqual(commits, [{'hash': 'abc1234', 'date': '2026-11-01', 'subject': 'Add help centre'}])
        args = run.call_args[0][0]
        self.assertEqual(args[:2], ['git', '-c'])
        self.assertIn('--no-merges', args)

    def test_no_checkout_or_git_failure(self):
        self.assertIsNone(helpCentre.recent_commits(repo=tempfile.mkdtemp(), run=mock.Mock()))
        repo = tempfile.mkdtemp()
        Path(repo, '.git').mkdir()
        self.assertIsNone(helpCentre.recent_commits(
            repo=repo, run=mock.Mock(side_effect=subprocess.TimeoutExpired('git', 5))))
        self.assertIsNone(helpCentre.recent_commits(
            repo=repo, run=mock.Mock(return_value=SimpleNamespace(returncode=128, stdout=''))))


# Binaries, packages and data files that the installer, upgrader and server tools download from the
# vendor. They have no local equivalent and are intentionally kept (see the inventory report).
ALLOWED_DOWNLOADS = {
    'https://cyberpanel.net/binaries',  # plogical/modSec.py: base URL of ModSecurity binaries
    'https://cyberpanel.net/modsec/comodo.tar.gz',
    'https://cyberpanel.net/dnsServers.txt',  # plogical/mailUtilities.py: resolver list for rDNS checks
    'https://cyberpanel.net/beautifulNames.zip',  # testPlugin docs: sample plugin archive
    'https://mirror.cyberpanel.net/install-test.sh',  # testPlugin docs: test installer
    'http://mirror.cyberpanel.net/urllib3-1.22.tar.gz',
    'http://mirror.cyberpanel.net/requests-2.18.4.tar.gz',
    'https://rep.cyberpanel.net/pure-ftpd-common_1.0.47-3_all.deb',
    'https://rep.cyberpanel.net/pure-ftpd-mysql_1.0.47-3_amd64.deb',
}
ALLOWED_PATTERNS = (
    re.compile(r'^https://cyberpanel\.net/openlitespeed-[0-9.]+-x86_64-[a-z0-9]+$'),
    re.compile(r'^https://cyberpanel\.net/cyberpanel_ols-[0-9.]+-x86_64-[a-z0-9]+\.so$'),
    re.compile(r'^https://cyberpanel\.net/mod_security-[0-9.]+-x86_64-[a-z0-9]+\.so$'),
)
LINK = re.compile(r"https?://(?:[a-z0-9-]+\.)*cyberpanel\.net[^\"' <>)`\\]*", re.I)


class NoVendorLinks(SimpleTestCase):
    def test_no_links_to_cyberpanel_net_outside_static(self):
        offending = []
        for path in ROOT.rglob('*'):
            if path.suffix not in ('.html', '.js', '.py') or not path.is_file():
                continue
            rel = path.relative_to(ROOT).as_posix()
            parts = rel.split('/')
            if 'static' in parts or 'node_modules' in parts or '.git' in parts:
                continue
            name = parts[-1]
            if name.startswith('test') or 'tests' in parts[:-1]:
                continue  # tests and fixtures may mention the vendor (this file lists the allowed URLs)
            text = path.read_text(encoding='utf-8', errors='ignore')
            for number, line in enumerate(text.splitlines(), 1):
                for url in LINK.findall(line):
                    url = url.rstrip('.,;')
                    if url in ALLOWED_DOWNLOADS or any(p.match(url) for p in ALLOWED_PATTERNS):
                        continue
                    offending.append('%s:%d %s' % (rel, number, url))
        self.assertEqual(offending, [], 'Links to cyberpanel.net remain:\n' + '\n'.join(offending))
