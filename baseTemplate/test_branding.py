"""Guard: page titles and main headings show the IndiansCloud brand, not the upstream CyberPanel name.

Body text may still name CyberPanel where it means the upstream project or its paid products
(for example "CyberPanel Add-ons", "CyberPanel Ent"); titles, h1 and h2 headings must not.
"""
import re
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = re.compile(r'(?<![A-Za-z0-9_\-/.])Cyber[Pp]anel(?![A-Za-z0-9_\-])')
STRIP = [re.compile(p, re.S) for p in (r'<!--.*?-->', r'\{#.*?#\}', r'\{%\s*url\b[^%]*%\}')]
TAGS = [
    ('<title>', re.compile(r'<title\b[^>]*>(.*?)</title>', re.S | re.I)),
    ('block title', re.compile(r'\{%\s*block\s+title\s*%\}(.*?)\{%\s*endblock', re.S)),
    ('h1', re.compile(r'<h1\b[^>]*>(.*?)</h1>', re.S | re.I)),
    ('h2', re.compile(r'<h2\b[^>]*>(.*?)</h2>', re.S | re.I)),
]


def templates():
    for path in sorted(ROOT.glob('*/templates/**/*.html')):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith('static/'):
            continue
        yield rel, path
    yield 'index.html', ROOT / 'index.html'


def offences(text):
    for pattern in STRIP:
        text = pattern.sub('', text)
    found = []
    for label, pattern in TAGS:
        for match in pattern.finditer(text):
            if UPSTREAM.search(match.group(1)):
                line = text.count('\n', 0, match.start()) + 1
                found.append('%s (line ~%d): %s' % (label, line, ' '.join(match.group(1).split())[:120]))
    return found


class BrandingGuard(SimpleTestCase):
    def test_titles_and_headings_use_indianscloud(self):
        problems = []
        for rel, path in templates():
            if not path.is_file():
                continue
            for item in offences(path.read_text(encoding='utf-8', errors='replace')):
                problems.append('%s: %s' % (rel, item))
        self.assertEqual(problems, [], 'Upstream name in a title or heading:\n' + '\n'.join(problems))

    def test_guard_detects_the_upstream_name(self):
        self.assertTrue(offences('{% block title %}{% trans "Users - CyberPanel" %}{% endblock %}'))
        self.assertTrue(offences('<h2 class="x">CyberPanel Version Control</h2>'))
        self.assertTrue(offences('<title>Webmail - CyberPanel</title>'))
        self.assertFalse(offences('{% block title %}{% trans "Users - IndiansCloud" %}{% endblock %}'))
        self.assertFalse(offences('<h2><!-- CyberPanel --><a href="{% url \'CyberPanelPort\' %}">Port</a></h2>'))

    def test_base_title_suffix_is_indianscloud(self):
        base = (ROOT / 'baseTemplate/templates/baseTemplate/index.html').read_text(encoding='utf-8')
        self.assertIn("' - IndiansCloud'", base)
        self.assertNotIn("' - CyberPanel'", base)
