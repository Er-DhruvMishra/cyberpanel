from pathlib import Path

from django.test import SimpleTestCase

from serverStatus.views import parseLshttpdVersion

ROOT = Path(__file__).resolve().parents[1]

LSHTTPD_V = (
    'LiteSpeed/1.9.4 Open (BUILD built: Wed Oct 28 16:03:52 UTC 2026) \n'
    '\tmodule versions:\n'
    '\tlsquic 4.11.1\n'
    '\tmodgzip 1.1\n'
    '\tcache 1.66\n'
    '\tmod_security 1.4 (with libmodsecurity v3.0.15)\n'
    '\n'
    '  \x00\n'
)


class LshttpdVersionParserTests(SimpleTestCase):
    def test_blank_lines_are_not_modules(self):
        version, heading, modules = parseLshttpdVersion(LSHTTPD_V)
        self.assertEqual(version, 'LiteSpeed/1.9.4 Open (BUILD built: Wed Oct 28 16:03:52 UTC 2026)')
        self.assertEqual(heading, 'module versions:')
        self.assertEqual(modules, ['lsquic 4.11.1', 'modgzip 1.1', 'cache 1.66',
                                   'mod_security 1.4 (with libmodsecurity v3.0.15)'])

    def test_empty_output(self):
        self.assertEqual(parseLshttpdVersion(''), ('', '', []))
        self.assertEqual(parseLshttpdVersion(None), ('', '', []))


class LitespeedStatusHeaderIconTests(SimpleTestCase):
    def test_header_icon_is_a_font_awesome_6_glyph_styled_by_the_theme(self):
        page = (ROOT / 'serverStatus/templates/serverStatus/litespeedStatus.html').read_text()
        start = page.index('<div class="page-header">')
        header = page[start:page.index('page-subtitle', start)]
        # A white-filtered PNG vanished on the theme's transparent header.
        self.assertNotIn('<img', header)
        self.assertIn('<i class="fas fa-server"', header)
        css = (ROOT / 'baseTemplate/static/baseTemplate/css/cyberpanel-evergreen.css').read_text()
        self.assertIn('.header-icon, .server-icon) {', css)
