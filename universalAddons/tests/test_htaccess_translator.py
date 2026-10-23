import re
import unittest

from universalAddons.htaccess import translator as tr

HOME = '/home/example.com'
DOC = '/home/example.com/public_html'


def run(files):
    result = tr.translate(files, HOME, DOC)
    return result, tr.render_vhost_block(result)


def statuses(result):
    return {(r['directive'].split()[0].lower(), r['status']) for r in result.report}


class Parsing(unittest.TestCase):
    def test_sections_quotes_continuations_comments(self):
        tree = tr.parse('# comment\n<IfModule mod_headers.c>\n  Header set X-A "a b"\n</IfModule>\n'
                        'php_value memory_limit \\\n  256M\n')
        ifmod, php = tree['children']
        self.assertEqual((ifmod['name'], ifmod['args']), ('ifmodule', ['mod_headers.c']))
        self.assertEqual(ifmod['children'][0]['args'], ['set', 'X-A', 'a b'])
        self.assertEqual((php['name'], php['args'], php['line']), ('php_value', ['memory_limit', '256M'], 5))

    def test_tokenize_keeps_regex_backslashes(self):
        self.assertEqual(tr.tokenize(r'RewriteRule ^(.*)\.php$ /x [L]'), ['RewriteRule', r'^(.*)\.php$', '/x', '[L]'])


class Security(unittest.TestCase):
    """The site owner controls .htaccess; nothing in it may escape into vhost.conf syntax."""

    def assertNoInjection(self, block):
        for needle in ('/etc/shadow', 'extprocessor', 'evil', 'END_extraHeaders\nHeader set Pwn'):
            self.assertNotIn(needle, block)

    def test_header_value_cannot_break_out(self):
        result, block = run({'': 'Header set X-A "ok}\\nextprocessor evil {"\nHeader set X-B "v END_extraHeaders"\n'})
        self.assertNoInjection(block)
        self.assertIn(('header', 'refused'), statuses(result))

    def test_dangerous_php_settings_refused(self):
        result, block = run({'': 'php_admin_value open_basedir /\nphp_value disable_functions ""\n'
                                 'php_value auto_prepend_file /home/other/x.php\nphp_value extension evil.so\n'
                                 'php_value memory_limit 512M\n'})
        self.assertIn('php_value memory_limit 512M', block)
        for name in ('open_basedir', 'disable_functions', 'auto_prepend_file', 'extension'):
            self.assertNotIn(name, block)
        self.assertEqual(sum(1 for r in result.report if r['status'] == 'refused'), 4)

    def test_php_value_injection(self):
        result, block = run({'': 'php_value memory_limit "1}\nphp_value x y"\nphp_value upload_max_filesize 64M{\n'})
        self.assertNotIn('upload_max_filesize', block)

    def test_auth_user_file_confined_to_home(self):
        result, block = run({'admin': 'AuthType Basic\nAuthName "Staff"\nAuthUserFile /etc/shadow\nRequire valid-user\n'})
        self.assertNotIn('/etc/shadow', block)
        self.assertNotIn('realm cpua_', block)
        result, block = run({'admin': 'AuthType Basic\nAuthUserFile /home/example.com/../other/.htpasswd\nRequire valid-user\n'})
        self.assertNotIn('realm cpua_', block)

    def test_errordocument_inline_text_and_bad_urls_refused(self):
        result, block = run({'': 'ErrorDocument 404 "<script>x</script>"\nErrorDocument 500 javascript:alert(1)\n'})
        self.assertNotIn('errorpage', block)


class Translation(unittest.TestCase):
    def test_php_at_root_goes_to_vhost_and_subdir_to_context(self):
        result, block = run({'': 'php_value upload_max_filesize 64M\nphp_flag display_errors off\n',
                             'shop': 'php_value max_execution_time 300\n'})
        top = block.split('context ')[0]
        self.assertIn('php_value upload_max_filesize 64M', top)
        self.assertIn('php_flag display_errors off', top)
        self.assertIn('context /shop/ {', block)
        self.assertIn('    php_value max_execution_time 300', block.split('context /shop/ {', 1)[1])

    def test_headers_in_root_context(self):
        result, block = run({'': '<IfModule mod_headers.c>\nHeader always set X-Frame-Options "SAMEORIGIN"\n'
                                 'Header unset X-Powered-By\nRequestHeader set X-Proto https\n</IfModule>\n'})
        self.assertIn('context / {', block)
        self.assertIn('Header set X-Frame-Options "SAMEORIGIN"', block)
        self.assertIn('Header unset X-Powered-By', block)
        self.assertIn('RequestHeader set X-Proto "https"', block)
        self.assertIn('extraHeaders            <<<END_extraHeaders', block)

    def test_access_apache22_and_24(self):
        def access(text):
            result = tr.translate({'private': text}, HOME, DOC)
            return next(s for s in result.contexts if s.uri == '/private/').access()
        self.assertEqual(access('Order deny,allow\nDeny from all\nAllow from 10.0.0.0/8 192.168.1\n'),
                         (['10.0.0.0/8', '192.168.1.0/24'], ['ALL']))
        self.assertEqual(access('Order allow,deny\nAllow from all\nDeny from 203.0.113.9\n'),
                         (['ALL'], ['203.0.113.9']))
        self.assertEqual(access('Require all denied\n'), ([], ['ALL']))
        self.assertEqual(access('Require ip 198.51.100.0/24 2001:db8::1\n'), (['198.51.100.0/24', '2001:db8::1'], ['ALL']))
        self.assertEqual(access('Require all granted\nRequire not ip 203.0.113.7\n'), (['ALL'], ['203.0.113.7']))

    def test_hostnames_in_allow_are_reported(self):
        result, _ = run({'x': 'Order deny,allow\nDeny from all\nAllow from trusted.example.org 10.1.2.3\n'})
        self.assertIn(('allow', 'partial'), statuses(result))

    def test_basic_auth(self):
        result, block = run({'admin': 'AuthType Basic\nAuthName "Staff only"\n'
                                      'AuthUserFile /home/example.com/.htpasswd\nRequire user alice bob\n'})
        realm = re.search(r'realm (cpua_[0-9a-f]+) \{', block).group(1)
        self.assertIn('location              /home/example.com/.htpasswd', block)
        ctx = block.split('context /admin/ {', 1)[1]
        self.assertIn('realm                   %s' % realm, ctx)
        self.assertIn('required                user alice bob', ctx)
        self.assertIn('authName                Staff only', ctx)

    def test_files_and_filesmatch_contexts(self):
        result, block = run({'': '<Files wp-config.php>\nRequire all denied\n</Files>\n'
                                 '<FilesMatch "\\.(ini|log|sh)$">\nOrder allow,deny\nDeny from all\n</FilesMatch>\n'})
        regexes = [s.uri[4:] for s in result.contexts if s.is_regex]
        self.assertEqual(len(regexes), 2)
        files_rx = next(r for r in regexes if 'config' in r)
        self.assertTrue(re.match(files_rx, '/wp-config.php'))
        self.assertTrue(re.match(files_rx, '/sub/wp-config.php'))
        self.assertFalse(re.match(files_rx, '/wp-config.php.bak'))
        match_rx = next(r for r in regexes if 'ini' in r)
        self.assertTrue(re.match(match_rx, '/logs/error.log'))
        self.assertFalse(re.match(match_rx, '/index.php'))
        self.assertFalse(re.match(match_rx, '/logs/error.log/x'))
        anchored = tr.translate({'': '<FilesMatch "^wp-">\nRequire all denied\n</FilesMatch>\n'}, HOME, DOC)
        rx = next(s.uri[4:] for s in anchored.contexts if s.is_regex)
        self.assertTrue(re.match(rx, '/wp-login.php'))
        self.assertFalse(re.match(rx, '/my-wp-login.php'))
        self.assertEqual(block.count('deny                  ALL'), 2)

    def test_expires(self):
        result, block = run({'': 'ExpiresActive On\nExpiresByType image/png "access plus 1 month"\n'
                                 'ExpiresByType text/css "access plus 1 week 2 days"\nExpiresDefault A3600\n'})
        self.assertIn('enableExpires           1', block)
        self.assertIn('expiresByType           image/png=A2592000, text/css=A777600', block)
        self.assertIn('expiresDefault          A3600', block)

    def test_errordocument(self):
        result, block = run({'': 'ErrorDocument 404 /not-found.html\nErrorDocument 503 https://status.example.com/\n'})
        self.assertIn('errorpage 404 {\n  url                     /not-found.html\n}', block)
        self.assertIn('errorpage 503', block)

    def test_rewrite_rules_are_native_and_untouched(self):
        result, block = run({'': 'RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]\n'})
        self.assertEqual(statuses(result), {('rewriteengine', 'native'), ('rewriterule', 'native')})
        self.assertEqual(block.strip(), tr.MARK_BEGIN + '\n\n' + tr.MARK_END)

    def test_unknown_directives_are_reported_not_dropped_silently(self):
        result, _ = run({'': 'AddHandler application/x-httpd-php .html\nSetEnvIf User-Agent bot is_bot\n'})
        self.assertEqual({r['status'] for r in result.report}, {'unsupported'})
        self.assertEqual([r['line'] for r in result.report], [1, 2])


class Redirects(unittest.TestCase):
    def rule(self, line):
        result = tr.translate({'': line}, HOME, DOC)
        self.assertEqual(len(result.redirects.get('', [])), 1, result.report)
        return result.redirects[''][0].split(' ')

    def test_redirect_prefix_semantics(self):
        _, pattern, target, flag = self.rule('Redirect 301 /old https://example.org/new')
        self.assertEqual(flag, '[R=301,L]')
        self.assertTrue(re.match(pattern, 'old'))
        self.assertEqual(re.sub(pattern, target.replace('$1', r'\1'), 'old/a/b'), 'https://example.org/new/a/b')
        self.assertFalse(re.match(pattern, 'oldfoo'))

    def test_redirect_permanent_gone_and_match(self):
        self.assertEqual(self.rule('RedirectPermanent /a/ /b/')[3], '[R=301,L]')
        self.assertEqual(self.rule('Redirect gone /removed')[2:], ['-', '[G,L]'])
        _, pattern, target, _ = self.rule('RedirectMatch 302 ^/(.*)\\.html$ /$1.php')
        self.assertTrue(re.match(pattern, 'page.html'))
        self.assertEqual(target, '/$1.php')

    def test_redirects_written_to_managed_htaccess_block(self):
        original = '# BEGIN WordPress\nRewriteRule . /index.php [L]\n# END WordPress\n'
        updated = tr.apply_redirects(original, ['RewriteRule ^a$ /b [R=301,L]'])
        self.assertTrue(updated.startswith(tr.HT_BEGIN + '\nRewriteEngine On\n'))
        self.assertTrue(updated.endswith(original))
        self.assertEqual(tr.apply_redirects(updated, []), original)
        self.assertEqual(tr.apply_redirects(tr.apply_redirects(updated, ['x']), ['x']).count(tr.HT_BEGIN), 1)

    def test_bad_redirects(self):
        for line in ('Redirect 301 /a', 'Redirect 999 /a /b', 'Redirect /a javascript:x', 'Redirect /a"} /b'):
            result = tr.translate({'': line}, HOME, DOC)
            self.assertFalse(result.redirects, line)


class BruteForce(unittest.TestCase):
    def test_official_directive_names(self):
        result = tr.translate({'': 'BruteForceProtection On\nBruteForceAllowedAttempts 5\nBruteForceWindow 600\n'
                                   'BruteForceAction throttle\nBruteForceWhitelist 10.0.0.1 192.168.0.0/16\n'
                                   'BruteForceProtectPath /admin/login.php\n'}, HOME, DOC)
        self.assertEqual(result.bruteforce, {'enabled': True, 'attempts': 5, 'window': 600, 'action': 'throttle',
                                             'whitelist': ['10.0.0.1', '192.168.0.0/16'],
                                             'paths': ['/admin/login.php'], 'xff': False})

    def test_defaults(self):
        result = tr.translate({'': 'BruteForceProtection On\n'}, HOME, DOC)
        self.assertEqual((result.bruteforce['attempts'], result.bruteforce['window'], result.bruteforce['paths']),
                         (10, 300, ['/wp-login.php', '/xmlrpc.php']))


SAMPLE_VHOST = """docRoot                   $VH_ROOT/public_html

phpIniOverride  {
php_value memory_limit 256M
}

rewrite  {
 enable                  1
  autoLoadHtaccess        1
}

context /.well-known/acme-challenge {
  location                /usr/local/lsws/Example/html/.well-known/acme-challenge
  phpIniOverride  {

  }
}

vhssl  {
  keyFile                 /etc/letsencrypt/live/example.com/privkey.pem
}
"""


class VhostEditing(unittest.TestCase):
    def test_apply_merges_php_and_is_idempotent(self):
        result = tr.translate({'': 'php_value upload_max_filesize 64M\nHeader set X-A b\n'}, HOME, DOC)
        once = tr.apply_to_vhost(SAMPLE_VHOST, result)
        twice = tr.apply_to_vhost(once, result)
        self.assertEqual(once, twice)
        self.assertEqual(once.count(tr.MARK_BEGIN), 1)
        managed = once.split(tr.MARK_BEGIN, 1)[1]
        self.assertIn('# preserved from vhost.conf\nphp_value memory_limit 256M\n# from .htaccess\n'
                      'php_value upload_max_filesize 64M', managed)
        top_level = [l for l in once.splitlines() if l.startswith('phpIniOverride')]
        self.assertEqual(len(top_level), 1, 'exactly one vhost-level phpIniOverride')
        self.assertIn('context /.well-known/acme-challenge {\n  location', once, 'other blocks untouched')
        self.assertLess(once.index(tr.MARK_END), once.index('vhssl'), 'managed block goes before vhssl')
        self.assertEqual(once.count('{'), once.count('}'))

    def test_removing_everything_restores_original_php(self):
        result = tr.translate({'': 'php_value upload_max_filesize 64M\n'}, HOME, DOC)
        applied = tr.apply_to_vhost(SAMPLE_VHOST, result)
        cleared = tr.apply_to_vhost(applied, tr.translate({}, HOME, DOC))
        self.assertIn('php_value memory_limit 256M', cleared)
        self.assertNotIn('upload_max_filesize', cleared)

    def test_nothing_to_translate_leaves_vhost_byte_identical(self):
        result = tr.translate({'': 'RewriteEngine On\nRewriteRule ^a$ /b [L]\n'}, HOME, DOC)
        self.assertEqual(tr.apply_to_vhost(SAMPLE_VHOST, result), SAMPLE_VHOST)

    def test_headers_only_keeps_vhost_php_block_in_place(self):
        result = tr.translate({'': 'Header set X-A b\n'}, HOME, DOC)
        applied = tr.apply_to_vhost(SAMPLE_VHOST, result)
        self.assertIn('phpIniOverride  {\nphp_value memory_limit 256M\n}', applied.split(tr.MARK_BEGIN)[0])
        self.assertNotIn(tr.PRESERVED, applied)

    def test_conflict_detection(self):
        vhost = SAMPLE_VHOST + '\nerrorpage 404 {\n  url /x.html\n}\n'
        result = tr.translate({'': 'ErrorDocument 404 /y.html\n'}, HOME, DOC)
        self.assertEqual(tr.conflicts(vhost, result), ['errorpage 404'])


if __name__ == '__main__':
    unittest.main()
