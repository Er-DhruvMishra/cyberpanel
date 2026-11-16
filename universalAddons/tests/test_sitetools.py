"""Site Tools: ACL, managed blocks, validation, htpasswd, path safety, staging rewrite, serialized replace."""
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons.sitetools import actions, service as st, views
from universalAddons.sitetools.service import SiteToolsError
from universalAddons.tests.helpers import FOREIGN, page, post

ON = {'sitetools_for_users': True}


def _ser(value):
    """A tiny PHP serialize() for building test data."""
    if isinstance(value, bytes):
        return b's:%d:"%s";' % (len(value), value)
    if isinstance(value, int):
        return b'i:%d;' % value
    if isinstance(value, list):
        return b'a:%d:{%s}' % (len(value), b''.join(_ser(i) + _ser(v) for i, v in enumerate(value)))
    if isinstance(value, dict):
        return b'a:%d:{%s}' % (len(value), b''.join(_ser(k) + _ser(v) for k, v in value.items()))
    raise TypeError(value)


# ----------------------------------------------------------------------------- ownership / ACL

class Access(SimpleTestCase):
    def setUp(self):
        patcher = mock.patch('universalAddons.privileged.call', return_value={'ok': 1})
        self.call = patcher.start()
        private = mock.patch('universalAddons.privileged.call_private', return_value={'ok': 1})
        self.private = private.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(private.stop)

    def test_switch_off_refuses_users_but_not_admins(self):
        code, data, _ = post(views.overview, {'domain': 'mine.example.com'})
        self.assertEqual(code, 403)
        self.call.assert_not_called()
        code, data, _ = post(views.overview, {'domain': 'mine.example.com'}, admin=True)
        self.assertEqual(code, 200)
        self.assertEqual(self.call.call_args[1]['domains'], None)

    def test_users_only_act_on_their_own_sites(self):
        for view, extra in ((views.overview, {}), (views.redirects, {'rules': []}), (views.hotlink, {'config': {}}),
                            (views.errorpage_save, {'code': '404', 'html': 'x'}), (views.unprotect, {'path': 'a'}),
                            (views.protect, {'path': 'a', 'username': 'u', 'password': 'p' * 9})):
            code, data, _ = post(view, dict(extra, domain=FOREIGN), policy=ON)
            self.assertEqual(code, 403, view.__name__)
        self.call.assert_not_called()
        self.private.assert_not_called()
        code, _, _ = post(views.overview, {'domain': 'mine.example.com'}, policy=ON)
        self.assertEqual(code, 200)
        self.assertEqual(self.call.call_args[1]['domains'], ['blog.mine.example.com', 'mine.example.com'])

    def test_clone_into_a_foreign_site_is_refused(self):
        code, _, _ = post(views.clone, {'source': 'mine.example.com', 'mode': 'site', 'target': FOREIGN}, policy=ON)
        self.assertEqual(code, 403)
        code, _, _ = post(views.clone, {'source': FOREIGN, 'mode': 'subdomain'}, policy=ON)
        self.assertEqual(code, 403)
        self.call.assert_not_called()

    def test_clone_by_user_uses_quota_and_records_the_job(self):
        self.call.return_value = {'job_id': 'a' * 24}
        code, data, session = post(views.clone, {'source': 'mine.example.com', 'mode': 'site',
                                                 'target': 'blog.mine.example.com', 'databases': ['x_db']}, policy=ON)
        self.assertEqual(code, 200)
        args = self.call.call_args[1]
        self.assertTrue(args['quota'])
        self.assertEqual(args['target'], 'blog.mine.example.com')
        self.assertIn('sitetools:' + 'a' * 24, session['ua_jobs'])
        code, _, _ = post(views.job, {'job': 'b' * 24}, session=session, policy=ON)
        self.assertEqual(code, 403)

    def test_passwords_never_go_on_the_command_line(self):
        post(views.protect, {'domain': 'mine.example.com', 'path': 'private', 'username': 'u', 'password': 'p' * 9},
             policy=ON)
        post(views.user_set, {'domain': 'mine.example.com', 'path': 'private', 'username': 'u', 'password': 'p' * 9},
             policy=ON)
        self.assertEqual(self.private.call_count, 2)
        self.call.assert_not_called()

    def test_users_are_rate_limited_admins_are_not(self):
        post(views.redirects, {'domain': 'mine.example.com', 'rules': []}, policy=ON)
        self.assertEqual(self.call.call_args[1]['min_interval'], views.USER_MIN_INTERVAL)
        post(views.redirects, {'domain': 'mine.example.com', 'rules': []}, admin=True)
        self.assertEqual(self.call.call_args[1]['min_interval'], 0)

    def test_push_requires_owning_the_live_site_root_side(self):
        state = {'sites': {}, 'changed': {}, 'staging': {'staging.mine.example.com': {'live': 'mine.example.com'}}}
        with mock.patch.object(actions, 'load_state', return_value=state):
            self.assertEqual(actions._pair('staging.mine.example.com', ['mine.example.com'])['live'], 'mine.example.com')
            with self.assertRaises(PermissionError):
                actions._pair('staging.mine.example.com', ['staging.mine.example.com'])
            with self.assertRaises(SiteToolsError):
                actions._pair('nope.example.com')

    def test_registered_everywhere(self):
        from universalAddons import access, registry, runner
        self.assertIn(('sitetools', 'sitetools_for_users'), access.USER_FEATURES)
        self.assertIs(access.DEFAULT_POLICY['sitetools_for_users'], False)
        self.assertIn('sitetools', access.USER_FEATURE_HELP)
        self.assertEqual(runner.MODULES['sitetools'], 'universalAddons.sitetools.actions')
        self.assertIn('sitetools', [m.key for m in registry.MODULES])
        for name in ('clone_run', 'push_run', 'restore_run', 'protect', 'redirects', 'hotlink', 'errorpage_save'):
            self.assertIn(name, actions.ACTIONS)


# ----------------------------------------------------------------------------- managed blocks

HTACCESS = '# my rules\nRewriteEngine On\nRewriteRule ^old$ /new [L]\n'
VHOST = ('docRoot                   $VH_ROOT/public_html\n\nrewrite  {\n  enable                  1\n}\n\n'
         'vhssl  {\n  keyFile                 /etc/x.key\n}\n')


class Blocks(SimpleTestCase):
    RULES = [{'code': '301', 'kind': 'path', 'source': '/old.html', 'target': '/new'},
             {'code': '302', 'kind': 'regex', 'source': '^blog/(.*)$', 'target': 'https://blog.example.com/$1'}]

    def test_redirect_block_rendered_idempotently_and_other_rules_kept(self):
        rules = st.validate_redirects(self.RULES)
        lines = st.redirect_lines(rules)
        self.assertEqual(lines, ['RewriteEngine On', r'RewriteRule ^old\.html$ /new [R=301,L]',
                                 'RewriteRule ^blog/(.*)$ https://blog.example.com/$1 [R=302,L]'])
        once = st.set_htaccess_block(HTACCESS, st.REDIRECTS, lines)
        self.assertTrue(once.startswith(st.REDIRECTS[0]))
        self.assertTrue(once.endswith(HTACCESS))
        self.assertEqual(st.set_htaccess_block(once, st.REDIRECTS, lines), once)
        self.assertEqual(once.count(st.REDIRECTS[0]), 1)
        self.assertEqual(st.set_htaccess_block(once, st.REDIRECTS, []).lstrip('\n'), HTACCESS)

    def test_two_blocks_coexist(self):
        text = st.set_htaccess_block(HTACCESS, st.REDIRECTS, st.redirect_lines(st.validate_redirects(self.RULES)))
        hot = st.hotlink_lines(st.validate_hotlink({'enabled': True, 'extensions': ['jpg']}, 'mine.example.com'),
                               'mine.example.com')
        both = st.set_htaccess_block(text, st.HOTLINK, hot)
        self.assertEqual(st.set_htaccess_block(both, st.HOTLINK, hot), both)
        self.assertIn(st.REDIRECTS[0], both)
        changed = st.set_htaccess_block(both, st.REDIRECTS, ['RewriteEngine On', 'RewriteRule ^a$ /b [R=301,L]'])
        self.assertIn(st.HOTLINK[0], changed)
        self.assertIn('RewriteRule ^a$ /b', changed)
        self.assertNotIn('old\\.html', changed)

    def test_unterminated_block_is_refused(self):
        with self.assertRaises(SiteToolsError):
            st.set_htaccess_block(st.REDIRECTS[0] + '\nRewriteRule x y\n', st.REDIRECTS, [])

    def test_hotlink_block(self):
        config = st.validate_hotlink({'enabled': True, 'domains': ['www.partner.org', 'cdn.example.net'],
                                      'extensions': ['.JPG', 'png'], 'allow_empty': True, 'redirect': '/hotlink.png'},
                                     'mine.example.com')
        lines = st.hotlink_lines(config, 'mine.example.com')
        self.assertEqual(lines[1], 'RewriteCond %{HTTP_REFERER} !^$')
        self.assertIn(r'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?mine\.example\.com(:[0-9]+)?(/|$) [NC]', lines)
        self.assertIn(r'RewriteCond %{HTTP_REFERER} !^https?://([^/]+\.)?partner\.org(:[0-9]+)?(/|$) [NC]', lines)
        self.assertIn(r'RewriteCond %{REQUEST_URI} !^/hotlink\.png$', lines)
        self.assertEqual(lines[-1], r'RewriteRule \.(jpg|png)$ /hotlink.png [NC,R=302,L]')
        forbid = st.hotlink_lines(dict(config, redirect='', allow_empty=False), 'mine.example.com')
        self.assertEqual(forbid[-1], r'RewriteRule \.(jpg|png)$ - [NC,F,L]')
        self.assertNotIn('RewriteCond %{HTTP_REFERER} !^$', forbid)
        self.assertEqual(st.hotlink_lines(dict(config, enabled=False), 'mine.example.com'), [])
        with self.assertRaises(SiteToolsError):
            st.validate_hotlink({'enabled': True, 'extensions': ['jp g']}, 'mine.example.com')
        with self.assertRaises(SiteToolsError):
            st.validate_hotlink({'enabled': True, 'domains': ['evil.com"\nRewriteRule'], 'extensions': ['jpg']},
                                'mine.example.com')

    def test_errorpage_block_in_vhost_before_ssl(self):
        body = st.errorpage_body(['404', '503'])
        once = st.set_vhost_block(VHOST, st.ERRORS, body)
        self.assertIn('errorpage 404 {\n  url                     /error-pages/404.html\n}', once)
        self.assertLess(once.index(st.ERRORS[0]), once.index('vhssl'))
        self.assertTrue(st.braces_balanced(once))
        self.assertEqual(st.set_vhost_block(once, st.ERRORS, body), once)
        self.assertEqual(st.set_vhost_block(once, st.ERRORS, ''), VHOST)
        self.assertEqual(st.errorpage_conflicts(once, ['404']), [])
        self.assertEqual(st.errorpage_conflicts(VHOST + 'errorpage 404 {\n url /x\n}\n', ['404', '500']), ['404'])
        with self.assertRaises(SiteToolsError):
            st.validate_code('418')

    def test_auth_block_in_vhost(self):
        entries = [{'path': 'private', 'realm': st.realm_name('mine.example.com', 'private'),
                    'userfile': '/home/mine.example.com/.ic-htpasswd-x', 'name': 'Staff only'}]
        body = st.auth_body(entries, '/home/mine.example.com/public_html')
        self.assertIn('realm %s {\n  userDB  {\n    location              /home/mine.example.com/.ic-htpasswd-x' %
                      entries[0]['realm'], body)
        self.assertIn('context /private/ {\n  location                /home/mine.example.com/public_html/private/', body)
        self.assertIn('  required                valid-user', body)
        once = st.set_vhost_block(VHOST, st.AUTH, body)
        both = st.set_vhost_block(once, st.ERRORS, st.errorpage_body(['404']))
        self.assertEqual(st.set_vhost_block(both, st.AUTH, body), both)
        self.assertTrue(st.braces_balanced(both))
        self.assertFalse(st.auth_conflicts(both, 'private'))
        self.assertTrue(st.auth_conflicts(VHOST + 'context /private {\n}\n', 'private'))
        self.assertTrue(st.auth_conflicts(VHOST + 'context / {\n}\n', ''))
        with self.assertRaises(SiteToolsError):
            st.auth_body([dict(entries[0], name='bad}\nname')], '/home/x/public_html')

    def test_braces(self):
        self.assertFalse(st.braces_balanced('a {\n'))
        self.assertTrue(st.braces_balanced('ctx {\n  extraHeaders <<<END_x\n  {{{\n  END_x\n}\n'))


# ----------------------------------------------------------------------------- validation

class Validation(SimpleTestCase):
    def test_regex_validation(self):
        self.assertEqual(st.validate_regex('^old/(.*)$'), '^old/(.*)$')
        self.assertEqual(st.validate_regex('^/old$'), '^old$')     # leading slash never matches in .htaccess
        for bad in ('', 'a b', '(unclosed', '^a"$', 'x\ny', '%{HTTP_HOST}', 'a' * 301, '[z-a]'):
            with self.assertRaises(SiteToolsError, msg=bad):
                st.validate_regex(bad)

    def test_redirect_validation(self):
        bad = [{'code': '307', 'source': '/a', 'target': '/b'}, {'source': 'a', 'target': '/b'},
               {'source': '/a b', 'target': '/b'}, {'source': '/a', 'target': 'javascript:alert(1)'},
               {'source': '/a', 'target': '/b [R=301]\nRewriteRule'}, {'source': '/a', 'target': '/a'},
               {'source': '/a?x=1', 'target': '/b'}, {'kind': 'other', 'source': '/a', 'target': '/b'}]
        for rule in bad:
            with self.assertRaises(SiteToolsError, msg=rule):
                st.validate_redirect(rule)
        with self.assertRaises(SiteToolsError):
            st.validate_redirects([{'source': '/a', 'target': '/b'}, {'source': '/a', 'target': '/c'}])
        self.assertEqual(st.validate_redirect({'source': '/a', 'target': 'https://x.org/b?c=1'})['code'], '301')

    def test_error_page_and_names(self):
        with self.assertRaises(SiteToolsError):
            st.validate_page('')
        with self.assertRaises(SiteToolsError):
            st.validate_page('x' * (st.MAX_PAGE_BYTES + 1))
        self.assertIn('404', st.default_page('404'))
        self.assertEqual(st.staging_domain('mine.example.com'), 'staging.mine.example.com')
        for label in ('Bad_', '-x', 'a.b', ''):
            if label:
                with self.assertRaises(SiteToolsError):
                    st.staging_domain('mine.example.com', label)

    def test_excludes(self):
        push = st.excludes(True, True, ['/backups/', 'tmp'], push=True)
        for item in ('.env', 'wp-config.php', '/wp-content/cache/', '/wp-content/uploads/', '/backups/', 'tmp'):
            self.assertIn(item, push)
        self.assertNotIn('/wp-content/uploads/', st.excludes(True, False))
        for bad in ('../x', 'a b', 'x;rm', '$(id)'):
            with self.assertRaises(SiteToolsError, msg=bad):
                st.excludes(extra=[bad])
        self.assertEqual(st.tar_excludes(['/cache/', '.env']), ['--exclude=./cache', '--exclude=.env'])


# ----------------------------------------------------------------------------- htpasswd

class Htpasswd(SimpleTestCase):
    def test_apr1_matches_openssl(self):
        self.assertEqual(st.apr1_crypt('S3cret-pass', 'abcdefgh'), '$apr1$abcdefgh$Dhp923kOcdRj9IQgweX30/')
        self.assertEqual(st.apr1_crypt('password', 'xy'), '$apr1$xy$.lxC8wf/tCocZ14cbZ9g1.')
        hashed = st.hash_password('correct horse', 'apr1')
        self.assertRegex(hashed, r'^\$apr1\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{22}$')
        self.assertTrue(st.verify_password('correct horse', hashed))
        self.assertFalse(st.verify_password('wrong horse!', hashed))

    def test_bcrypt_uses_2y(self):
        hashed = st.hash_password('correct horse')
        self.assertRegex(hashed, r'^\$2y\$10\$[./0-9A-Za-z]{53}$')
        self.assertTrue(st.verify_password('correct horse', hashed))
        self.assertFalse(st.verify_password('correct horsf', hashed))

    def test_file_format(self):
        a, b = st.hash_password('password1', 'apr1'), st.hash_password('password2')
        entries = st.set_ht_user([], 'alice', a)
        entries = st.set_ht_user(entries, 'bob', b)
        entries = st.set_ht_user(entries, 'alice', b)       # change password, keep position
        text = st.render_htpasswd(entries)
        self.assertEqual(text, 'alice:%s\nbob:%s\n' % (b, b))
        self.assertEqual(st.parse_htpasswd('# c\n\n' + text + 'bad line\n'), entries)
        self.assertEqual(st.remove_ht_user(entries, 'alice'), [('bob', b)])
        for user in ('a:b', 'a b', '', 'x' * 65, 'a\nb'):
            with self.assertRaises(SiteToolsError, msg=user):
                st.validate_ht_user(user)
        with self.assertRaises(SiteToolsError):
            st.set_ht_user([], 'alice', 'plain')
        for password in ('short', 'x' * 129, 'line\nbreak1'):
            with self.assertRaises(SiteToolsError):
                st.hash_password(password)
        with self.assertRaises(SiteToolsError):
            st.hash_password('password1', 'md4')


# ----------------------------------------------------------------------------- paths

class Paths(SimpleTestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.docroot = os.path.join(self.base, 'public_html')
        os.makedirs(os.path.join(self.docroot, 'private', 'deep'))
        self.outside = os.path.join(self.base, 'outside')
        os.makedirs(self.outside)
        os.symlink(self.outside, os.path.join(self.docroot, 'escape'))
        os.symlink(os.path.join(self.docroot, 'private'), os.path.join(self.docroot, 'alias'))
        open(os.path.join(self.docroot, 'file.txt'), 'w').close()

    def test_directory_inside_docroot(self):
        self.assertEqual(st.safe_dir(self.docroot, 'private/deep'), os.path.join(self.docroot, 'private', 'deep'))
        self.assertEqual(st.safe_dir(self.docroot, ''), self.docroot)
        self.assertEqual(st.norm_rel('/private/'), 'private')

    def test_traversal_and_links_refused(self):
        for rel in ('../outside', 'private/../../outside', '/etc', 'a//b', './private'):
            with self.assertRaises((SiteToolsError, ValueError), msg=rel):
                st.safe_dir(self.docroot, st.norm_rel(rel))
        for rel in ('escape', 'alias', 'alias/deep', 'file.txt', 'missing'):
            with self.assertRaises(SiteToolsError, msg=rel):
                st.safe_dir(self.docroot, rel)

    def test_docroot_itself_may_not_be_a_link(self):
        link = os.path.join(self.base, 'linked_root')
        os.symlink(self.docroot, link)
        with self.assertRaises(SiteToolsError):
            st.safe_dir(link, 'private')

    def test_nested_and_empty(self):
        self.assertTrue(st.nested('/home/a/public_html', '/home/a/public_html/staging'))
        self.assertFalse(st.nested('/home/a/public_html', '/home/a/staging.a.com'))
        self.assertTrue(st.looks_empty(['index.html', '.well-known']))
        self.assertFalse(st.looks_empty(['index.php']))


# ----------------------------------------------------------------------------- staging config rewrite

DB_MAP = {'mine_live': {'name': 'mine_stg1a2b3c', 'user': 'mine_stg1a2b3c', 'password': 'n3w-Pass_word'}}


class ConfigRewrite(SimpleTestCase):
    def test_laravel_env(self):
        env = ('APP_NAME=Shop\nAPP_URL=https://mine.example.com\nASSET_URL="https://mine.example.com/cdn"\n'
               'DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=mine_live\nDB_USERNAME=mine_live\n'
               'DB_PASSWORD="old secret"\nSESSION_DOMAIN=.mine.example.com\nMAIL_FROM_ADDRESS=hi@mine.example.com\n')
        text, keys = st.rewrite_env(env, DB_MAP, 'mine.example.com', 'staging.mine.example.com')
        self.assertIn('APP_URL=https://staging.mine.example.com\n', text)
        self.assertIn('ASSET_URL=https://staging.mine.example.com/cdn\n', text)
        self.assertIn('DB_DATABASE=mine_stg1a2b3c\n', text)
        self.assertIn('DB_USERNAME=mine_stg1a2b3c\n', text)
        self.assertIn('DB_PASSWORD=n3w-Pass_word\n', text)
        self.assertIn('DB_HOST=127.0.0.1\n', text)
        self.assertIn('SESSION_DOMAIN=.staging.mine.example.com\n', text)
        self.assertIn('MAIL_FROM_ADDRESS=hi@mine.example.com\n', text)    # e-mail addresses are left alone
        self.assertEqual(sorted(keys), sorted(['APP_URL', 'ASSET_URL', 'DB_DATABASE', 'DB_USERNAME', 'DB_PASSWORD',
                                               'SESSION_DOMAIN']))
        again, keys = st.rewrite_env(text, DB_MAP, 'mine.example.com', 'staging.mine.example.com')
        self.assertEqual(keys, [])

    def test_env_of_another_database_keeps_its_credentials(self):
        env = 'DB_DATABASE=other_db\nDB_PASSWORD=keep\nAPP_URL=http://mine.example.com\n'
        text, keys = st.rewrite_env(env, DB_MAP, 'mine.example.com', 'staging.mine.example.com')
        self.assertIn('DB_PASSWORD=keep', text)
        self.assertIn('APP_URL=http://staging.mine.example.com', text)   # scheme kept

    def test_database_url_and_quoting(self):
        env = 'DATABASE_URL="mysql://mine_live:old@127.0.0.1:3306/mine_live?serverVersion=10.5"\n'
        db_map = {'mine_live': dict(DB_MAP['mine_live'], password='p@ss w"rd')}
        text, keys = st.rewrite_env(env, db_map, 'a.com', 'b.a.com')
        self.assertIn('mysql://mine_stg1a2b3c:p%40ss%20w%22rd@127.0.0.1:3306/mine_stg1a2b3c?serverVersion=10.5', text)
        text, _ = st.rewrite_env('DB_DATABASE=mine_live\nDB_PASSWORD=x\n', db_map, 'a.com', 'b.a.com')
        self.assertIn('DB_PASSWORD="p@ss w\\"rd"', text)

    def test_wp_config(self):
        php = ("<?php\ndefine( 'DB_NAME', 'mine_live' );\ndefine('DB_USER', \"mine_live\");\n"
               "define( 'DB_PASSWORD', 'o\\'ld' );\ndefine( 'DB_HOST', 'localhost' );\n"
               "define('WP_HOME', 'https://mine.example.com');\ndefine('WP_SITEURL', 'https://mine.example.com/wp');\n"
               "$table_prefix = 'wp_';\n")
        text, keys = st.rewrite_wp_config(php, DB_MAP, 'mine.example.com', 'staging.mine.example.com')
        self.assertIn("define( 'DB_NAME', 'mine_stg1a2b3c' );", text)
        self.assertIn("define('DB_USER', 'mine_stg1a2b3c');", text)
        self.assertIn("define( 'DB_PASSWORD', 'n3w-Pass_word' );", text)
        self.assertIn("define( 'DB_HOST', 'localhost' );", text)
        self.assertIn("define('WP_HOME', 'https://staging.mine.example.com');", text)
        self.assertIn("define('WP_SITEURL', 'https://staging.mine.example.com/wp');", text)
        self.assertEqual(set(keys), {'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'WP_HOME', 'WP_SITEURL'})
        self.assertEqual(st.rewrite_wp_config(text, DB_MAP, 'mine.example.com', 'staging.mine.example.com')[1], [])
        self.assertEqual(st.config_db_names({'wp-config.php': php, 'app/.env': 'DB_DATABASE=x_db\n'}), ['mine_live', 'x_db'])

    def test_wp_config_password_with_quotes(self):
        php = "define('DB_NAME','mine_live');\ndefine('DB_PASSWORD','x');\n"
        db_map = {'mine_live': dict(DB_MAP['mine_live'], password="a'b\\c")}
        text, _ = st.rewrite_wp_config(php, db_map, 'a.com', 'b.a.com')
        self.assertIn("define('DB_PASSWORD','a\\'b\\\\c');", text)

    def test_find_config_files(self):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, 'app', 'vendor'))
        for rel in ('.env', 'app/.env', 'app/vendor/.env', 'wp-config.php'):
            open(os.path.join(root, rel), 'w').close()
        self.assertEqual(st.find_config_files(root), ['.env', 'app/.env', 'wp-config.php'])


# ----------------------------------------------------------------------------- serialized-safe replace

class SerializedReplace(SimpleTestCase):
    PAIRS = st.url_pairs('mine.example.com', 'staging.mine.example.com')

    def test_lengths_fixed_including_nested_and_utf8(self):
        inner = _ser([b'https://mine.example.com/a'])
        value = _ser({b'home': b'https://mine.example.com', b'nested': inner, b'name': 'Café'.encode(),
                      b'n': 5})
        out = st.replace_value(value, self.PAIRS)
        tree = st.unserialize_tree(out)
        self.assertIsNotNone(tree)
        self.assertIn(b's:32:"https://staging.mine.example.com";', out)
        nested = dict((k[1], v) for k, v in tree[1])[b'nested']
        self.assertIsNotNone(st.unserialize_tree(nested[1]))
        self.assertIn(b'https://staging.mine.example.com/a', nested[1])
        self.assertIn(b's:5:"Caf\xc3\xa9";', out)

    def test_plain_json_and_scheme(self):
        self.assertEqual(st.replace_value(b'see http://mine.example.com/x', self.PAIRS),
                         b'see http://staging.mine.example.com/x')
        self.assertEqual(st.replace_value(b'{"u":"https:\\/\\/www.mine.example.com"}', self.PAIRS),
                         b'{"u":"https:\\/\\/staging.mine.example.com"}')
        self.assertEqual(st.replace_value(b'mail hi@mine.example.com', self.PAIRS), b'mail hi@mine.example.com')

    def test_objects_and_broken_data(self):
        obj = b'O:8:"stdClass":1:{s:3:"url";s:24:"https://mine.example.com";}'
        out = st.replace_value(obj, self.PAIRS)
        self.assertEqual(out, b'O:8:"stdClass":1:{s:3:"url";s:32:"https://staging.mine.example.com";}')
        broken = b'a:1:{i:0;s:99:"https://mine.example.com";}'
        self.assertIsNone(st.unserialize_tree(broken))
        self.assertIn(b'staging.mine.example.com', st.replace_value(broken, self.PAIRS))
        self.assertEqual(st.serialize_tree(st.unserialize_tree(b'a:2:{i:0;b:1;i:1;d:0.5;}')), b'a:2:{i:0;b:1;i:1;d:0.5;}')

    def test_sql_dump_lines(self):
        value = _ser({b'siteurl': b'https://mine.example.com'})
        line = (b"INSERT INTO `options` VALUES (1,'home','https://mine.example.com','yes'),(2,'o','" + st.sql_escape(value)
                + b"','no'),(3,'it''s','line\\nbreak');\n")
        out = st.transform_dump_line(line, self.PAIRS)
        self.assertIn(b"'https://staging.mine.example.com'", out)
        literal = out.split(b"(2,'o','")[1].split(b"','no')")[0]
        self.assertIsNotNone(st.unserialize_tree(st.sql_unescape(literal)))
        self.assertIn(b"'line\\nbreak'", out)
        self.assertTrue(out.endswith(b'\n'))
        create = b"CREATE TABLE `x` (`u` varchar(9) DEFAULT 'https://mine.example.com');\n"
        self.assertEqual(st.transform_dump_line(create, self.PAIRS), create)
        for raw in (b'a\\b', b"it's", b'x\x00y\n\r"\x1a'):
            self.assertEqual(st.sql_unescape(st.sql_escape(raw)), raw)


# ----------------------------------------------------------------------------- vhost writer

class VhostWriter(SimpleTestCase):
    def setUp(self):
        self.vhosts = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.vhosts, 'mine.example.com'))
        self.path = os.path.join(self.vhosts, 'mine.example.com', 'vhost.conf')
        with open(self.path, 'w') as handle:
            handle.write(VHOST)
        self.site = SimpleNamespace(domain='mine.example.com', vhost='mine.example.com')
        self.backups = tempfile.mkdtemp()
        patches = [mock.patch.object(actions, 'VHOSTS', self.vhosts), mock.patch.object(actions, 'restart', return_value=True)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def read(self):
        with open(self.path) as handle:
            return handle.read()

    def test_writes_backs_up_and_is_idempotent(self):
        with mock.patch.object(actions, 'status', return_value='200'):
            result = actions.write_vhost_block(self.site, st.ERRORS, st.errorpage_body(['404']), self.backups)
            self.assertTrue(result['changed'])
            self.assertIn('errorpage 404', self.read())
            self.assertFalse(actions.write_vhost_block(self.site, st.ERRORS, st.errorpage_body(['404']),
                                                       self.backups)['changed'])
        self.assertTrue(os.listdir(os.path.join(self.backups, 'vhost')))
        self.assertEqual(actions.restart.call_count, 1)

    def test_rolls_back_when_the_site_breaks(self):
        with mock.patch.object(actions, 'status', side_effect=['200', '503']):
            with self.assertRaisesRegex(SiteToolsError, 'restored'):
                actions.write_vhost_block(self.site, st.ERRORS, st.errorpage_body(['404']), self.backups)
        self.assertEqual(self.read(), VHOST)
        self.assertEqual(actions.restart.call_count, 2)

    def test_htaccess_writer_restores_on_failure(self):
        site = SimpleNamespace(domain='mine.example.com', docroot='/home/mine.example.com/public_html')
        written = []
        with mock.patch.object(actions.siteinfo, 'read_owned', return_value=HTACCESS), \
                mock.patch.object(actions.siteinfo, 'write_as', side_effect=lambda s, p, t, **k: written.append(t)), \
                mock.patch.object(actions, 'status', side_effect=['200', '500']), \
                mock.patch.object(actions, 'BACKUP_ROOT', self.backups):
            with self.assertRaisesRegex(SiteToolsError, 'previous .htaccess'):
                actions.write_htaccess_block(site, st.REDIRECTS, ['RewriteEngine On', 'RewriteRule ^a$ /b [R=301,L]'])
        self.assertIn(st.REDIRECTS[0], written[0])
        self.assertEqual(written[-1], HTACCESS)

    def test_throttle(self):
        state = {'changed': {'mine.example.com': 10 ** 10}}
        with self.assertRaisesRegex(SiteToolsError, 'try again'):
            actions._throttle(state, 'mine.example.com', 20)
        actions._throttle(state, 'other.example.com', 20)
        actions._throttle(state, 'mine.example.com', 0)

    def test_wordpress_sites_point_to_the_wordpress_addon(self):
        src = SimpleNamespace(domain='mine.example.com', docroot='/x')
        with mock.patch.object(actions, 'resolve', return_value=src), \
                mock.patch.object(actions, 'is_wordpress', return_value=True):
            with self.assertRaisesRegex(SiteToolsError, '/addons/wordpress/'):
                actions.plan_clone('mine.example.com')


# ----------------------------------------------------------------------------- page

class Page(SimpleTestCase):
    def test_page_needs_the_switch_for_users(self):
        self.assertEqual(page(views.page)[0], 403)
        code, values = page(views.page, policy=ON)
        self.assertEqual(code, 200)
        self.assertEqual(values['_template'], 'universalAddons/sitetools.html')
        code, values = page(views.page, admin=True)
        self.assertTrue(values['is_admin'])

    def test_template_renders(self):
        request = RequestFactory().get('/addons/site-tools/')
        request.session = {}
        from resellerBranding.service import default_brand
        html = render_to_string('universalAddons/sitetools.html', {'is_admin': False, 'site': 'mine.example.com',
                                                                    'panel_brand': default_brand()})
        self.assertIn('ua-wrap', html)
        self.assertIn('data-site="mine.example.com"', html)
        self.assertIn('IndiansCloud', html)
        self.assertIn('/addons/site-tools/', html)
        for path in ('universalAddons/templates/universalAddons/sitetools.html',
                     'universalAddons/static/universalAddons/sitetools.js'):
            with open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), path)) as handle:
                self.assertNotIn('CyberPanel', handle.read(), path)   # user-visible text says IndiansCloud
