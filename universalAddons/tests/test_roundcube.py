import io
import json
import os
import tarfile
import tempfile
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import include, path

from universalAddons import jobs
from universalAddons.roundcube import actions, service as rc, views

# The module is not in universalAddons/urls.py yet: give the page test its own URLconf.
from CyberCP.urls import urlpatterns as _project_urls  # noqa: E402

urlpatterns = [path('addons/roundcube/', include('universalAddons.roundcube.urls'))] + list(_project_urls)

VH_ROOT = '/home/shop.example.com'
RELEASE = '/usr/local/cp-roundcube/1.6.21'
SECRET = {'db_password': 'DbSecretAbc123DbSecretAbc123XyZ0', 'des_key': 'DesKeyQwerty0123456789Ab'}

VHOST = """docRoot                   $VH_ROOT/public_html
vhDomain                  $VH_NAME

accesslog $VH_ROOT/logs/$VH_NAME.access_log {
  useServer               0
  logFormat               "%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i""
}

scripthandler  {
  add                     lsapi:shop1234 php
}

extprocessor shop1234 {
  type                    lsapi
  address                 UDS://tmp/lshttpd/shop1234.sock
  path                    /usr/local/lsws/lsphp73/bin/lsphp
  extUser                 shop1234
  extGroup                shop1234
}

phpIniOverride  {
php_admin_value open_basedir "/tmp:$VH_ROOT"
}

# BEGIN cp-ua-apps (managed by CyberPanel; do not edit)

context /api/ {
  type                    proxy
  handler                 cpapp_api
}

# END cp-ua-apps

vhssl  {
  keyFile                 /etc/letsencrypt/live/shop.example.com/privkey.pem
}
"""

HTTPD = """virtualhost other.com {
  vhRoot                  /home/$VH_NAME
  restrained              1
}

virtualhost shop.example.com {
  vhRoot                  /home/$VH_NAME
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhost.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}
"""


class ConfigRendering(SimpleTestCase):
    def test_config_contents(self):
        text = rc.render_config(SECRET, 'ssl://127.0.0.1:993', 'tls://127.0.0.1:587', 'shop.example.com', True)
        for expected in ("$config['imap_host'] = 'ssl://127.0.0.1:993';", "$config['smtp_host'] = 'tls://127.0.0.1:587';",
                         "$config['smtp_user'] = '%u';", "$config['smtp_pass'] = '%p';", "$config['skin'] = 'elastic';",
                         "$config['plugins'] = ['archive', 'zipdownload'];", "'verify_peer' => false",
                         "$config['enable_installer'] = false;", "$config['force_https'] = true;",
                         "$config['db_dsnw'] = 'mysql://cp_roundcube:%s@localhost/cp_roundcube';" % SECRET['db_password'],
                         "$config['des_key'] = '%s';" % SECRET['des_key'],
                         "$config['trusted_host_patterns'] = ['shop.example.com', 'www.shop.example.com'];"):
            self.assertIn(expected, text)
        self.assertNotIn('managesieve', text)
        sieve = rc.render_config(SECRET, 'x', 'y', 'shop.example.com', False, sieve=True)
        self.assertIn("'managesieve']", sieve)
        self.assertIn("$config['force_https'] = false;", sieve)

    def test_php_string_escaping(self):
        self.assertEqual(rc.php_string("a'b\\c"), "'a\\'b\\\\c'")

    def test_generated_secrets(self):
        secret = rc.new_secrets()
        self.assertEqual(len(secret['des_key']), 24)
        self.assertTrue(secret['db_password'].isalnum() and len(secret['db_password']) == 32)

    def test_written_config_is_private(self):
        release = tempfile.mkdtemp()
        os.makedirs(os.path.join(release, 'config'))
        path = rc.write_config(release, '<?php\n', os.getgid(), chown=False)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o640')

    def test_mail_choice(self):
        self.assertEqual(rc.choose_imap({'ssl': 'yes'}, lambda p: True), 'ssl://127.0.0.1:993')
        self.assertEqual(rc.choose_imap({'ssl': 'required'}, lambda p: False), 'tls://127.0.0.1:143')
        self.assertEqual(rc.choose_imap({'ssl': 'no'}, lambda p: True), '127.0.0.1:143')
        services = rc.parse_postconf_services('smtp       inet  n - n - - smtpd\nsubmission inet n - n - - smtpd\n'
                                              '127.0.0.1:2588 inet n - n - - smtpd\npickup unix n - n 60 1 pickup\n')
        self.assertEqual(rc.choose_smtp(services), 'tls://127.0.0.1:587')
        self.assertEqual(rc.choose_smtp({'smtps'}), 'ssl://127.0.0.1:465')
        with self.assertRaises(rc.RoundcubeError):
            rc.choose_smtp({'smtp'})
        self.assertEqual(rc.parse_doveconf({'ssl': 'yes', 'protocols': 'imap pop3'}), {'ssl': 'yes', 'sieve': False})
        self.assertTrue(rc.parse_doveconf({'ssl': 'yes', 'protocols': 'imap lmtp sieve'})['sieve'])


class NoSecretsLeak(SimpleTestCase):
    def test_mysql_passwords_travel_on_stdin(self):
        seen = {}

        def runner(argv, **kwargs):
            seen.update(argv=argv, input=kwargs.get('input'))
            return SimpleNamespace(returncode=0, stdout='')
        rc.mysql(rc.create_db_sql(SECRET['db_password']), '/root/x.cnf', runner)
        self.assertNotIn(SECRET['db_password'], ' '.join(seen['argv']))
        self.assertIn("IDENTIFIED BY '%s'" % SECRET['db_password'], seen['input'])
        self.assertEqual(seen['argv'][:2], ['mysql', '--defaults-extra-file=/root/x.cnf'])
        with self.assertRaises(rc.RoundcubeError):
            rc.create_db_sql("x' OR '1")

    def test_install_job_redacts_secrets_from_log_and_error(self):
        root, state, job_dir = tempfile.mkdtemp(), tempfile.mkdtemp(), tempfile.mkdtemp()
        captured = {}

        @contextmanager
        def fake_credentials():
            yield '/root/defaults.cnf'

        def fake_extract(tarball, destination, version):
            os.makedirs(os.path.join(destination, 'SQL'))
            open(os.path.join(destination, 'index.php'), 'w').close()

        def fake_mysql(sql, defaults, *a, **k):
            if 'IDENTIFIED BY' in sql:
                captured['password'] = sql.split("IDENTIFIED BY '")[1].split("'")[0]
                return ''
            return '0\n'

        def failing_schema(path, defaults):
            raise rc.RoundcubeError("MySQL said: Access denied for 'cp_roundcube' using password '%s'" % captured['password'])

        job_id = 'ab' * 12
        with mock.patch.object(rc, 'ROOT', root), mock.patch.object(rc, 'STATE_DIR', state), \
                mock.patch.object(jobs, 'JOB_DIR', job_dir), \
                mock.patch.object(rc, 'download', side_effect=lambda url, target: open(target, 'wb').write(b'x') and 1), \
                mock.patch.object(rc, 'verify_checksum', return_value='f' * 64), \
                mock.patch.object(rc, 'extract_release', side_effect=fake_extract), \
                mock.patch.object(actions, 'credentials', fake_credentials), \
                mock.patch.object(rc, 'mysql', side_effect=fake_mysql), \
                mock.patch.object(rc, 'load_schema', side_effect=failing_schema):
            data = actions.install_run(job_id, 'shop.example.com')
            on_disk = open(os.path.join(job_dir, job_id + '.json')).read()
        self.assertEqual(data['state'], 'failed')
        self.assertTrue(captured['password'])
        for text in (json.dumps(data), on_disk):
            self.assertNotIn(captured['password'], text)
        self.assertIn('********', data['error'])
        self.assertFalse(os.path.exists(os.path.join(state, 'secrets.json')), 'secrets saved only after the DB is ready')

    def test_overview_never_returns_secrets(self):
        state = tempfile.mkdtemp()
        rc.save_secrets(SECRET, state)
        rc.save_state({'site': 'shop.example.com', 'enabled': True}, state)
        site = {'domain': 'shop.example.com', 'vh_root': VH_ROOT, 'ssl': True, 'block': True,
                'php': {'lsphp': 'lsphp73'}, 'vhost_path': '/x'}
        with mock.patch.object(rc, 'STATE_DIR', state), mock.patch.object(rc, 'installed_version', return_value='1.6.21'), \
                mock.patch.object(actions, '_db_status', return_value={'ok': True}), \
                mock.patch.object(actions, '_site', return_value=site):
            result = actions.overview()
        self.assertEqual(result['url'], 'https://shop.example.com/webmail-rc/')
        text = json.dumps(result)
        self.assertNotIn(SECRET['db_password'], text)
        self.assertNotIn(SECRET['des_key'], text)
        self.assertEqual(oct(os.stat(os.path.join(state, 'secrets.json')).st_mode & 0o777), '0o600')


class VhostBlock(SimpleTestCase):
    def test_apply_is_idempotent_balanced_and_before_ssl(self):
        once = rc.apply_block(VHOST, VH_ROOT, RELEASE)
        twice = rc.apply_block(once, VH_ROOT, RELEASE)
        self.assertEqual(once, twice)
        self.assertEqual(once.count(rc.MARK_BEGIN), 1)
        self.assertTrue(rc.brace_balanced(once))
        self.assertLess(once.index(rc.MARK_END), once.index('vhssl'))
        self.assertIn('# BEGIN cp-ua-apps', once)  # other managed blocks untouched
        self.assertIn('context /webmail-rc/ {\n  location                /home/shop.example.com/cp-roundcube-web/', once)
        self.assertIn('php_admin_value open_basedir "/tmp:/home/shop.example.com:/usr/local/cp-roundcube/"', once)
        self.assertNotIn('/usr/local/cp-roundcube/1.6.21/public_html', once, 'restrained vhosts cannot map outside $VH_ROOT')

    def test_remove_restores_original_and_is_idempotent(self):
        applied = rc.apply_block(VHOST, VH_ROOT, RELEASE)
        removed = rc.remove_block(applied)
        self.assertEqual(removed, VHOST)
        self.assertEqual(rc.remove_block(removed), removed)
        self.assertFalse(rc.block_present(removed))
        self.assertTrue(rc.brace_balanced(removed))

    def test_without_ssl_block_goes_last(self):
        plain = VHOST.split('vhssl')[0]
        applied = rc.apply_block(plain, VH_ROOT, RELEASE)
        self.assertTrue(applied.rstrip().endswith(rc.MARK_END))
        self.assertFalse(rc.has_ssl(plain))

    def test_refuses_unbalanced_or_conflicting_vhosts(self):
        with self.assertRaisesRegex(rc.RoundcubeError, 'unbalanced'):
            rc.apply_block(VHOST + 'context /x/ {\n', VH_ROOT, RELEASE)
        with self.assertRaisesRegex(rc.RoundcubeError, 'unbalanced'):
            rc.remove_block(VHOST + '}\n')
        clash = VHOST + '\ncontext /webmail-rc/ {\n  location /x/\n}\n'
        with self.assertRaisesRegex(rc.RoundcubeError, 'already defines'):
            rc.apply_block(clash, VH_ROOT, RELEASE)

    def test_deny_rules_present(self):
        block = rc.render_vhost_block(VH_ROOT, RELEASE)
        for name in ('config', 'temp', 'logs', 'SQL', 'bin'):
            self.assertIn('context /webmail-rc/%s/ {\n  location                %s/cp-roundcube-web/\n'
                          '  allowBrowse             0\n}' % (name, VH_ROOT), block)
        self.assertTrue(rc.brace_balanced(block))

    def test_parses_handler_and_declaration(self):
        php = rc.parse_php_handler(VHOST)
        self.assertEqual((php['handler'], php['lsphp'], php['user'], php['group'], php['php_cli']),
                         ('shop1234', 'lsphp73', 'shop1234', 'shop1234', '/usr/local/lsws/lsphp73/bin/php'))
        self.assertEqual(rc.parse_vhost_declaration(HTTPD, 'shop.example.com'),
                         {'vh_root': '/home/shop.example.com', 'restrained': True})
        with self.assertRaises(rc.RoundcubeError):
            rc.parse_vhost_declaration(HTTPD, 'missing.com')
        with self.assertRaises(rc.RoundcubeError):
            rc.parse_php_handler(VHOST.replace('/usr/local/lsws/lsphp73/bin/lsphp', '/home/x/evil'))


class Mirror(SimpleTestCase):
    def test_mirror_has_stub_and_static_files_only(self):
        release = tempfile.mkdtemp()
        files = {'skins/elastic/styles/styles.min.css': 'x', 'skins/elastic/watermark.html': 'x',
                 'skins/elastic/templates/mail.html': 'x', 'plugins/archive/archive.php': 'x',
                 'plugins/archive/archive.min.js': 'x', 'program/js/app.min.js': 'x',
                 'program/resources/blank.gif': 'x', 'config/config.inc.php': 'secret', 'program/lib/x.php': 'x'}
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(release, rel)), exist_ok=True)
            with open(os.path.join(release, rel), 'w') as handle:
                handle.write(text)
        target = os.path.join(tempfile.mkdtemp(), 'cp-roundcube-web')
        count = rc.build_mirror(release, target, chown=False)
        found = sorted(os.path.relpath(os.path.join(d, f), target) for d, _, fs in os.walk(target) for f in fs)
        self.assertEqual(count, 5)
        self.assertEqual(found, sorted(['.cp-ua-roundcube', 'index.php', 'plugins/archive/archive.min.js',
                                        'program/js/app.min.js', 'program/resources/blank.gif',
                                        'skins/elastic/styles/styles.min.css', 'skins/elastic/watermark.html']))
        self.assertIn("define('INSTALL_PATH', '%s/');" % release, open(os.path.join(target, 'index.php')).read())
        self.assertEqual(rc.build_mirror(release, target, chown=False), 5)  # rebuild in place
        self.assertTrue(rc.remove_mirror(target))

    def test_refuses_foreign_directory(self):
        target = tempfile.mkdtemp()
        with self.assertRaisesRegex(rc.RoundcubeError, 'not created by the panel'):
            rc.build_mirror(tempfile.mkdtemp(), target, chown=False)
        self.assertFalse(rc.remove_mirror(target))
        self.assertTrue(os.path.isdir(target))


def _tarball(entries):
    path = os.path.join(tempfile.mkdtemp(), 'rc.tar.gz')
    with tarfile.open(path, 'w:gz') as archive:
        for name, kind, data in entries:
            info = tarfile.TarInfo(name)
            if kind == 'dir':
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == 'sym':
                info.type, info.linkname = tarfile.SYMTYPE, data
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return path


class DownloadAndExtract(SimpleTestCase):
    def test_checksum_mismatch_is_rejected(self):
        path = os.path.join(tempfile.mkdtemp(), rc.TARBALL)
        with open(path, 'wb') as handle:
            handle.write(b'not roundcube')
        with self.assertRaisesRegex(rc.RoundcubeError, 'Checksum mismatch'):
            rc.verify_checksum(path)
        import hashlib
        self.assertEqual(rc.verify_checksum(path, hashlib.sha256(b'not roundcube').hexdigest()),
                         hashlib.sha256(b'not roundcube').hexdigest())

    def test_install_job_stops_on_bad_checksum_and_discards_the_download(self):
        root, state, job_dir = tempfile.mkdtemp(), tempfile.mkdtemp(), tempfile.mkdtemp()

        def fake_download(url, target):
            with open(target, 'wb') as handle:
                handle.write(b'tampered')
            return 8
        with mock.patch.object(rc, 'ROOT', root), mock.patch.object(rc, 'STATE_DIR', state), \
                mock.patch.object(jobs, 'JOB_DIR', job_dir), mock.patch.object(rc, 'download', side_effect=fake_download), \
                mock.patch.object(rc, 'extract_release') as extract, mock.patch.object(actions, 'credentials') as creds:
            data = actions.install_run('cd' * 12, 'shop.example.com')
        self.assertEqual(data['state'], 'failed')
        self.assertIn('Checksum mismatch', data['error'])
        extract.assert_not_called()
        creds.assert_not_called()
        self.assertEqual(os.listdir(root), [])  # download dir removed, nothing extracted

    def test_extract_release_and_unsafe_archives(self):
        good = _tarball([('roundcubemail-1.6.21', 'dir', None), ('roundcubemail-1.6.21/index.php', 'file', b'<?php'),
                         ('roundcubemail-1.6.21/installer/index.php', 'file', b'<?php'),
                         ('roundcubemail-1.6.21/public_html/skins', 'sym', '../skins')])
        parent = tempfile.mkdtemp()
        destination = rc.extract_release(good, os.path.join(parent, '1.6.21'), chown=False)
        self.assertTrue(os.path.isfile(os.path.join(destination, 'index.php')))
        self.assertFalse(os.path.exists(os.path.join(destination, 'installer')))
        rc.point_current(parent, '1.6.21')
        with mock.patch.object(rc, 'VERSION_RE', rc.VERSION_RE):
            self.assertEqual(rc.installed_version(parent), '1.6.21')
        for bad in ([('roundcubemail-1.6.21/../evil', 'file', b'x')], [('/etc/passwd', 'file', b'x')],
                    [('other/index.php', 'file', b'x')], [('roundcubemail-1.6.21/x', 'sym', '/etc/shadow')],
                    [('roundcubemail-1.6.21/x', 'sym', '../../etc')]):
            target = os.path.join(tempfile.mkdtemp(), '1.6.21')
            with self.assertRaises(rc.RoundcubeError, msg=bad):
                rc.extract_release(_tarball(bad), target, chown=False)
            self.assertFalse(os.path.exists(target))


class PhpAndReleases(SimpleTestCase):
    def test_php_report(self):
        modules = '[PHP Modules]\nCore\ndom\nintl\nmbstring\nPDO\npdo_mysql\nopenssl\nfileinfo\njson\nzip\n\n[Zend Modules]\n'
        self.assertEqual(rc.php_report('7.3.33', modules), {'version': '7.3.33', 'missing': [], 'version_ok': True, 'ok': True})
        report = rc.php_report('7.2.34', modules.replace('intl\n', '').replace('zip\n', ''))
        self.assertEqual((report['missing'], report['version_ok'], report['ok']), (['intl', 'zip'], False, False))

    def test_upgrade_check_reports_latest_1_6_only(self):
        releases = [{'tag_name': '1.7.2'}, {'tag_name': '1.6.22', 'prerelease': True}, {'tag_name': '1.6.21'},
                    {'tag_name': '1.6.9'}, {'tag_name': '1.5.10'}]
        self.assertEqual(rc.latest_in_branch(releases), '1.6.21')
        self.assertFalse(rc.upgrade_report('1.6.21', '1.6.21')['update_available'])
        self.assertTrue(rc.upgrade_report('1.6.20', '1.6.21')['update_available'])

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch.object(rc, 'installed_version', return_value='1.6.9'):
            result = actions.check_upgrade(opener=lambda request, timeout: Response(json.dumps(releases).encode()))
        self.assertEqual((result['latest'], result['update_available']), ('1.6.21', True))


class Views(SimpleTestCase):
    def post(self, view, body, admin=0, session=True):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 3} if session else {}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'job_id': 'x'}) as call:
            response = view(request)
        return response.status_code, json.loads(response.content), call

    def test_everything_is_admin_only(self):
        for view in (views.overview, views.preflight, views.install, views.enable, views.disable, views.uninstall,
                     views.upgrade, views.job):
            status, _, call = self.post(view, {'site': 'shop.example.com', 'job': 'ab' * 12})
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()
            self.assertEqual(self.post(view, {}, session=False)[0], 401)

    def test_admin_calls_and_validation(self):
        status, _, call = self.post(views.install, {'site': 'Shop.Example.com'}, admin=1)
        call.assert_called_once_with('roundcube', 'install', site='shop.example.com')
        for bad in ('', 'a;b', '../x', 'x' * 300):
            status, _, call = self.post(views.enable, {'site': bad}, admin=1)
            self.assertEqual(status, 400)
            call.assert_not_called()

    def test_drop_database_needs_explicit_confirmation(self):
        status, _, call = self.post(views.uninstall, {'dropDatabase': True, 'confirmName': 'yes'}, admin=1)
        self.assertEqual(status, 400)
        call.assert_not_called()
        _, _, call = self.post(views.uninstall, {'dropDatabase': 'true', 'confirmName': 'cp_roundcube'}, admin=1)
        self.assertEqual(call.call_args[1], {'drop_database': False, 'confirm_name': ''})
        _, _, call = self.post(views.uninstall, {'dropDatabase': True, 'confirmName': 'cp_roundcube'}, admin=1)
        self.assertEqual(call.call_args[1], {'drop_database': True, 'confirm_name': 'cp_roundcube'})
        with self.assertRaisesRegex(rc.RoundcubeError, 'confirm'):
            actions.uninstall(drop_database=True, confirm_name='nope')

    def test_default_site_is_the_hostname(self):
        self.assertEqual(views.default_site(['a.com', 'host.example.com'], 'host.example.com'), 'host.example.com')
        self.assertEqual(views.default_site(['a.com'], 'localhost'), '')


@override_settings(ROOT_URLCONF=__name__)
class PagesRender(SimpleTestCase):
    def test_page_renders(self):
        request = RequestFactory().get('/addons/roundcube/')
        request.session = {}
        context = {'request': request, 'is_admin': True, 'sites': ['a.com', 'shop.example.com'],
                   'default_site': 'shop.example.com', 'version': rc.VERSION, 'prefix': rc.URL_PREFIX, 'db_name': rc.DB_NAME}
        html = render_to_string('universalAddons/roundcube.html', context)
        self.assertIn('ua-wrap', html)
        self.assertIn('<option value="shop.example.com" selected>', html)
        self.assertIn('roundcube.js', html)
        self.assertIn('data-base="/addons/roundcube/"', html)
        denied = render_to_string('universalAddons/roundcube.html', dict(context, is_admin=False))
        self.assertIn('Administrator access is required', denied)
        self.assertNotIn('rc-install', denied)


class SiteRewriteIsolation(SimpleTestCase):
    def test_roundcube_context_disables_the_sites_rewrites(self):
        from universalAddons.roundcube import service as rcs
        block = rcs.render_vhost_block('/home/example.com', '/usr/local/cp-roundcube/1.6.21')
        main = block[block.index('context /webmail-rc/ {'):]
        self.assertIn('rewrite  {\n    enable                0\n  }', main)
        self.assertEqual(block.count('{'), block.count('}'))
