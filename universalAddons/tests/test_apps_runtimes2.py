"""Ruby/Rails, Kotlin, Go, Deno and Bun apps; runtime sizes and uninstalling (Universal Apps)."""
import hashlib
import io
import json
import os
import shutil
import tempfile
import zipfile
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from universalAddons import access
from universalAddons.apps import actions, runtimes as rt, service as svc, views
from universalAddons.tests.test_apps import AccessControl
from universalAddons.tests.test_runtimes import tarball

SITE = {'domain': 'shop.example.com', 'user': 'shop1234', 'home': '/home/shop.example.com'}
POLICY = dict(access.DEFAULT_POLICY)
APP_DIR = '/home/shop.example.com/apps/web'
RUBY = {'version': '3.4.7', 'path': '/opt/cp-runtimes/ruby/3.4.7/bin/ruby', 'source': 'ruby-lang.org (built here)'}
GO = {'version': '1.25.4', 'path': '/opt/cp-runtimes/go/1.25.4/bin/go'}
DENO = {'version': '2.5.6', 'path': '/opt/cp-runtimes/deno/2.5.6/bin/deno'}
BUN = {'version': '1.3.2', 'path': '/opt/cp-runtimes/bun/1.3.2/bin/bun'}
JRE21 = {'version': '21.0.13', 'path': '/opt/cp-runtimes/java/21.0.13/bin/java', 'source': 'Temurin'}
RUNTIMES = {'ruby': [RUBY], 'go': [GO], 'deno': [DENO], 'bun': [BUN], 'java': [JRE21]}


def spec(**kw):
    base = {'id': 'web', 'kind': 'ruby', 'runtime': '3.4.7', 'prefix': '/'}
    base.update(kw)
    return base


def app(existing=None, **kw):
    record = svc.validate(spec(**kw), SITE, POLICY, existing or {}, RUNTIMES)
    record['port'] = 20011
    return record


def unit_lines(record, runtime):
    return svc.render_unit(record, runtime, 239, False).splitlines()


# ----------------------------------------------------------------------------- catalogue

RUBY_INDEX = '\n'.join('\t'.join(row) for row in [
    ('name', 'url', 'sha1', 'sha256', 'sha512'),
    ('ruby-3.2.9', 'https://cache.ruby-lang.org/pub/ruby/3.2/ruby-3.2.9.tar.gz', '1' * 40, '2' * 64, '3' * 128),
    ('ruby-3.3.9', 'https://cache.ruby-lang.org/pub/ruby/3.3/ruby-3.3.9.tar.gz', '1' * 40, 'a' * 64, 'b' * 128),
    ('ruby-3.3.10', 'https://cache.ruby-lang.org/pub/ruby/3.3/ruby-3.3.10.tar.gz', '1' * 40, 'c' * 64, 'd' * 128),
    ('ruby-3.3.10', 'https://cache.ruby-lang.org/pub/ruby/3.3/ruby-3.3.10.zip', '1' * 40, 'e' * 64, 'f' * 128),
    ('ruby-3.4.7', 'https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.7.tar.gz', '1' * 40, '4' * 64, ''),
    ('ruby-4.0.0-preview2', 'https://cache.ruby-lang.org/pub/ruby/4.0/ruby-4.0.0-preview2.tar.gz', '1' * 40,
     '5' * 64, '6' * 128),
    ('ruby-4.0.1', 'https://cache.ruby-lang.org/pub/ruby/4.0/ruby-4.0.1.tar.gz', '1' * 40, '7' * 64, '8' * 128),
])
GO_INDEX = [
    {'version': 'go1.25.4', 'stable': True, 'files': [
        {'filename': 'go1.25.4.src.tar.gz', 'os': '', 'arch': '', 'kind': 'source', 'sha256': '0' * 64},
        {'filename': 'go1.25.4.linux-amd64.tar.gz', 'os': 'linux', 'arch': 'amd64', 'kind': 'archive',
         'sha256': '9' * 64, 'size': 59000000},
        {'filename': 'go1.25.4.linux-arm64.tar.gz', 'os': 'linux', 'arch': 'arm64', 'kind': 'archive',
         'sha256': '8' * 64}]},
    {'version': 'go1.24.10', 'stable': True, 'files': [
        {'filename': 'go1.24.10.linux-amd64.tar.gz', 'os': 'linux', 'arch': 'amd64', 'kind': 'archive',
         'sha256': '7' * 64}]},
    {'version': 'go1.26rc1', 'stable': False, 'files': []},
]


def gh_asset(prefix, tag, name, digest=None, size=1000):
    asset = {'name': name, 'browser_download_url': prefix + tag + '/' + name, 'size': size}
    if digest:
        asset['digest'] = 'sha256:' + digest
    return asset


DENO_ZIP = 'deno-x86_64-unknown-linux-gnu.zip'


def deno_release(version, sums=True, digest=None, prerelease=False):
    tag = 'v' + version
    assets = [gh_asset(rt.DENO_PREFIX, tag, DENO_ZIP, digest)]
    if sums:
        assets.append(gh_asset(rt.DENO_PREFIX, tag, DENO_ZIP + '.sha256sum'))
    return {'tag_name': tag, 'draft': False, 'prerelease': prerelease, 'assets': assets}


def bun_release(version, digest=None):
    tag = 'bun-v' + version
    return {'tag_name': tag, 'draft': False, 'prerelease': False,
            'assets': [gh_asset(rt.BUN_PREFIX, tag, name, digest if name.endswith('.zip') else None)
                       for name in ('bun-linux-x64.zip', 'bun-linux-x64-baseline.zip', 'bun-linux-aarch64.zip',
                                    'SHASUMS256.txt')]}


class Catalogue(SimpleTestCase):
    def test_ruby_newest_supported_patch_per_minor_from_source_index(self):
        cat = rt.ruby_catalogue(RUBY_INDEX)
        self.assertEqual([e['version'] for e in cat], ['4.0.1', '3.4.7', '3.3.10'])  # no 3.2 (EOL), no preview
        newest, middle, oldest = cat
        self.assertEqual((newest['sha512'], newest['url']),
                         ('8' * 128, 'https://cache.ruby-lang.org/pub/ruby/4.0/ruby-4.0.1.tar.gz'))
        self.assertEqual((middle['sha512'], middle['sha256']), ('', '4' * 64), 'SHA-256 when no SHA-512 is listed')
        self.assertEqual(oldest['sha256'], 'c' * 64, 'the .tar.gz row, not the .zip row')
        self.assertTrue(newest['build'])
        self.assertIn('minutes', newest['estimate'])

    def test_go_stable_linux_archives(self):
        cat = rt.go_catalogue(GO_INDEX, 'x64')
        self.assertEqual([(e['version'], e['sha256'][0]) for e in cat], [('1.25.4', '9'), ('1.24.10', '7')])
        self.assertEqual(cat[0]['url'], 'https://go.dev/dl/go1.25.4.linux-amd64.tar.gz')
        self.assertEqual([e['version'] for e in rt.go_catalogue(GO_INDEX, 'arm64')], ['1.25.4'])

    def test_deno_needs_a_checksum(self):
        releases = [deno_release('2.5.6'), deno_release('2.5.5'), deno_release('2.4.9', sums=False, digest='a' * 64),
                    deno_release('2.3.7', sums=False), deno_release('2.6.0-rc.1', prerelease=True)]
        cat = rt.deno_catalogue(releases, 'x64')
        self.assertEqual([e['version'] for e in cat], ['2.5.6', '2.4.9'])
        self.assertTrue(cat[0]['sums_url'].endswith('/v2.5.6/' + DENO_ZIP + '.sha256sum'))
        self.assertEqual((cat[1]['sums_url'], cat[1]['digest']), ('', 'a' * 64))

    def test_deno_asset_must_come_from_the_deno_repository(self):
        release = deno_release('2.5.6')
        release['assets'][0]['browser_download_url'] = 'https://example.com/v2.5.6/' + DENO_ZIP
        self.assertEqual(rt.deno_catalogue([release]), [])

    def test_bun_baseline_and_kernel_warning(self):
        fast = rt.bun_catalogue([bun_release('1.3.2')], 'x64', avx2=True, kernel=(6, 1))
        self.assertEqual((fast[0]['file'], fast[0].get('warning')), ('bun-linux-x64.zip', None))
        old = rt.bun_catalogue([bun_release('1.3.2')], 'x64', avx2=False, kernel=(4, 18))
        self.assertEqual(old[0]['file'], 'bun-linux-x64-baseline.zip')
        self.assertIn('no AVX2', old[0]['label'])
        self.assertIn('4.18', old[0]['warning'])
        self.assertEqual(rt.kernel_version('4.18.0-348.7.1.el8_5.x86_64'), (4, 18))

    def test_java_jdk_variant(self):
        from universalAddons.tests.test_apps import ADOPTIUM_21
        jdk = json.loads(json.dumps(ADOPTIUM_21))
        jdk[0]['binary']['image_type'] = 'jdk'
        entry = rt.java_catalogue(jdk, 'x64', 'jdk')[0]
        self.assertEqual((entry['variant'], entry['version']), ('jdk', '21.0.13'))
        self.assertIn('Temurin JDK', entry['label'])
        self.assertEqual(rt.java_catalogue(ADOPTIUM_21, 'x64', 'jdk'), [])

    def test_catalogue_lists_every_kind_and_reports_errors_per_kind(self):
        def fetcher(url):
            if url == rt.RUBY_INDEX:
                return RUBY_INDEX.encode()
            if url == rt.GO_INDEX:
                return json.dumps(GO_INDEX).encode()
            if url == rt.DENO_RELEASES:
                return json.dumps([deno_release('2.5.6')]).encode()
            raise OSError('offline')
        with mock.patch.object(rt, 'arch', return_value='x64'):
            cat = rt.catalogue(fetcher)
        self.assertEqual(set(rt.KINDS) - set(cat), set())
        self.assertEqual(cat['ruby'][0]['version'], '4.0.1')
        self.assertEqual(cat['go'][0]['version'], '1.25.4')
        self.assertEqual(cat['deno'][0]['version'], '2.5.6')
        self.assertIn('bun', cat['errors'])
        self.assertNotIn('ruby', cat['errors'])


# ----------------------------------------------------------------------------- verified installs

class _Root(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.files, self.ran = {}, []

    def tearDown(self):
        shutil.rmtree(self.root)

    def fetch_file(self, url, target):
        with open(target, 'wb') as handle:
            handle.write(self.files[url])

    def leftovers(self):
        return [n for n in os.listdir(self.root) if n.startswith('cp-runtime-')]


def zip_bytes(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as bundle:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            bundle.writestr(info, data)
    return buffer.getvalue()


class GoInstall(_Root):
    def install(self, data, sha):
        index = json.loads(json.dumps(GO_INDEX))
        index[0]['files'][1]['sha256'] = sha
        self.files['https://go.dev/dl/go1.25.4.linux-amd64.tar.gz'] = data

        def runner(argv, **kw):
            self.ran.append(argv)
            return SimpleNamespace(returncode=0, stdout='go version go1.25.4 linux/amd64\n')
        with mock.patch.object(rt, 'arch', return_value='x64'):
            return rt.install('go', '1.25.4', self.root, fetcher=lambda url: json.dumps(index).encode(),
                              fetch_file=self.fetch_file, runner=runner)

    def test_verified_pruned_and_smoke_tested(self):
        data = tarball([('go/bin/go', b'#!/bin/sh\n', None), ('go/test/fixedbugs/x.go', b'x', None),
                        ('go/src/fmt/print.go', b'x', None)])
        entry = self.install(data, hashlib.sha256(data).hexdigest())
        self.assertEqual(entry['path'], os.path.join(self.root, 'go', '1.25.4', 'bin', 'go'))
        self.assertFalse(os.path.exists(os.path.join(self.root, 'go', '1.25.4', 'test')))
        self.assertTrue(os.path.exists(os.path.join(self.root, 'go', '1.25.4', 'src', 'fmt', 'print.go')))
        self.assertEqual(self.ran[0][1:], ['version'])
        self.assertTrue(self.ran[0][0].endswith('/tree/bin/go'))
        self.assertEqual(self.leftovers(), [])

    def test_checksum_mismatch_discards(self):
        data = tarball([('go/bin/go', b'#!/bin/sh\n', None)])
        with self.assertRaisesRegex(rt.RuntimeError_, 'Checksum mismatch'):
            self.install(data, '0' * 64)
        self.assertEqual(self.ran, [], 'nothing from an unverified archive is executed')
        self.assertFalse(os.path.exists(os.path.join(self.root, 'go')))
        self.assertEqual(self.leftovers(), [])


class GithubInstall(_Root):
    def deno(self, data, sums_text, digest=None):
        release = deno_release('2.5.6', digest=digest)
        self.files[release['assets'][0]['browser_download_url']] = data
        sums_url = release['assets'][1]['browser_download_url']

        def fetcher(url):
            if url == rt.DENO_RELEASE % '2.5.6':
                return json.dumps(release).encode()
            if url == sums_url:
                return sums_text.encode()
            raise AssertionError(url)

        def runner(argv, **kw):
            self.ran.append(argv)
            return SimpleNamespace(returncode=0, stdout='deno 2.5.6 (stable, release, x86_64-unknown-linux-gnu)\n')
        with mock.patch.object(rt, 'arch', return_value='x64'):
            return rt.install('deno', '2.5.6', self.root, fetcher=fetcher, fetch_file=self.fetch_file, runner=runner)

    def test_deno_verified_against_published_sum(self):
        data = zip_bytes([('deno', b'\x7fELF', 0o644)])
        sha = hashlib.sha256(data).hexdigest()
        entry = self.deno(data, '%s  %s\n' % (sha, DENO_ZIP), digest=sha)
        self.assertEqual(entry['path'], os.path.join(self.root, 'deno', '2.5.6', 'bin', 'deno'))
        self.assertEqual(oct(os.stat(entry['path']).st_mode & 0o777), '0o755')
        self.assertTrue(self.ran[0][0].endswith('/tree/bin/deno'), 'the staged binary is smoke-tested before it is placed')
        self.assertEqual(self.ran[0][1:], ['--version'])

    def test_bare_hash_sum_file_accepted(self):
        data = zip_bytes([('deno', b'\x7fELF', 0o755)])
        self.deno(data, 'Hash: %s\n' % hashlib.sha256(data).hexdigest().upper())

    def test_publisher_and_github_digest_must_agree(self):
        data = zip_bytes([('deno', b'\x7fELF', 0o755)])
        with self.assertRaisesRegex(rt.RuntimeError_, 'disagree'):
            self.deno(data, '%s  %s\n' % (hashlib.sha256(data).hexdigest(), DENO_ZIP), digest='1' * 64)
        self.assertEqual(self.ran, [])
        self.assertEqual(self.leftovers(), [])

    def test_wrong_sum_refused(self):
        data = zip_bytes([('deno', b'\x7fELF', 0o755)])
        with self.assertRaisesRegex(rt.RuntimeError_, 'Checksum mismatch'):
            self.deno(data, '%s  %s\n' % ('2' * 64, DENO_ZIP))
        self.assertFalse(os.path.exists(os.path.join(self.root, 'deno')))

    def test_no_checksum_refused(self):
        with self.assertRaisesRegex(rt.RuntimeError_, 'No checksum'):
            rt.published_sha256({'file': 'x.zip', 'sums_url': '', 'digest': ''}, fetcher=None)
        with self.assertRaisesRegex(rt.RuntimeError_, 'lists no SHA-256'):
            rt.published_sha256({'file': 'bun-linux-x64.zip', 'sums_url': 'https://x/SHASUMS256.txt', 'digest': ''},
                                lambda url: ('%s  bun-darwin-x64.zip\n' % ('a' * 64)).encode())

    def test_bun_from_shasums(self):
        release = bun_release('1.3.2')
        data = zip_bytes([('bun-linux-x64/', b'', 0o40755), ('bun-linux-x64/bun', b'\x7fELF', 0o755)])
        url = [a for a in release['assets'] if a['name'] == 'bun-linux-x64.zip'][0]['browser_download_url']
        sums_url = [a for a in release['assets'] if a['name'] == 'SHASUMS256.txt'][0]['browser_download_url']
        self.files[url] = data
        sums = '%s  bun-linux-x64-baseline.zip\n%s  bun-linux-x64.zip\n' % ('f' * 64, hashlib.sha256(data).hexdigest())

        def fetcher(u):
            return json.dumps(release).encode() if u == rt.BUN_RELEASE % '1.3.2' else sums.encode()
        runner = lambda argv, **kw: SimpleNamespace(returncode=0, stdout='1.3.2\n')
        with mock.patch.object(rt, 'arch', return_value='x64'), mock.patch.object(rt, 'cpu_has_avx2', return_value=True):
            entry = rt.install('bun', '1.3.2', self.root, fetcher=fetcher, fetch_file=self.fetch_file, runner=runner)
        self.assertEqual(entry['path'], os.path.join(self.root, 'bun', '1.3.2', 'bin', 'bun'))

    def test_zip_escapes_and_links_refused(self):
        target = os.path.join(self.root, 'out')
        os.makedirs(target)
        for entries in ([('../evil', b'x', 0o644)], [('/abs', b'x', 0o644)], [('link', b'/etc/passwd', 0o120777)]):
            archive = os.path.join(self.root, 'a.zip')
            with open(archive, 'wb') as handle:
                handle.write(zip_bytes(entries))
            with self.assertRaises(rt.RuntimeError_, msg=entries):
                rt._safe_extract_zip(archive, target)
        self.assertFalse(os.path.exists(os.path.join(self.root, 'evil')))


class RubyInstall(_Root):
    VERSION = '3.4.7'

    def setUp(self):
        super().setUp()
        self.repos = tempfile.mkdtemp()
        with open(os.path.join(self.repos, 'CentOS-Linux-PowerTools.repo'), 'w') as handle:
            handle.write('[powertools]\nname=PowerTools\n')
        for repo in ('baseos', 'appstream'):
            with open(os.path.join(self.repos, repo + '.repo'), 'w') as handle:
                handle.write('[%s]\nname=x\n[%s-source]\n' % (repo, repo))
        with open(os.path.join(self.repos, 'mssql.repo'), 'w') as handle:
            handle.write('[packages-microsoft-com-mssql-server-2022]\n')
        self.installed_rpms = set(rt.RUBY_BUILD_PACKAGES) - {'libyaml-devel'}

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.repos)

    def runner(self, argv, **kw):
        self.ran.append(argv)
        if argv[:3] == ['rpm', '-q', '--quiet']:
            return SimpleNamespace(returncode=0 if argv[3] in self.installed_rpms else 1, stdout='')
        if argv[0] == 'dnf':
            self.installed_rpms.update(a for a in argv if not a.startswith('-') and a not in ('dnf', 'install'))
            return SimpleNamespace(returncode=0, stdout='Installed.\n')
        return SimpleNamespace(returncode=0, stdout=self.VERSION)  # the smoke test: print RUBY_VERSION

    def build(self, argv, cwd, env, log, timeout):
        self.ran.append(('build', argv, env))
        destdir = [a for a in argv if a.startswith('DESTDIR=')]
        if destdir:
            tree = os.path.join(destdir[0][8:], self.root.lstrip('/'), 'ruby', self.VERSION, 'bin')
            os.makedirs(tree)
            for name in ('ruby', 'bundle', 'gem'):
                with open(os.path.join(tree, name), 'w') as handle:
                    handle.write('#!/bin/sh\n')
        return 0, 'ok'

    def install(self, sha512=None):
        data = tarball([('ruby-3.4.7/configure', b'#!/bin/sh\n', None), ('ruby-3.4.7/ruby.c', b'int x;', None)])
        index = RUBY_INDEX.replace('4' * 64 + '\t', '4' * 64 + '\t' + (sha512 or hashlib.sha512(data).hexdigest()))
        self.files['https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.7.tar.gz'] = data
        with mock.patch.object(rt, 'REPO_DIR', self.repos):
            return rt.install('ruby', self.VERSION, self.root, fetcher=lambda url: index.encode(),
                              fetch_file=self.fetch_file, runner=self.runner, build=self.build)

    def test_build_from_verified_source(self):
        entry = self.install()
        self.assertEqual(entry['path'], os.path.join(self.root, 'ruby', '3.4.7', 'bin', 'ruby'))
        self.assertEqual(entry['bundle'], os.path.join(self.root, 'ruby', '3.4.7', 'bin', 'bundle'))
        builds = [step for step in self.ran if step[0] == 'build']
        configure, make, make_install = (step[1] for step in builds)
        self.assertEqual(configure[:6], ['nice', '-n', '19', 'ionice', '-c', '3'])
        self.assertIn('--prefix=%s' % os.path.join(self.root, 'ruby', '3.4.7'), configure)
        self.assertIn('--disable-install-doc', configure)
        self.assertEqual(make[-1], '-j%d' % max(1, min(2, os.cpu_count() or 1)))
        self.assertTrue(builds[0][2]['TMPDIR'].startswith(self.root), '/tmp may be noexec: build in the work dir')
        smoke = [argv for argv in self.ran if argv[0] != 'build' and argv[0].endswith('/bin/ruby')][0]
        self.assertEqual(smoke[1:4], ['-ropenssl', '-rpsych', '-rzlib'])
        self.assertEqual(self.leftovers(), [])

    def test_missing_headers_installed_from_os_repos_and_recorded(self):
        self.install()
        dnf = [argv for argv in self.ran if argv[0] == 'dnf'][0]
        self.assertEqual(dnf, ['dnf', '-y', '-q', 'install', '--disablerepo=*', '--enablerepo=baseos,appstream,powertools',
                               'libyaml-devel'])
        recorded = rt.ledger(self.root)
        self.assertEqual(list(recorded), ['libyaml-devel'], 'only what the panel installed is removable later')
        self.assertEqual(recorded['libyaml-devel']['reason'], 'Ruby build')

    def test_checksum_mismatch_builds_nothing(self):
        with self.assertRaisesRegex(rt.RuntimeError_, 'Checksum mismatch'):
            self.install(sha512='0' * 128)
        self.assertEqual([s for s in self.ran if s[0] == 'build'], [])
        self.assertFalse(os.path.exists(os.path.join(self.root, 'ruby')))
        self.assertEqual(self.leftovers(), [])

    def test_ruby_without_openssl_or_psych_is_not_installed(self):
        with mock.patch.object(self, 'runner', side_effect=lambda argv, **kw: SimpleNamespace(
                returncode=1 if argv[0].endswith('/bin/ruby') else 0, stdout='cannot load such file -- psych')):
            with self.assertRaisesRegex(rt.RuntimeError_, 'psych'):
                self.install()
        self.assertFalse(os.path.exists(os.path.join(self.root, 'ruby')))

    def test_failed_make_reports_tail(self):
        def build(argv, cwd, env, log, timeout):
            return (2, 'ossl.c: fatal error: openssl/ssl.h: No such file') if argv[-1].startswith('-j') else (0, '')
        self.build = build
        with self.assertRaisesRegex(rt.RuntimeError_, 'make -j.*failed.*ssl.h'):
            self.install()

    def test_streamed_build_logs_while_running(self):
        lines = ['compiling %d.c\n' % i for i in range(5)]
        process = mock.Mock(stdout=iter(lines))
        process.wait.return_value = 0
        logged, ticks = [], iter(range(0, 1000, 6))
        code, tail = rt._run_streamed(['make'], '/x', {}, logged.append, 60, popen=lambda *a, **k: process,
                                      clock=lambda: next(ticks))
        self.assertEqual(code, 0)
        self.assertTrue(logged, 'progress reaches the job log during the build')
        self.assertTrue(tail.endswith('compiling 4.c'))


# ----------------------------------------------------------------------------- units

class RubyApps(SimpleTestCase):
    def test_rails_unit(self):
        rails = app(prefix='/shop')
        self.assertEqual((rails['mode'], rails['entry'], rails['workers'], rails['precompile'], rails['migrate']),
                         ('rails', 'config.ru', 1, True, True))
        lines = unit_lines(rails, RUBY)
        self.assertIn('ExecStart=/opt/cp-runtimes/ruby/3.4.7/bin/bundle exec puma --bind tcp://127.0.0.1:20011 '
                      '%s/config.ru' % APP_DIR, lines)
        for line in ('RAILS_ENV=production', 'RACK_ENV=production', 'RAILS_RELATIVE_URL_ROOT=/shop',
                     'APP_BASE_PATH=/shop', 'BUNDLE_DEPLOYMENT=1', 'BUNDLE_PATH=%s/vendor/bundle' % APP_DIR,
                     'BUNDLE_GEMFILE=%s/Gemfile' % APP_DIR, 'BUNDLE_WITHOUT=development:test',
                     'RAILS_SERVE_STATIC_FILES=1', 'RAILS_LOG_TO_STDOUT=1', 'PORT=20011',
                     'PATH=/opt/cp-runtimes/ruby/3.4.7/bin:/usr/bin:/bin'):
            self.assertIn('Environment="%s"' % line, lines)
        self.assertIn('ReadWritePaths=%s' % APP_DIR, lines)
        self.assertFalse([line for line in lines if 'SECRET_KEY_BASE' in line], 'secrets live in the env file only')

    def test_rack_unit_and_workers(self):
        rack = app(mode='rack', workers=3)
        self.assertNotIn('precompile', rack)
        self.assertNotIn('SECRET_KEY_BASE', rack['env'])
        self.assertEqual(svc.exec_argv(rack, RUBY), ['/opt/cp-runtimes/ruby/3.4.7/bin/bundle', 'exec', 'puma', '--bind',
                                                     'tcp://127.0.0.1:20011', '--workers', '3', APP_DIR + '/config.ru'])
        self.assertNotIn('RAILS_RELATIVE_URL_ROOT', svc.render_unit(rack, RUBY), 'site root: no prefix')

    def test_ruby_validation(self):
        for bad, message in ((spec(mode='sinatra'), 'Rack'), (spec(entry='app.rb'), 'rackup'),
                             (spec(entry='../config.ru'), 'rackup'), (spec(runtime='3.1.0'), 'not installed'),
                             (spec(workers=9), 'between 1 and 8')):
            with self.assertRaisesRegex(svc.AppError, message, msg=bad):
                svc.validate(bad, SITE, POLICY, {}, RUNTIMES)
        for key in ('RAILS_RELATIVE_URL_ROOT', 'BUNDLE_PATH', 'BUNDLE_GEMFILE'):
            with self.assertRaises(svc.AppError, msg=key):
                svc.validate_env({key: '/x'})
        self.assertEqual(app(precompile=False)['precompile'], False)


class RailsSecret(SimpleTestCase):
    def test_generated_once_and_kept(self):
        first = app()
        key = first['env']['SECRET_KEY_BASE']
        self.assertRegex(key, r'^[0-9a-f]{128}$')
        again = app(existing={'web': first})
        self.assertEqual(again['env']['SECRET_KEY_BASE'], key, 'editing the app keeps the key')
        resent = app(existing={'web': first}, env={'DATABASE_URL': 'postgres://x'})
        self.assertEqual(resent['env'], {'DATABASE_URL': 'postgres://x', 'SECRET_KEY_BASE': key},
                         'a new variable list without the key keeps the stored key')
        self.assertNotEqual(app()['env']['SECRET_KEY_BASE'], key, 'each app gets its own')
        own = app(env={'SECRET_KEY_BASE': 'mine'})
        self.assertEqual(own['env']['SECRET_KEY_BASE'], 'mine')

    def test_never_returned_by_list_or_save(self):
        record = dict(app(), enabled=True)
        key = record['env']['SECRET_KEY_BASE']
        with mock.patch.object(svc, 'load_apps', return_value={'web': record}), \
                mock.patch.object(svc, 'status', return_value={'state': 'active'}), \
                mock.patch.object(rt, 'installed', return_value={'ruby': [RUBY]}):
            listed = actions.list_apps()
        self.assertNotIn(key, json.dumps(listed))
        self.assertEqual(listed['apps'][0]['env_keys'], ['SECRET_KEY_BASE'])
        with mock.patch.object(actions, '_site', return_value=SITE), \
                mock.patch.object(svc, 'load_apps', return_value={}), mock.patch.object(svc, 'save_apps') as saved, \
                mock.patch.object(svc, 'allocate_port', return_value=20011), \
                mock.patch.object(rt, 'installed', return_value=RUNTIMES), \
                mock.patch.object(actions, 'load_policy', return_value=POLICY), \
                mock.patch.object(actions, '_write_unit'), mock.patch('os.path.isdir', return_value=True):
            result = actions.save_app('shop.example.com', spec())
        stored = saved.call_args[0][0]['web']['env']['SECRET_KEY_BASE']
        self.assertRegex(stored, r'^[0-9a-f]{128}$')
        self.assertNotIn(stored, json.dumps(result))
        self.assertNotIn('env', result['app'])


class RubyDeploy(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.app = dict(app(env={'DATABASE_URL': 'postgres://u:secretpw@db/x'}), dir=self.dir)
        for name, body in (('Gemfile', "gem 'rails'\n"), ('config.ru', 'run Rails.application\n'),
                           ('Gemfile.lock', 'GEM\n  specs:\n    puma (7.1.0)\n    rails (8.1.1)\n')):
            with open(os.path.join(self.dir, name), 'w') as handle:
                handle.write(body)
        os.makedirs(os.path.join(self.dir, 'app', 'assets'))
        self.calls = []

    def tearDown(self):
        shutil.rmtree(self.dir)

    def runner(self, argv, **kw):
        self.calls.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout='')

    def commands(self):
        return [argv[argv.index('env') + 2:] for argv, kw in self.calls]

    def test_bundle_deployment_precompile_migrate_as_site_user(self):
        svc.install_dependencies(self.app, RUBY, runner=self.runner)
        bundle = '/opt/cp-runtimes/ruby/3.4.7/bin/bundle'
        self.assertEqual(self.commands(), [
            [bundle, 'config', 'set', '--local', 'deployment', 'true'],
            [bundle, 'config', 'set', '--local', 'path', 'vendor/bundle'],
            [bundle, 'config', 'set', '--local', 'without', 'development test'],
            [bundle, 'install', '--jobs', '2'],
            [bundle, 'exec', 'rails', 'assets:precompile'],
            [bundle, 'exec', 'rails', 'db:migrate']])
        argv, kw = self.calls[-1]
        self.assertEqual(argv[:3], ['sudo', '-u', 'shop1234'])
        self.assertEqual(kw['cwd'], self.dir)
        self.assertEqual(kw['env']['SECRET_KEY_BASE'], self.app['env']['SECRET_KEY_BASE'])
        self.assertEqual((kw['env']['RAILS_ENV'], kw['env']['HOME']), ('production', '/home/shop.example.com'))
        command_line = ' '.join(' '.join(a) for a, k in self.calls)
        self.assertNotIn('secretpw', command_line, 'values never on a command line')
        self.assertNotIn(self.app['env']['SECRET_KEY_BASE'], command_line)
        self.assertIn('--preserve-env=', command_line)
        self.assertIn('PATH=/opt/cp-runtimes/ruby/3.4.7/bin:/usr/bin:/bin', argv)

    def test_switches_and_api_only_apps(self):
        shutil.rmtree(os.path.join(self.dir, 'app'))
        logged = []
        svc.install_dependencies(dict(self.app, migrate=False), RUBY, runner=self.runner, log=logged.append)
        self.assertEqual(self.commands()[-1][1:], ['install', '--jobs', '2'])
        self.assertTrue(any('skipped' in line for line in logged))

    def test_rack_runs_no_rails_tasks(self):
        svc.install_dependencies(dict(self.app, mode='rack'), RUBY, runner=self.runner)
        self.assertNotIn('rails', ' '.join(' '.join(c) for c in self.commands()))

    def test_lockfile_and_puma_required(self):
        with open(os.path.join(self.dir, 'Gemfile.lock'), 'w') as handle:
            handle.write('GEM\n  specs:\n    rails (8.1.1)\n')
        with self.assertRaisesRegex(svc.AppError, 'bundle add puma'):
            svc.install_dependencies(self.app, RUBY, runner=self.runner)
        os.unlink(os.path.join(self.dir, 'Gemfile.lock'))
        with self.assertRaisesRegex(svc.AppError, 'Gemfile.lock'):
            svc.install_dependencies(self.app, RUBY, runner=self.runner)
        self.assertEqual(self.calls, [])

    def test_failure_stops_the_deploy(self):
        with self.assertRaisesRegex(svc.AppError, 'bundle install failed'):
            svc.install_dependencies(self.app, RUBY, runner=lambda argv, **kw: SimpleNamespace(
                returncode=1 if 'install' in argv else 0, stdout='Could not find gem'))


class KotlinApps(SimpleTestCase):
    def kotlin(self, **kw):
        return app(**dict(dict(kind='java', runtime='21.0.13', flavor='kotlin', entry='build/libs/app-all.jar',
                               memory_mb=512), **kw))

    def test_ktor_jar_reuses_the_java_runner(self):
        ktor = self.kotlin(build='shadowJar', ktor_args=True)
        self.assertEqual((ktor['kind'], ktor['flavor'], ktor['build'], ktor['ktor_args']), ('java', 'kotlin', 'shadowJar', True))
        self.assertIn('ExecStart=/opt/cp-runtimes/java/21.0.13/bin/java -Xmx384m -XX:+UseSerialGC -Djava.io.tmpdir=/tmp '
                      '-jar %s/build/libs/app-all.jar -host=127.0.0.1 -port=20011' % APP_DIR, unit_lines(ktor, JRE21))
        spring = self.kotlin(build='bootJar', entry='build/libs/app.jar')
        argv = svc.exec_argv(spring, JRE21)
        self.assertEqual(argv[-2:], ['-jar', APP_DIR + '/build/libs/app.jar'])
        self.assertIn('Environment="SERVER_PORT=20011"', unit_lines(spring, JRE21))

    def test_kotlin_validation(self):
        for bad, message in ((dict(build='assemble'), 'shadowJar or bootJar'), (dict(flavor='scala'), 'Kotlin'),
                             (dict(build='bootJar', mode='war', entry='app.war'), 'choose the JAR')):
            with self.assertRaisesRegex(svc.AppError, message, msg=bad):
                self.kotlin(**bad)
        self.assertFalse(self.kotlin(mode='war', entry='app.war', ktor_args=True)['ktor_args'])
        plain = app(kind='java', runtime='21.0.13', entry='app.jar')
        self.assertEqual((plain['flavor'], plain['build']), ('java', ''))

    def test_gradle_build_needs_a_jdk(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        jdk = os.path.join(directory, 'jdk')
        os.makedirs(os.path.join(jdk, 'bin'))
        for name in ('java', 'javac'):
            open(os.path.join(jdk, 'bin', name), 'w').close()
        project = os.path.join(directory, 'p')
        os.makedirs(os.path.join(project, 'build', 'libs'))
        for name in ('gradlew', 'build/libs/app-all.jar'):
            open(os.path.join(project, name), 'w').close()
        record = dict(self.kotlin(build='shadowJar'), dir=project)
        calls = []

        def runner(argv, **kw):
            calls.append((argv, kw))
            return SimpleNamespace(returncode=0, stdout='BUILD SUCCESSFUL')
        with self.assertRaisesRegex(svc.AppError, 'Temurin JDK'):
            svc.install_dependencies(record, JRE21, runner=runner)
        self.assertEqual(calls, [])
        svc.install_dependencies(record, dict(JRE21, path=os.path.join(jdk, 'bin', 'java')), runner=runner)
        gradle, kw = calls[0]
        self.assertEqual(gradle[:4], ['sudo', '-u', 'shop1234', '--'])
        self.assertIn('JAVA_HOME=%s' % jdk, gradle)
        self.assertEqual(gradle[-8:], ['/bin/sh', project + '/gradlew', '--no-daemon', '--console=plain', '-p', project,
                                       '-Pkotlin.compiler.execution.strategy=in-process', 'shadowJar'])
        self.assertEqual(kw['cwd'], project)
        self.assertEqual(calls[-1][0][-3:], ['test', '-r', project + '/build/libs/app-all.jar'])


class GoApps(SimpleTestCase):
    def test_binary_needs_no_toolchain(self):
        binary = app(kind='go', runtime='', entry='bin/server')
        self.assertEqual((binary['build'], binary['runtime']), (False, ''))
        lines = unit_lines(binary, {})
        self.assertIn('ExecStart=%s/bin/server' % APP_DIR, lines)
        for line in ('PORT=20011', 'HOST=127.0.0.1', 'GOMAXPROCS=1', 'GOMEMLIMIT=230MiB', 'PATH=/usr/bin:/bin'):
            self.assertIn('Environment="%s"' % line, lines)
        self.assertIn('Environment="GOMAXPROCS=2"', unit_lines(dict(binary, cpu_percent=150), {}))

    def test_go_build_step(self):
        with self.assertRaisesRegex(svc.AppError, 'not installed'):
            app(kind='go', runtime='', build=True)
        built = app(kind='go', runtime='1.25.4', build=True, package='./cmd/server', entry='server')
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        for name in ('go.mod', 'server'):
            open(os.path.join(directory, name), 'w').close()
        calls = []
        svc.install_dependencies(dict(built, dir=directory), GO, runner=lambda argv, **kw: calls.append(argv) or
                                 SimpleNamespace(returncode=0, stdout=''))
        build = calls[0]
        self.assertEqual(build[-6:], [GO['path'], 'build', '-trimpath', '-o', directory + '/server', './cmd/server'])
        for setting in ('GOTOOLCHAIN=local', 'CGO_ENABLED=0', 'GOPATH=/home/shop.example.com/go'):
            self.assertIn(setting, build)
        self.assertEqual(calls[1][-2:], ['clean', '-cache'])
        self.assertEqual(calls[-1][-3:], ['test', '-x', directory + '/server'])

    def test_go_validation(self):
        for bad in (dict(package='../other'), dict(package='/abs'), dict(package='./a/../../b'), dict(entry='../x')):
            with self.assertRaises(svc.AppError, msg=bad):
                app(**dict(dict(kind='go', runtime=''), **bad))
        self.assertEqual(app(kind='go', runtime='', package='./...')['package'], './...')


class DenoBunApps(SimpleTestCase):
    def test_deno_run_scoped_permissions(self):
        deno = app(kind='deno', runtime='2.5.6', entry='main.ts', prefix='/api')
        lines = unit_lines(deno, DENO)
        self.assertIn('ExecStart=/opt/cp-runtimes/deno/2.5.6/bin/deno run --no-prompt --allow-net --allow-env '
                      '--allow-read={0} --allow-write={0} {0}/main.ts'.format(APP_DIR), lines)
        for line in ('PORT=20011', 'DENO_DIR=%s/.deno' % APP_DIR, 'APP_BASE_PATH=/api', 'DENO_NO_UPDATE_CHECK=1'):
            self.assertIn('Environment="%s"' % line, lines)

    def test_deno_serve_and_all_permissions(self):
        serve = app(kind='deno', runtime='2.5.6', mode='serve', deno_perms='all', entry='server.ts')
        self.assertEqual(svc.exec_argv(serve, DENO), [DENO['path'], 'serve', '--host', '127.0.0.1', '--port', '20011',
                                                      '--allow-all', APP_DIR + '/server.ts'])
        for bad in (dict(mode='compile'), dict(deno_perms='none'), dict(entry='../x.ts')):
            with self.assertRaises(svc.AppError, msg=bad):
                app(**dict(dict(kind='deno', runtime='2.5.6'), **bad))

    def test_bun_entry_and_start_script(self):
        bun = app(kind='bun', runtime='1.3.2', entry='src/index.ts')
        lines = unit_lines(bun, BUN)
        self.assertIn('ExecStart=/opt/cp-runtimes/bun/1.3.2/bin/bun %s/src/index.ts' % APP_DIR, lines)
        self.assertIn('Environment="BUN_RUNTIME_TRANSPILER_CACHE_PATH=0"', lines)
        self.assertIn('Environment="NODE_ENV=production"', lines)
        start = app(kind='bun', runtime='1.3.2', entry='bun-start')
        self.assertEqual(svc.exec_argv(start, BUN), [BUN['path'], 'run', 'start'])

    def test_bun_install_frozen_lockfile(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        for name in ('package.json', 'bun.lock', 'index.ts'):
            open(os.path.join(directory, name), 'w').close()
        calls = []
        svc.install_dependencies(dict(app(kind='bun', runtime='1.3.2'), dir=directory), BUN,
                                 runner=lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0, stdout=''))
        self.assertEqual(calls[0][-3:], ['install', '--production', '--frozen-lockfile'])
        self.assertFalse(os.path.exists(os.path.join(directory, '.bun-cache')))

    def test_unsafe_tokens_still_refused(self):
        deno = app(kind='deno', runtime='2.5.6')
        deno['entry'] = 'main.ts --allow-run'
        with self.assertRaisesRegex(svc.AppError, 'Unsafe'):
            svc.render_unit(deno, DENO)


# ----------------------------------------------------------------------------- sizes and uninstalling

class Sizes(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_size_on_disk_counts_hard_links_once_and_skips_link_targets(self):
        tree = os.path.join(self.root, 'tree')
        os.makedirs(os.path.join(tree, 'lib'))
        with open(os.path.join(tree, 'lib', 'big'), 'wb') as handle:
            handle.write(b'x' * 300000)
        os.link(os.path.join(tree, 'lib', 'big'), os.path.join(tree, 'lib', 'big-again'))
        os.symlink('/usr', os.path.join(tree, 'usr-link'))
        expected = sum(os.lstat(p).st_blocks * 512 for p in (tree, os.path.join(tree, 'lib'),
                                                             os.path.join(tree, 'lib', 'big'),
                                                             os.path.join(tree, 'usr-link')))
        self.assertEqual(rt._du(tree), expected)
        self.assertLess(rt._du(tree), 2 * 300000, 'the hard link is not counted twice')
        self.assertEqual(rt._du(os.path.join(self.root, 'missing')), 0)

    def test_installed_reports_new_kinds_with_sizes(self):
        for kind, binary in (('ruby', 'bin/ruby'), ('go', 'bin/go'), ('deno', 'bin/deno'), ('bun', 'bin/bun')):
            path = os.path.join(self.root, kind, '1.2.3', binary)
            os.makedirs(os.path.dirname(path))
            with open(path, 'wb') as handle:
                handle.write(b'x' * 5000)
        os.makedirs(os.path.join(self.root, 'go', 'cp-partial', 'bin'))  # not a version: ignored
        with mock.patch.object(rt, 'system_pythons', return_value=[]), mock.patch.object(rt, 'system_nodes', return_value=[]), \
                mock.patch.object(rt, 'system_javas', return_value=[]):
            found = rt.installed(self.root)
        for kind in ('ruby', 'go', 'deno', 'bun'):
            self.assertEqual([e['version'] for e in found[kind]], ['1.2.3'], kind)
            self.assertGreaterEqual(found[kind][0]['size'], 5000)
            self.assertEqual(found[kind][0]['size'], rt._du(os.path.join(self.root, kind, '1.2.3')))

    def test_jdk_detected(self):
        for name in ('java', 'javac'):
            path = os.path.join(self.root, 'java', '21.0.13', 'bin', name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, 'w').close()
        with mock.patch.object(rt, 'system_pythons', return_value=[]), mock.patch.object(rt, 'system_nodes', return_value=[]), \
                mock.patch.object(rt, 'system_javas', return_value=[]):
            java = rt.installed(self.root)['java'][0]
        self.assertEqual((java['jdk'], java['source']), (True, 'Temurin JDK'))
        with self.assertRaisesRegex(rt.RuntimeError_, 'already installed as a JDK'):
            rt.install('java', '21.0.13', self.root, fetcher=lambda url: b'[]')

    def test_system_runtime_annotated_with_its_package(self):
        installed = {'java': [{'kind': 'java', 'version': '8.0.312', 'path': '/usr/bin/java', 'source': 'system'}]}
        runner = lambda argv, **kw: SimpleNamespace(returncode=0, stdout='java-1.8.0-openjdk-headless\t118000000\n')
        with mock.patch.object(rt, 'ledger', return_value={}):
            rt.annotate_system(installed, self.root, runner)
        self.assertEqual({k: installed['java'][0][k] for k in ('package', 'size', 'panel_installed')},
                         {'package': 'java-1.8.0-openjdk-headless', 'size': 118000000, 'panel_installed': False})


class Uninstall(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_in_use_runtime_refused_with_app_list(self):
        os.makedirs(os.path.join(self.root, 'ruby', '3.4.7', 'bin'))
        with self.assertRaisesRegex(rt.RuntimeError_, 'used by: blog, shop'):
            rt.uninstall('ruby', '3.4.7', ['shop', 'blog'], self.root)
        self.assertTrue(os.path.isdir(os.path.join(self.root, 'ruby', '3.4.7')))
        for kind in ('ruby', 'go', 'deno', 'bun'):
            os.makedirs(os.path.join(self.root, kind, '1.0.0'), exist_ok=True)
            rt.uninstall(kind, '1.0.0', [], self.root)
            self.assertFalse(os.path.exists(os.path.join(self.root, kind, '1.0.0')))
        with self.assertRaisesRegex(rt.RuntimeError_, 'not installed by the panel'):
            rt.uninstall('go', '9.9.9', [], self.root)

    def test_action_lists_apps_using_it(self):
        apps = {'shop': {'id': 'shop', 'kind': 'ruby', 'runtime': '3.4.7'},
                'api': {'id': 'api', 'kind': 'go', 'runtime': ''},
                'kt': {'id': 'kt', 'kind': 'java', 'runtime': '21.0.13', 'flavor': 'kotlin'}}
        os.makedirs(os.path.join(self.root, 'ruby', '3.4.7'))
        with mock.patch.object(svc, 'load_apps', return_value=apps), mock.patch.object(rt, 'RUNTIME_ROOT', self.root), \
                mock.patch.object(rt, 'installed', return_value={'ruby': [RUBY]}), \
                mock.patch.object(rt, 'uninstall', wraps=rt.uninstall) as removal:  # refuses before touching files
            with self.assertRaisesRegex(rt.RuntimeError_, 'used by: shop'):
                actions.runtime_uninstall('ruby', '3.4.7')
        removal.assert_called_once_with('ruby', '3.4.7', ['shop'])
        self.assertEqual(actions._apps_using(apps.values(), 'java', '21.0.13'), ['kt'], 'Kotlin apps use Java runtimes')
        self.assertEqual(actions._apps_using(apps.values(), 'go', ''), ['api'])

    def test_os_package_not_installed_by_the_panel_is_refused(self):
        system = {'kind': 'java', 'version': '8.0.312', 'path': '/usr/bin/java', 'source': 'system'}
        with mock.patch.object(svc, 'load_apps', return_value={}), mock.patch.object(rt, 'RUNTIME_ROOT', self.root), \
                mock.patch.object(rt, 'installed', return_value={'java': [system]}), \
                mock.patch.object(rt, 'rpm_info', return_value={'package': 'java-1.8.0-openjdk-headless', 'size': 1}), \
                mock.patch.object(rt, 'ledger', return_value={}), mock.patch.object(rt, 'remove_package') as removal:
            with self.assertRaisesRegex(svc.AppError, 'IndiansCloud did not install it'):
                actions.runtime_uninstall('java', '8.0.312')
        removal.assert_not_called()

    def test_panel_installed_package_removal(self):
        rt._ledger_write(self.root, {'libyaml-devel': {'reason': 'Ruby build', 'installed': 1}})
        ran = []

        def runner(argv, **kw):
            ran.append(argv)
            if argv[:2] == ['rpm', '-q']:
                return SimpleNamespace(returncode=0, stdout='libyaml-devel\t40000\n')
            return SimpleNamespace(returncode=0, stdout='')
        with self.assertRaisesRegex(rt.RuntimeError_, 'needed to deploy: shop'):
            rt.remove_package('libyaml-devel', ['shop'], self.root, runner)
        with self.assertRaisesRegex(rt.RuntimeError_, 'Only OS packages installed by IndiansCloud'):
            rt.remove_package('glibc', [], self.root, runner)
        self.assertEqual(ran, [])
        self.assertEqual(rt.remove_package('libyaml-devel', [], self.root, runner), {'removed': 'libyaml-devel'})
        self.assertEqual(ran[1:], [['rpm', '-e', '--test', 'libyaml-devel'], ['rpm', '-e', 'libyaml-devel']],
                         'exactly that package, never dnf autoremove')
        self.assertEqual(rt.ledger(self.root), {})

    def test_package_with_dependants_refused(self):
        rt._ledger_write(self.root, {'gcc': {'reason': 'Ruby build'}})

        def runner(argv, **kw):
            if argv[:3] == ['rpm', '-e', '--test']:
                return SimpleNamespace(returncode=1, stdout='gcc is needed by (installed) gcc-c++')
            return SimpleNamespace(returncode=0, stdout='gcc\t1000\n')
        with self.assertRaisesRegex(rt.RuntimeError_, 'gcc-c\\+\\+'):
            rt.remove_package('gcc', [], self.root, runner)
        self.assertIn('gcc', rt.ledger(self.root))

    def test_overview_flags_removable_entries(self):
        apps = {'shop': {'id': 'shop', 'kind': 'ruby', 'runtime': '3.4.7'}}
        installed = {'ruby': [dict(RUBY, size=80000000), dict(RUBY, version='3.3.10', size=79000000)],
                     'java': [{'kind': 'java', 'version': '8.0.312', 'path': '/usr/bin/java', 'source': 'system'}]}
        with mock.patch.object(svc, 'load_apps', return_value=apps), \
                mock.patch.object(rt, 'installed', return_value=installed), \
                mock.patch.object(rt, 'rpm_info', return_value={'package': 'java-1.8.0-openjdk-headless', 'size': 9}), \
                mock.patch.object(rt, 'ledger', return_value={}), \
                mock.patch.object(rt, 'panel_packages', return_value=[{'name': 'gcc', 'size': 1}, {'name': 'other'}]), \
                mock.patch.object(actions, 'load_policy', return_value=POLICY), \
                mock.patch.object(actions, '_disk_free_mb', return_value=20000):
            overview = actions.runtimes_overview()
        ruby = {e['version']: e for e in overview['installed']['ruby']}
        self.assertEqual((ruby['3.4.7']['used_by'], ruby['3.4.7']['removable']), (['shop'], False))
        self.assertEqual((ruby['3.3.10']['used_by'], ruby['3.3.10']['removable']), ([], True))
        self.assertFalse(overview['installed']['java'][0]['removable'], 'OS package the panel did not install')
        self.assertEqual([p['used_by'] for p in overview['packages']], [['shop'], []])

    def test_free_disk_checked_per_kind_before_the_job(self):
        with mock.patch.object(actions, '_disk_free_mb', return_value=1500), \
                mock.patch.object(actions.jobs, 'spawn', return_value={'job_id': 'x'}) as spawn:
            with self.assertRaisesRegex(svc.AppError, 'needs 2048 MB'):
                actions.runtime_install('ruby', '3.4.7')
            spawn.assert_not_called()
            actions.runtime_install('go', '1.25.4')
            actions.runtime_install('java', '21.0.13', 'jdk')
        self.assertEqual(spawn.call_args_list[0][0], ('apps', 'runtime_install_run',
                                                      {'kind': 'go', 'version': '1.25.4', 'variant': ''}))
        self.assertEqual(spawn.call_args_list[1][0][2]['variant'], 'jdk')


class Views(SimpleTestCase):
    def test_new_kinds_admin_only(self):
        for kind, version in (('ruby', '3.4.7'), ('go', '1.25.4'), ('deno', '2.5.6'), ('bun', '1.3.2')):
            status, body, call = AccessControl.post(self, views.runtime_install, {'kind': kind, 'version': version}, admin=1)
            self.assertEqual(status, 200, kind)
            call.assert_called_once_with('apps', 'runtime_install', kind=kind, version=version)
            status, body, call = AccessControl.post(self, views.runtime_install, {'kind': kind, 'version': version},
                                                    policy={'apps_for_users': True})
            self.assertEqual(status, 403)
            call.assert_not_called()
        status, body, call = AccessControl.post(self, views.package_uninstall, {'name': 'gcc'}, policy={'apps_for_users': True})
        self.assertEqual(status, 403)

    def test_jdk_variant_and_bad_input(self):
        status, body, call = AccessControl.post(self, views.runtime_install,
                                                {'kind': 'java', 'version': '21.0.13', 'variant': 'jdk'}, admin=1)
        call.assert_called_once_with('apps', 'runtime_install', kind='java', version='21.0.13', variant='jdk')
        for bad in ({'kind': 'go', 'version': '1.25.4', 'variant': 'jdk'}, {'kind': 'java', 'version': '21', 'variant': 'x'},
                    {'kind': 'perl', 'version': '5.40.0'}):
            status, body, call = AccessControl.post(self, views.runtime_install, bad, admin=1)
            self.assertEqual(status, 400, bad)
        status, body, call = AccessControl.post(self, views.package_uninstall, {'name': 'gcc; rm -rf /'}, admin=1)
        self.assertEqual(status, 400)
        status, body, call = AccessControl.post(self, views.package_uninstall, {'name': 'libyaml-devel'}, admin=1)
        call.assert_called_once_with('apps', 'package_uninstall', name='libyaml-devel')

    def test_new_fields_reach_validation(self):
        status, body, call = AccessControl.post(self, views.save, {
            'domain': 'shop.example.com', 'id': 'web', 'kind': 'java', 'flavor': 'kotlin', 'build': 'shadowJar',
            'ktor_args': True, 'precompile': False, 'deno_perms': 'all', 'package': './cmd'}, admin=1)
        sent = call.call_args[1]['spec']
        self.assertEqual({k: sent[k] for k in ('flavor', 'build', 'ktor_args', 'precompile', 'deno_perms', 'package')},
                         {'flavor': 'kotlin', 'build': 'shadowJar', 'ktor_args': True, 'precompile': False,
                          'deno_perms': 'all', 'package': './cmd'})
