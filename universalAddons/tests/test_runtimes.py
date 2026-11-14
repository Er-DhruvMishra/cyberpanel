import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest

from universalAddons.apps import runtimes as rt

NODE_INDEX = [
    {'version': 'v27.0.0', 'lts': False, 'files': ['linux-x64']},
    {'version': 'v26.13.1', 'lts': 'Lithium', 'files': ['linux-x64', 'linux-arm64']},
    {'version': 'v26.13.0', 'lts': 'Lithium', 'files': ['linux-x64']},
    {'version': 'v24.22.3', 'lts': 'Krypton', 'files': ['linux-x64']},
    {'version': 'v22.23.5', 'lts': 'Jod', 'files': ['linux-arm64']},
]
DOTNET_INDEX = {'releases-index': [
    {'channel-version': '11.0', 'support-phase': 'active', 'latest-runtime': '11.0.0', 'releases.json': 'u11'},
    {'channel-version': '9.0', 'support-phase': 'eol', 'latest-runtime': '9.0.23', 'releases.json': 'u9'},
    {'channel-version': '10.0', 'support-phase': 'active', 'latest-runtime': '10.0.15', 'releases.json': 'u10'},
]}
PY_SUMS = '\n'.join([
    'a' * 64 + '  cpython-3.13.18+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz',
    'b' * 64 + '  cpython-3.13.17+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz',
    'c' * 64 + '  cpython-3.13.18+20261110-x86_64-unknown-linux-gnu-install_only.tar.gz',
    'd' * 64 + '  cpython-3.9.25+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz',
    'e' * 64 + '  cpython-3.12.16+20261110-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz',
])


def tarball(entries):
    """entries: list of (name, data|None for dir, linkname|None)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as bundle:
        for name, data, link in entries:
            info = tarfile.TarInfo(name)
            if link is not None:
                info.type, info.linkname = tarfile.SYMTYPE, link
                bundle.addfile(info)
            elif data is None:
                info.type = tarfile.DIRTYPE
                bundle.addfile(info)
            else:
                info.size = len(data)
                info.mode = 0o755
                bundle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class Catalogue(unittest.TestCase):
    def test_node_latest_lts_per_major_for_arch(self):
        versions = [c['version'] for c in rt.node_catalogue(NODE_INDEX, 'x64')]
        self.assertEqual(versions, ['26.13.1', '24.22.3'])
        self.assertEqual([c['version'] for c in rt.node_catalogue(NODE_INDEX, 'arm64')], ['26.13.1', '22.23.5'])

    def test_dotnet_supported_channels_only(self):
        self.assertEqual([c['version'] for c in rt.dotnet_catalogue(DOTNET_INDEX)], ['11.0.0', '10.0.15'])

    def test_python_stripped_newest_patch_per_minor(self):
        cat = rt.python_catalogue(PY_SUMS, 'x86_64')
        self.assertEqual([(c['version'], c['sha256'][0], c['tag']) for c in cat], [('3.13.18', 'a', '20261110')])
        self.assertEqual([c['version'] for c in rt.python_catalogue(PY_SUMS, 'aarch64')], ['3.12.16'])

    def test_catalogue_reports_errors_per_kind(self):
        def fetcher(url):
            if 'nodejs' in url:
                raise OSError('offline')
            return json.dumps(DOTNET_INDEX).encode() if 'dotnet' in url else PY_SUMS.encode()
        cat = rt.catalogue(fetcher)
        self.assertIn('node', cat['errors'])
        self.assertTrue(cat['dotnet'])


class Installing(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.files = {}

    def tearDown(self):
        shutil.rmtree(self.root)

    def fetch_file(self, url, target):
        with open(target, 'wb') as handle:
            handle.write(self.files[url])

    def node_fixture(self, version, body, digest=None):
        name = 'node-v%s-linux-%s.tar.xz' % (version, rt.arch())
        data = tarball([('node/bin/node', body, None), ('node/include/node.h', b'x', None),
                        ('node/lib/node_modules/npm/bin/npm-cli.js', b'x', None)])
        url = rt.NODE_DIST % ('v' + version) + name
        self.files[url] = data
        sums = '%s  %s\n' % (digest or hashlib.sha256(data).hexdigest(), name)
        return lambda u: sums.encode()

    def test_node_install_verifies_prunes_and_smoke_tests(self):
        fetcher = self.node_fixture('24.1.0', b'#!/bin/sh\necho v24.1.0\n')
        entry = rt.install('node', '24.1.0', self.root, fetcher=fetcher, fetch_file=self.fetch_file)
        self.assertEqual(entry['version'], '24.1.0')
        self.assertFalse(os.path.exists(os.path.join(self.root, 'node', '24.1.0', 'include')))
        self.assertEqual(oct(os.stat(entry['path']).st_mode & 0o777), '0o755')
        self.assertEqual([n for n in os.listdir(self.root) if n.startswith('cp-runtime-')], [])

    def test_checksum_mismatch_discards(self):
        fetcher = self.node_fixture('24.1.0', b'#!/bin/sh\necho hi\n', digest='0' * 64)
        with self.assertRaisesRegex(rt.RuntimeError_, 'Checksum mismatch'):
            rt.install('node', '24.1.0', self.root, fetcher=fetcher, fetch_file=self.fetch_file)
        self.assertFalse(os.path.exists(os.path.join(self.root, 'node', '24.1.0')))

    def test_binary_that_cannot_run_is_removed(self):
        fetcher = self.node_fixture('26.0.0', b'#!/bin/sh\necho "GLIBC_2.34 not found" >&2\nexit 127\n')
        with self.assertRaisesRegex(rt.RuntimeError_, 'does not run on this server.*GLIBC_2.34'):
            rt.install('node', '26.0.0', self.root, fetcher=fetcher, fetch_file=self.fetch_file)
        self.assertFalse(os.path.exists(os.path.join(self.root, 'node', '26.0.0')))

    def test_safe_extract_rejects_escapes(self):
        for entries in ([('x/../../etc/evil', b'x', None)], [('x/link', None, '/etc')], [('/abs', b'x', None)]):
            archive = os.path.join(self.root, 'a.tar.gz')
            with open(archive, 'wb') as handle:
                handle.write(tarball(entries))
            target = os.path.join(self.root, 'out')
            os.makedirs(target, exist_ok=True)
            with self.assertRaises(rt.RuntimeError_, msg=entries):
                rt._safe_extract(archive, target, strip=0 if entries[0][0].startswith('/') else 1)

    def test_invalid_requests(self):
        for kind, version in (('ruby', '3.3.0'), ('node', '24; rm -rf /'), ('node', '../../x')):
            with self.assertRaises(rt.RuntimeError_):
                rt.install(kind, version, self.root)

    def test_uninstall_refuses_in_use(self):
        os.makedirs(os.path.join(self.root, 'node', '24.1.0', 'bin'))
        with self.assertRaisesRegex(rt.RuntimeError_, 'used by: shop'):
            rt.uninstall('node', '24.1.0', ['shop'], self.root)
        rt.uninstall('node', '24.1.0', [], self.root)
        self.assertFalse(os.path.exists(os.path.join(self.root, 'node', '24.1.0')))

    def test_prune_python_keeps_headers(self):
        tree = os.path.join(self.root, 'py')
        for path in ('include/python3.13/Python.h', 'lib/tcl8.6/init.tcl', 'lib/libtk8.6.so',
                     'lib/python3.13/idlelib/x.py', 'lib/python3.13/json/__init__.py', 'share/man/man1/p.1'):
            os.makedirs(os.path.dirname(os.path.join(tree, path)), exist_ok=True)
            open(os.path.join(tree, path), 'w').close()
        rt._prune_python(tree)
        self.assertTrue(os.path.exists(os.path.join(tree, 'include/python3.13/Python.h')))
        self.assertTrue(os.path.exists(os.path.join(tree, 'lib/python3.13/json/__init__.py')))
        for gone in ('lib/tcl8.6', 'lib/libtk8.6.so', 'lib/python3.13/idlelib', 'share/man'):
            self.assertFalse(os.path.exists(os.path.join(tree, gone)), gone)


if __name__ == '__main__':
    unittest.main()
