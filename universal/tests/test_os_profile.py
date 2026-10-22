"""Universal OS profile mapping: Python table, shell table, and their agreement.

Run: python3 universal/tests/test_os_profile.py
"""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import cyberpanel_os_profile as osp  # noqa: E402

# os-release content -> (profile os, profile version, native)
CASES = {
    'centos8': ('ID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="8"\n', ('CentOS', 8, True)),
    'centos7': ('ID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="7"\n', ('CentOS', 7, True)),
    'stream9': ('ID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="9"\n', ('CentOS', 9, False)),
    'alma9': ('ID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n', ('CentOS', 9, True)),
    'rocky9': ('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.3"\n', ('CentOS', 9, False)),
    'rocky10': ('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="10.0"\n', ('CentOS', 10, False)),
    'rhel8': ('ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="8.10"\n', ('CentOS', 8, True)),
    'oracle8': ('ID="ol"\nID_LIKE="fedora"\nVERSION_ID="8.9"\n', ('CentOS', 8, False)),
    'cloudlinux8': ('ID="cloudlinux"\nID_LIKE="rhel fedora centos"\nVERSION_ID="8.9"\n', ('CentOS', 8, True)),
    'el11': ('ID="almalinux"\nID_LIKE="rhel"\nVERSION_ID="11.0"\n', ('CentOS', 10, False)),
    'fedora41': ('ID=fedora\nVERSION_ID=41\n', ('CentOS', 10, False)),
    'fedora36': ('ID=fedora\nVERSION_ID=36\n', ('CentOS', 9, False)),
    'amzn2023': ('ID="amzn"\nID_LIKE="fedora"\nVERSION_ID="2023"\n', ('CentOS', 9, False)),
    'ubuntu2204': ('ID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\nUBUNTU_CODENAME=jammy\n', ('Ubuntu', 22, True)),
    'ubuntu2504': ('ID=ubuntu\nID_LIKE=debian\nVERSION_ID="25.04"\n', ('Ubuntu', 24, False)),
    'ubuntu1604': ('ID=ubuntu\nID_LIKE=debian\nVERSION_ID="16.04"\n', ('Ubuntu', 18, False)),
    'mint21': ('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="21.3"\nUBUNTU_CODENAME=jammy\n', ('Ubuntu', 22, False)),
    'debian11': ('ID=debian\nVERSION_ID="11"\n', ('Ubuntu', 20, False)),
    'debian12': ('ID=debian\nVERSION_ID="12"\n', ('Ubuntu', 22, False)),
    'debian13': ('ID=debian\nVERSION_ID="13"\n', ('Ubuntu', 24, False)),
    'debian_sid': ('ID=debian\n', ('Ubuntu', 22, False)),
    'openeuler22': ('ID="openEuler"\nVERSION_ID="22.03"\n', ('openEuler', 22, True)),
    'openeuler24': ('ID="openEuler"\nVERSION_ID="24.03"\n', ('openEuler', 22, False)),
}
UNSUPPORTED = {
    'centos6': 'ID="centos"\nVERSION_ID="6"\n',
    'arch': 'ID=arch\n',
}

COMPAT = os.path.join(ROOT, 'universal', 'compat.sh')


def shell_map(path):
    script = 'source "$1"; Universal_Map_Profile "$2"'
    result = subprocess.run(['bash', '-c', script, '_', COMPAT, path],
                            stdout=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        return None
    os_name, version, _family, native = result.stdout.split()
    return os_name, int(version), native == '1'


class OSProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        path = os.path.join(self.tmp.name, name)
        with open(path, 'w') as handle:
            handle.write(content)
        return path

    def test_python_mapping(self):
        for name, (content, expected) in CASES.items():
            with self.subTest(name):
                profile = osp.detect(self.write(name, content), profile_path=None)
                self.assertEqual((profile.os, profile.version, profile.native), expected)

    def test_shell_mapping_matches_python(self):
        for name, (content, expected) in CASES.items():
            with self.subTest(name):
                self.assertEqual(shell_map(self.write(name, content)), expected)

    def test_unsupported(self):
        for name, content in UNSUPPORTED.items():
            with self.subTest(name):
                path = self.write(name, content)
                self.assertIsNone(osp.detect(path, profile_path=None))
                self.assertIsNone(shell_map(path))

    def test_recorded_profile_wins(self):
        release = self.write('release', CASES['debian12'][0])
        recorded = self.write('profile', 'FAMILY=rhel\nPROFILE_OS=CentOS\nPROFILE_VERSION=8\n'
                                         'REAL_ID=custom\nREAL_VERSION=1\nNATIVE=0\n')
        profile = osp.detect(release, profile_path=recorded)
        self.assertEqual((profile.family, profile.os, profile.version), ('rhel', 'CentOS', 8))

    def test_shell_detect_writes_nothing_in_dry_run(self):
        release = self.write('release', CASES['centos8'][0])
        script = ('UNIVERSAL_DRY_RUN=1 UNIVERSAL_OS_RELEASE="$2" Universal_Log_File=/dev/null; '
                  'source "$1"; Universal_Log_File=/dev/null; Universal_Detect_OS >/dev/null; '
                  'echo "$Server_OS $Server_OS_Version $Universal_Family $Universal_Native"')
        out = subprocess.run(['bash', '-c', script, '_', COMPAT, release],
                             stdout=subprocess.PIPE, universal_newlines=True,
                             env=dict(os.environ, UNIVERSAL_DRY_RUN='1', UNIVERSAL_OS_RELEASE=release))
        self.assertEqual(out.stdout.split(), ['CentOS', '8', 'rhel', '1'])


if __name__ == '__main__':
    unittest.main()
