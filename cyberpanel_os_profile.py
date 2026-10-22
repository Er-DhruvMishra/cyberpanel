"""Map any Linux distribution onto the nearest OS profile upstream CyberPanel supports.

Upstream only recognises a fixed list of distributions and either exits or silently
falls back to Ubuntu for everything else. This module looks at the os-release family
(ID / ID_LIKE / VERSION_ID) and returns the closest supported profile, so the rest of
the code can keep using its existing per-OS branches.

The installer (cyberpanel.sh, universal/compat.sh) writes the profile it chose to
/etc/cyberpanel/os_profile; when present that file wins, so shell and Python never
disagree. Keep the mapping table below in sync with Universal_Map_Profile in
universal/compat.sh.

This file must stay dependency-free: it is imported by install/install.py before the
panel virtualenv exists.
"""

import os
from collections import namedtuple

OS_RELEASE_PATH = '/etc/os-release'
PROFILE_PATH = '/etc/cyberpanel/os_profile'

RHEL = 'rhel'
DEBIAN = 'debian'
OPENEULER = 'openeuler'

# family: rhel | debian | openeuler
# os: CentOS | Ubuntu | openEuler (the upstream profile name)
# version: profile major version as int (CentOS 7-10, Ubuntu 18-26, openEuler 20/22)
# native: True when upstream supports the host as-is (no mapping was needed)
OSProfile = namedtuple('OSProfile', 'family os version real_id real_version native')

_RHEL_IDS = ('centos', 'rhel', 'almalinux', 'rocky', 'cloudlinux', 'ol', 'eurolinux',
             'navy', 'miraclelinux', 'circle', 'virtuozzo', 'scientific')
_UBUNTU_CODENAMES = {'bionic': 18, 'focal': 20, 'jammy': 22, 'noble': 24, 'resolute': 26}
_NATIVE_RHEL = {('centos', 7), ('centos', 8), ('cloudlinux', 7), ('cloudlinux', 8),
                ('almalinux', 8), ('almalinux', 9), ('almalinux', 10), ('rocky', 8),
                ('rhel', 8), ('rhel', 9)}
_NATIVE_UBUNTU = (18, 20, 22, 24, 26)


def _parse_key_values(path):
    values = {}
    try:
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    except (IOError, OSError):
        pass
    return values


def _major_minor(version):
    parts = (version or '').split('.')
    try:
        major = int(parts[0])
    except ValueError:
        return None, 0
    try:
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        minor = 0
    return major, minor


def _clamp(value, low, high):
    return max(low, min(high, value))


def map_release(release):
    """Return an OSProfile for a parsed os-release dict, or None if unsupported."""
    os_id = release.get('ID', '').lower()
    like = release.get('ID_LIKE', '').lower().split()
    version = release.get('VERSION_ID', '')
    major, _ = _major_minor(version)

    if os_id == 'openeuler':
        return OSProfile(OPENEULER, 'openEuler', 20 if major == 20 else 22, os_id, version,
                         major in (20, 22))

    if os_id in _RHEL_IDS or 'rhel' in like or 'centos' in like:
        if major is None or major < 7:
            return None
        return OSProfile(RHEL, 'CentOS', _clamp(major, 7, 10), os_id, version,
                         (os_id, major) in _NATIVE_RHEL)

    if os_id == 'amzn':
        return OSProfile(RHEL, 'CentOS', 9 if major and major >= 2022 else 7, os_id, version,
                         False)

    if os_id == 'fedora' or 'fedora' in like:
        # Fedora releases feed the next RHEL major: 28 -> EL8, 34 -> EL9, 40 -> EL10.
        if major is None:
            return None
        profile = 10 if major >= 40 else 9 if major >= 34 else 8
        return OSProfile(RHEL, 'CentOS', profile, os_id, version, False)

    if os_id == 'ubuntu':
        if major is None:
            return None
        lts = major if major % 2 == 0 else major - 1
        lts = _clamp(lts, 18, 26)
        return OSProfile(DEBIAN, 'Ubuntu', lts, os_id, version, major in _NATIVE_UBUNTU)

    if 'ubuntu' in like:
        codename = release.get('UBUNTU_CODENAME', '').lower()
        return OSProfile(DEBIAN, 'Ubuntu', _UBUNTU_CODENAMES.get(codename, 22), os_id,
                         version, False)

    if os_id == 'debian' or 'debian' in like:
        # Debian 11 ~ Ubuntu 20.04, 12 ~ 22.04, 13+ ~ 24.04 (closest library baselines).
        if major is None:
            profile = 22
        elif major <= 11:
            profile = 20
        elif major == 12:
            profile = 22
        else:
            profile = 24
        return OSProfile(DEBIAN, 'Ubuntu', profile, os_id, version, False)

    return None


def _from_profile_file(path):
    values = _parse_key_values(path)
    try:
        return OSProfile(values['FAMILY'], values['PROFILE_OS'], int(values['PROFILE_VERSION']),
                         values.get('REAL_ID', ''), values.get('REAL_VERSION', ''),
                         values.get('NATIVE', '0') == '1')
    except (KeyError, ValueError):
        return None


def detect(os_release_path=OS_RELEASE_PATH, profile_path=PROFILE_PATH):
    """Return the host's OSProfile, preferring the profile the installer recorded."""
    if profile_path and os.path.exists(profile_path):
        profile = _from_profile_file(profile_path)
        if profile is not None:
            return profile
    return map_release(_parse_key_values(os_release_path))


if __name__ == '__main__':
    print(detect())
