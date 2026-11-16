"""Language runtimes for hosted apps: discovery, verified installs, removal.

Smallest variants on purpose:
- Node.js: official `linux-<arch>.tar.xz` build (no headers/docs extras), verified against the
  release's SHASUMS256.txt.
- .NET: the ASP.NET Core *runtime* only (no SDK, roughly a tenth of its size), verified against
  the SHA-512 in Microsoft's release metadata. All versions share one dotnet root, as Microsoft
  supports side by side.
- Python: the distribution's own interpreters when present (zero extra space), otherwise
  Astral's `install_only_stripped` standalone build, verified against the release SHA256SUMS.
- Java: the distribution's JRE when present (e.g. OpenJDK 8 on EL8), otherwise an Eclipse Temurin
  *JRE* (no JDK) LTS build, verified against the SHA-256 in the Adoptium API. Temurin's linux-x64
  builds target glibc 2.12 (17, CentOS 6 image) or 2.17 (21+, CentOS 7 devkit), so they run on
  EL8 (glibc 2.28). WAR apps run on Heroku's webapp-runner (embedded Tomcat 9, Java 8+), which is
  pinned by version and SHA-256 and fetched from Maven Central on first use. A Temurin *JDK* can be
  installed instead (same version, same directory, a superset of the JRE) for Gradle builds.
- Ruby: built on this server from the official ruby-lang.org source tarball, verified against the
  SHA-512 (or SHA-256) in https://cache.ruby-lang.org/pub/ruby/index.txt. ruby-lang.org publishes
  no binaries, and EL8 AppStream only has end-of-life streams (2.5-3.0 on CentOS 8, at most 3.1 on
  8.6+, which also allows one stream per server), so compiling a supported release is the only
  option that is both official and patched. Needs gcc/make and openssl/zlib/libffi/libyaml headers
  (libyaml-devel is in PowerTools/CRB); missing ones are installed with dnf (GPG-checked packages)
  and recorded as panel-installed so they can be removed again. Build: configure + make -j<=2
  at nice 19 / idle I/O, about 10-20 minutes on a 2-vCPU server, roughly 1 GB of temporary space.
- Go: the official go.dev/dl linux archive, verified against the SHA-256 in go.dev/dl/?mode=json.
- Deno / Bun: official GitHub release zips. Deno publishes <asset>.sha256sum, Bun a SHASUMS256.txt;
  GitHub's own asset digest (sha256) is cross-checked when present. A release with neither is not
  offered. Bun's SHASUMS256.txt.asc PGP signature is not checked (no pinned key).

Everything lands in RUNTIME_ROOT (root-owned, world-readable, not writable by site users).
After an install the binary is executed once; a runtime that cannot start on this host (for
example a newer glibc requirement) is removed again and reported.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

RUNTIME_ROOT = '/opt/cp-runtimes'
KINDS = ('node', 'dotnet', 'python', 'java', 'ruby', 'go', 'deno', 'bun')
JAVA_VARIANTS = ('jre', 'jdk')
RUBY_INDEX = 'https://cache.ruby-lang.org/pub/ruby/index.txt'
RUBY_DOWNLOAD = 'https://cache.ruby-lang.org/pub/ruby/%d.%d/ruby-%s.tar.gz'
RUBY_MIN = (3, 3)  # 3.2 reached end-of-life upstream (2026-03)
RUBY_BUILD_PACKAGES = ('gcc', 'make', 'openssl-devel', 'zlib-devel', 'libffi-devel', 'libyaml-devel')
GO_INDEX = 'https://go.dev/dl/?mode=json'
GO_DOWNLOAD = 'https://go.dev/dl/%s'
DENO_RELEASES = 'https://api.github.com/repos/denoland/deno/releases?per_page=30'
DENO_RELEASE = 'https://api.github.com/repos/denoland/deno/releases/tags/v%s'
DENO_PREFIX = 'https://github.com/denoland/deno/releases/download/'
BUN_RELEASES = 'https://api.github.com/repos/oven-sh/bun/releases?per_page=30'
BUN_RELEASE = 'https://api.github.com/repos/oven-sh/bun/releases/tags/bun-v%s'
BUN_PREFIX = 'https://github.com/oven-sh/bun/releases/download/'
BUN_MIN_KERNEL = (5, 1)  # Bun's documented minimum (5.6+ recommended)
REPO_DIR = '/etc/yum.repos.d'
LEDGER = '.panel-packages.json'  # inside RUNTIME_ROOT: OS packages this module installed
# Free space required before an install starts (MB); a Ruby build unpacks and compiles in place.
MIN_FREE_MB = {'ruby': 2048}
DEFAULT_MIN_FREE_MB = 1024
ESTIMATE = {'ruby': 'about 10-20 minutes (compiled on this server)', 'go': 'about 1 minute',
            'java': 'about 1 minute'}
MANAGED = {  # kind -> (binary inside <root>/<kind>/<version>, source label)
    'ruby': ('bin/ruby', 'ruby-lang.org (built here)'),
    'go': ('bin/go', 'go.dev'),
    'deno': ('bin/deno', 'Deno (GitHub release)'),
    'bun': ('bin/bun', 'Bun (GitHub release)'),
}
NODE_INDEX = 'https://nodejs.org/dist/index.json'
NODE_DIST = 'https://nodejs.org/dist/%s/'
DOTNET_INDEX = 'https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json'
PYTHON_SUMS = 'https://github.com/astral-sh/python-build-standalone/releases/latest/download/SHA256SUMS'
PYTHON_DOWNLOAD = 'https://github.com/astral-sh/python-build-standalone/releases/download/%s/%s'
SYSTEM_PYTHONS = ('/usr/bin/python3.13', '/usr/bin/python3.12', '/usr/bin/python3.11', '/usr/bin/python3.10',
                  '/usr/bin/python3.9')
VERSION_RE = re.compile(r'^\d{1,3}(\.\d{1,4}){1,3}$')
ADOPTIUM_RELEASES = 'https://api.adoptium.net/v3/info/available_releases'
ADOPTIUM_LATEST = ('https://api.adoptium.net/v3/assets/latest/%d/hotspot?architecture=%s&image_type=%s&os=linux'
                   '&vendor=eclipse')
JAVA_MIN_FEATURE = 17  # oldest LTS offered for install; Java 8/11 come from the OS if at all
SYSTEM_JAVAS = ('/usr/bin/java', '/usr/lib/jvm/*/bin/java')
# Embedded Tomcat 9.0.x (javax.servlet) for WAR apps. 9.0.123.0 is the newest 9.0.x on Maven Central
# (2026-11); Main-Class and Tomcat are Java 8 bytecode, verified to run on the system OpenJDK 8.
WEBAPP_RUNNER_VERSION = '9.0.123.0'
WEBAPP_RUNNER_SHA256 = 'fdee962ac6b641d59a61afa915ea78dbe0545f4ed46d9405cbb6009e6b2f8311'
WEBAPP_RUNNER_URL = 'https://repo1.maven.org/maven2/com/heroku/webapp-runner/%s/webapp-runner-%s.jar'


class RuntimeError_(ValueError):
    pass


def arch():
    machine = platform.machine()
    return {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine.lower(), machine)


CA_BUNDLES = ('/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/cert.pem')


def ssl_context():
    """Verifying TLS context that finds the system CA bundle even for standalone Pythons."""
    import ssl
    for bundle in CA_BUNDLES:
        if os.path.exists(bundle):
            return ssl.create_default_context(cafile=bundle)
    return ssl.create_default_context()


def _open(url, timeout):
    request = urllib.request.Request(url, headers={'User-Agent': 'CyberPanel-Universal'})
    return urllib.request.urlopen(request, timeout=timeout, context=ssl_context())


def fetch(url, timeout=60, limit=8 * 1024 * 1024):
    with _open(url, timeout) as response:
        return response.read(limit)


# ----------------------------------------------------------------------------- catalogue

def node_catalogue(index_json, machine='x64'):
    """Latest release of each LTS major, newest first."""
    seen, out = set(), []
    for release in index_json:
        major = release['version'].lstrip('v').split('.')[0]
        if not release.get('lts') or major in seen or 'linux-%s' % machine not in release.get('files', []):
            continue
        seen.add(major)
        out.append({'kind': 'node', 'version': release['version'].lstrip('v'), 'label': 'Node.js %s (LTS %s)' % (
            release['version'].lstrip('v'), release['lts'])})
    return out[:4]


def dotnet_catalogue(index_json):
    out = []
    for channel in index_json.get('releases-index', []):
        if channel.get('support-phase') in ('active', 'maintenance', 'go-live') and channel.get('latest-runtime'):
            out.append({'kind': 'dotnet', 'version': channel['latest-runtime'], 'channel': channel['channel-version'],
                        'releases': channel['releases.json'], 'label': 'ASP.NET Core runtime %s' % channel['latest-runtime']})
    return out


def python_catalogue(sums_text, machine='x86_64'):
    """Newest patch release per minor version from a python-build-standalone SHA256SUMS."""
    pattern = re.compile(r'^([0-9a-f]{64})\s+(cpython-(3\.(\d+)\.(\d+))\+(\d{8})-%s-unknown-linux-gnu-install_only_stripped\.tar\.gz)$'
                         % re.escape(machine))
    best = {}
    for line in sums_text.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        sha, name, version, minor, patch, tag = match.groups()
        if int(minor) < 10:
            continue
        key = int(minor)
        if key not in best or int(patch) > best[key]['patch']:
            best[key] = {'kind': 'python', 'version': version, 'sha256': sha, 'file': name, 'tag': tag,
                         'patch': int(patch), 'label': 'Python %s (standalone, stripped)' % version}
    return [dict((k, v) for k, v in best[m].items() if k != 'patch') for m in sorted(best, reverse=True)][:4]


def adoptium_arch(machine):
    return {'arm64': 'aarch64'}.get(machine, machine)


def java_features(available_json, newest=3):
    """LTS feature releases worth installing, newest first (e.g. [25, 21, 17])."""
    lts = sorted({int(f) for f in available_json.get('available_lts_releases', []) if int(f) >= JAVA_MIN_FEATURE},
                 reverse=True)
    return lts[:newest]


def java_catalogue(assets_json, machine='x64', image='jre'):
    """Entries from one Adoptium /assets/latest/<feature>/hotspot response (Temurin JRE or JDK, linux, glibc)."""
    out = []
    for asset in assets_json:
        binary, version = asset.get('binary') or {}, asset.get('version') or {}
        package = binary.get('package') or {}
        if (binary.get('os') != 'linux' or binary.get('architecture') != adoptium_arch(machine)
                or binary.get('image_type') != image or binary.get('jvm_impl') != 'hotspot'
                or binary.get('heap_size', 'normal') != 'normal' or asset.get('vendor', 'eclipse') != 'eclipse'):
            continue
        sha = str(package.get('checksum') or '').lower()
        link, name = str(package.get('link') or ''), str(package.get('name') or '')
        if not re.match(r'^[0-9a-f]{64}$', sha) or not link.startswith('https://') or not name.endswith('.tar.gz'):
            continue
        number = '%d.%d.%d' % (int(version['major']), int(version.get('minor') or 0), int(version.get('security') or 0))
        out.append({'kind': 'java', 'version': number, 'feature': int(version['major']), 'sha256': sha, 'url': link,
                    'file': name, 'size': package.get('size'), 'release': asset.get('release_name', ''),
                    'variant': image,
                    'label': 'Java %d (Temurin %s %s%s)' % (int(version['major']), image.upper(),
                                                           version.get('openjdk_version') or number,
                                                           ', for Gradle builds' if image == 'jdk' else '')})
    return out[:1]


# --- Ruby (source), Go, Deno, Bun

def ruby_catalogue(index_text, newest=3):
    """Newest patch release per supported minor from ruby-lang.org's index.txt (name, url, sha1, sha256, sha512)."""
    best = {}
    for line in index_text.splitlines():
        cols = [c.strip() for c in line.split('\t')]
        if len(cols) < 4:
            continue
        match = re.match(r'^ruby-(\d+)\.(\d+)\.(\d+)$', cols[0])
        if not match or cols[1].rsplit('/', 1)[-1] != cols[0] + '.tar.gz':
            continue
        sha256 = cols[3].lower()
        sha512 = cols[4].lower() if len(cols) > 4 else ''
        if not re.match(r'^[0-9a-f]{64}$', sha256):
            continue
        major, minor, patch = (int(g) for g in match.groups())
        if (major, minor) < RUBY_MIN:
            continue
        version = '%d.%d.%d' % (major, minor, patch)
        if (major, minor) not in best or patch > best[(major, minor)]['_patch']:
            best[(major, minor)] = {
                'kind': 'ruby', 'version': version, 'sha256': sha256,
                'sha512': sha512 if re.match(r'^[0-9a-f]{128}$', sha512) else '',
                'url': RUBY_DOWNLOAD % (major, minor, version), 'file': cols[0] + '.tar.gz', '_patch': patch,
                'build': True, 'estimate': ESTIMATE['ruby'],
                'label': 'Ruby %s (compiled from ruby-lang.org source)' % version}
    return [dict((k, v) for k, v in best[key].items() if k != '_patch') for key in sorted(best, reverse=True)][:newest]


def go_arch(machine):
    return {'x64': 'amd64', 'arm64': 'arm64'}.get(machine, machine)


def go_catalogue(releases_json, machine='x64', newest=3):
    """Stable releases from go.dev/dl/?mode=json with a linux archive for this architecture."""
    goarch, out = go_arch(machine), []
    for release in releases_json:
        tag = str(release.get('version') or '')
        number = tag[2:] if tag.startswith('go') else ''
        if not release.get('stable') or not VERSION_RE.match(number):
            continue
        for item in release.get('files') or []:
            sha = str(item.get('sha256') or '').lower()
            if (item.get('os') == 'linux' and item.get('arch') == goarch and item.get('kind') == 'archive'
                    and item.get('filename') == '%s.linux-%s.tar.gz' % (tag, goarch) and re.match(r'^[0-9a-f]{64}$', sha)):
                out.append({'kind': 'go', 'version': number, 'sha256': sha, 'file': item['filename'],
                            'url': GO_DOWNLOAD % item['filename'], 'size': item.get('size'),
                            'label': 'Go %s (toolchain for go build)' % number})
                break
    out.sort(key=lambda e: _version_key(e['version']), reverse=True)
    return out[:newest]


def github_digest(asset):
    """GitHub's own sha256 of a release asset ('sha256:<hex>'), or ''."""
    value = str(asset.get('digest') or '')
    return value[7:].lower() if re.match(r'^sha256:[0-9a-fA-F]{64}$', value) else ''


def cpu_has_avx2(path='/proc/cpuinfo'):
    try:
        with open(path) as handle:
            return bool(re.search(r'^flags\s*:.*\bavx2\b', handle.read(), re.M))
    except OSError:
        return False


def kernel_version(release=None):
    match = re.match(r'^(\d+)\.(\d+)', release or platform.release())
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def deno_asset(machine):
    return 'deno-%s-unknown-linux-gnu.zip' % {'x64': 'x86_64', 'arm64': 'aarch64'}.get(machine, machine)


def bun_asset(machine, avx2=True):
    if machine == 'arm64':
        return 'bun-linux-aarch64.zip'
    return 'bun-linux-x64.zip' if avx2 else 'bun-linux-x64-baseline.zip'


def _github_catalogue(kind, releases_json, asset_name, tag_re, prefix, sums_name, newest):
    best = {}
    for release in releases_json:
        if release.get('draft') or release.get('prerelease'):
            continue
        tag = str(release.get('tag_name') or '')
        match = re.match(tag_re, tag)
        if not match or not VERSION_RE.match(match.group(1)):
            continue
        version = match.group(1)
        assets = {str(a.get('name')): a for a in release.get('assets') or []}
        asset = assets.get(asset_name)
        if not asset or not str(asset.get('browser_download_url', '')).startswith(prefix + tag + '/'):
            continue
        sums = assets.get(sums_name(asset_name)) or {}
        sums_url = str(sums.get('browser_download_url') or '')
        if sums_url and not sums_url.startswith(prefix + tag + '/'):
            sums_url = ''
        digest = github_digest(asset)
        if not sums_url and not digest:
            continue  # nothing to verify against: not offered
        minor = '.'.join(version.split('.')[:2])
        if minor in best and _version_key(best[minor]['version']) >= _version_key(version):
            continue
        best[minor] = {'kind': kind, 'version': version, 'url': asset['browser_download_url'], 'file': asset_name,
                       'sums_url': sums_url, 'digest': digest, 'size': asset.get('size'),
                       'label': '%s %s' % ({'deno': 'Deno', 'bun': 'Bun'}[kind], version)}
    return sorted(best.values(), key=lambda e: _version_key(e['version']), reverse=True)[:newest]


def deno_catalogue(releases_json, machine='x64', newest=3):
    return _github_catalogue('deno', releases_json, deno_asset(machine), r'^v(\d+\.\d+\.\d+)$', DENO_PREFIX,
                             lambda name: name + '.sha256sum', newest)


def bun_catalogue(releases_json, machine='x64', newest=3, avx2=None, kernel=None):
    avx2 = cpu_has_avx2() if avx2 is None else avx2
    out = _github_catalogue('bun', releases_json, bun_asset(machine, avx2), r'^bun-v(\d+\.\d+\.\d+)$', BUN_PREFIX,
                            lambda name: 'SHASUMS256.txt', newest)
    kernel = kernel or kernel_version()
    for entry in out:
        if not avx2 and machine == 'x64':
            entry['label'] += ' (baseline build: this CPU has no AVX2)'
        if kernel < BUN_MIN_KERNEL:
            entry['warning'] = ('Bun documents Linux kernel %d.%d or newer (5.6+ recommended); this server runs %d.%d. '
                                'The install is smoke-tested, but test the app before relying on it.'
                                % (BUN_MIN_KERNEL + kernel))
    return out


def parse_java_version(text):
    """`java -version` output (stderr) -> {'feature', 'version', 'java_version', 'vendor'} or None.

    'openjdk version "1.8.0_312"' -> feature 8, version 8.0.312; '"21.0.5" 2024-10-15 LTS' -> 21.0.5;
    '"25" 2025-09-16' -> 25.0.0.
    """
    match = re.search(r'^(\S+) version "([0-9][0-9._]*)[^"]*"', text or '', re.M)
    if not match:
        return None
    raw = match.group(2)
    legacy = re.match(r'^1\.(\d+)\.(\d+)(?:_(\d+))?$', raw)
    if legacy:
        feature, minor, security = int(legacy.group(1)), int(legacy.group(2)), int(legacy.group(3) or 0)
    else:
        parts = [int(p) for p in re.findall(r'\d+', raw)[:3]] + [0, 0]
        feature, minor, security = parts[0], parts[1], parts[2]
    vendor = 'Temurin' if 'Temurin' in text else ('OpenJDK' if match.group(1).lower() == 'openjdk' else 'Java')
    return {'feature': feature, 'version': '%d.%d.%d' % (feature, minor, security), 'java_version': raw, 'vendor': vendor}


def system_javas(candidates=SYSTEM_JAVAS, runner=subprocess.run):
    """Java runtimes installed by the OS (/usr/bin/java and /usr/lib/jvm/*), one entry per real binary."""
    import glob
    found, seen, versions = [], set(), set()
    for pattern in candidates:
        for path in sorted(glob.glob(pattern)) if '*' in pattern else [pattern]:
            if not os.path.exists(path):
                continue
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            try:
                out = runner([path, '-version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                continue
            info = parse_java_version(out.stdout or '')
            if out.returncode != 0 or not info or info['version'] in versions:
                continue
            versions.add(info['version'])
            found.append({'kind': 'java', 'version': info['version'], 'feature': info['feature'], 'path': path,
                          'java_version': info['java_version'], 'source': 'system',
                          'label': 'Java %d (system, %s %s)' % (info['feature'], info['vendor'], info['java_version'])})
    return found


SYSTEM_NODES = ('/usr/local/bin/node', '/usr/bin/node')
NODE_SUPPORTED_MAJOR = 20  # older majors are past end-of-life upstream


def system_nodes(candidates=SYSTEM_NODES, runner=subprocess.run):
    """Node.js installed by the OS or by hand (e.g. AppStream's nodejs module), next to its npm."""
    found, seen = [], set()
    for path in candidates:
        if not os.path.exists(path):
            continue
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        try:
            out = runner([path, '--version'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         universal_newlines=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        version = (out.stdout or '').strip().lstrip('v')
        if out.returncode != 0 or not VERSION_RE.match(version):
            continue
        npm = os.path.join(os.path.dirname(path), 'npm')
        eol = int(version.split('.')[0]) < NODE_SUPPORTED_MAJOR
        found.append({'kind': 'node', 'version': version, 'path': path, 'npm': npm if os.path.exists(npm) else '',
                      'source': 'system', 'eol': eol,
                      'label': 'Node.js %s (system%s)' % (version, ', end-of-life' if eol else '')})
    return found


def system_pythons(candidates=SYSTEM_PYTHONS, runner=subprocess.run):
    found = []
    for path in candidates:
        if os.path.exists(path):
            try:
                out = runner([path, '-c', 'import sys, venv; print("%d.%d.%d" % sys.version_info[:3])'],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                continue
            if out.returncode == 0 and VERSION_RE.match(out.stdout.strip()):
                found.append({'kind': 'python', 'version': out.stdout.strip(), 'path': path, 'source': 'system',
                              'label': 'Python %s (system)' % out.stdout.strip()})
    return found


def catalogue(fetcher=fetch):
    """Installable versions per kind (network). Failures are reported per kind, not raised."""
    result = dict({kind: [] for kind in KINDS}, errors={})
    machine = arch()
    try:
        result['node'] = node_catalogue(json.loads(fetcher(NODE_INDEX)), machine)
    except Exception as exc:
        result['errors']['node'] = str(exc)[:200]
    try:
        result['dotnet'] = dotnet_catalogue(json.loads(fetcher(DOTNET_INDEX)))
    except Exception as exc:
        result['errors']['dotnet'] = str(exc)[:200]
    try:
        result['python'] = python_catalogue(fetcher(PYTHON_SUMS).decode(), 'x86_64' if machine == 'x64' else 'aarch64')
    except Exception as exc:
        result['errors']['python'] = str(exc)[:200]
    try:
        for feature in java_features(json.loads(fetcher(ADOPTIUM_RELEASES))):
            for image in JAVA_VARIANTS:
                result['java'] += java_catalogue(json.loads(fetcher(ADOPTIUM_LATEST % (
                    feature, adoptium_arch(machine), image))), machine, image)
    except Exception as exc:
        result['errors']['java'] = str(exc)[:200]
    sources = (('ruby', RUBY_INDEX, lambda data: ruby_catalogue(data.decode('utf-8', 'replace'))),
               ('go', GO_INDEX, lambda data: go_catalogue(json.loads(data), machine)),
               ('deno', DENO_RELEASES, lambda data: deno_catalogue(json.loads(data), machine)),
               ('bun', BUN_RELEASES, lambda data: bun_catalogue(json.loads(data), machine)))
    for kind, url, parse in sources:
        try:
            result[kind] = parse(fetcher(url))
        except Exception as exc:
            result['errors'][kind] = str(exc)[:200]
    return result


# ----------------------------------------------------------------------------- installed

def installed(root=RUNTIME_ROOT, runner=subprocess.run):
    """{'node': [...], 'dotnet': [...], ...} of usable runtimes per kind, with binary paths and sizes on disk."""
    out = dict({kind: [] for kind in KINDS}, python=system_pythons(runner=runner))
    node_root = os.path.join(root, 'node')
    if os.path.isdir(node_root):
        for version in sorted(os.listdir(node_root), reverse=True):
            binary = os.path.join(node_root, version, 'bin', 'node')
            if VERSION_RE.match(version) and os.path.exists(binary):
                out['node'].append({'kind': 'node', 'version': version, 'path': binary,
                                    'npm': os.path.join(node_root, version, 'bin', 'npm'), 'source': 'nodejs.org',
                                    'size': _du(os.path.join(node_root, version))})
    managed = {entry['version'] for entry in out['node']}
    out['node'] += [entry for entry in system_nodes(runner=runner) if entry['version'] not in managed]
    dotnet_root = os.path.join(root, 'dotnet')
    framework = os.path.join(dotnet_root, 'shared', 'Microsoft.AspNetCore.App')
    if os.path.isdir(framework):
        for version in sorted(os.listdir(framework), reverse=True):
            if VERSION_RE.match(version.split('-')[0]):
                out['dotnet'].append({'kind': 'dotnet', 'version': version, 'path': os.path.join(dotnet_root, 'dotnet'),
                                      'source': 'Microsoft', 'size': _du(os.path.join(framework, version)) +
                                      _du(os.path.join(dotnet_root, 'shared', 'Microsoft.NETCore.App', version))})
    python_root = os.path.join(root, 'python')
    if os.path.isdir(python_root):
        for version in sorted(os.listdir(python_root), reverse=True):
            binary = os.path.join(python_root, version, 'bin', 'python3')
            if VERSION_RE.match(version) and os.path.exists(binary):
                out['python'].append({'kind': 'python', 'version': version, 'path': binary, 'source': 'standalone',
                                      'size': _du(os.path.join(python_root, version))})
    java_root = os.path.join(root, 'java')
    if os.path.isdir(java_root):
        for version in sorted(os.listdir(java_root), key=_version_key, reverse=True):
            binary = os.path.join(java_root, version, 'bin', 'java')
            if VERSION_RE.match(version) and os.path.exists(binary):
                jdk = os.path.exists(os.path.join(java_root, version, 'bin', 'javac'))
                out['java'].append({'kind': 'java', 'version': version, 'feature': int(version.split('.')[0]),
                                    'path': binary, 'source': 'Temurin JDK' if jdk else 'Temurin', 'jdk': jdk,
                                    'size': _du(os.path.join(java_root, version))})
    managed = {entry['version'] for entry in out['java']}
    out['java'] += [dict(entry, jdk=has_javac(java_home(entry))) for entry in system_javas(runner=runner)
                    if entry['version'] not in managed]
    for kind, (binary_name, source) in MANAGED.items():
        kind_root = os.path.join(root, kind)
        if not os.path.isdir(kind_root):
            continue
        for version in sorted(os.listdir(kind_root), key=_version_key, reverse=True):
            binary = os.path.join(kind_root, version, binary_name)
            if VERSION_RE.match(version) and os.path.exists(binary):
                entry = {'kind': kind, 'version': version, 'path': binary, 'source': source,
                         'size': _du(os.path.join(kind_root, version))}
                if kind == 'ruby':
                    entry['bundle'] = os.path.join(kind_root, version, 'bin', 'bundle')
                out[kind].append(entry)
    return out


def java_home(runtime):
    """JAVA_HOME for a java binary (the JDK above an OpenJDK 8 jre/ directory when that JDK is installed)."""
    home = os.path.dirname(os.path.dirname(os.path.realpath(runtime['path'])))
    parent = os.path.dirname(home)
    if os.path.basename(home) == 'jre' and has_javac(parent):
        return parent
    return home


def has_javac(home):
    return os.path.exists(os.path.join(home, 'bin', 'javac'))


def _version_key(text):
    return [int(p) if p.isdigit() else -1 for p in text.split('.')]


def find(kind, version, root=RUNTIME_ROOT, runner=subprocess.run):
    for runtime in installed(root, runner).get(kind, []):
        if runtime['version'] == version:
            return runtime
    raise RuntimeError_('%s %s is not installed.' % (kind, version))


def _du(path):
    """Bytes on disk under path, like `du -s`: allocated blocks, hard links counted once, links not followed."""
    total, seen = 0, set()
    for current, dirs, files in os.walk(path):
        for name in [''] + dirs + files if current == path else dirs + files:
            try:
                info = os.lstat(os.path.join(current, name) if name else current)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) in seen:
                continue
            seen.add((info.st_dev, info.st_ino))
            total += info.st_blocks * 512 if hasattr(info, 'st_blocks') else info.st_size
    return total


# ----------------------------------------------------------------------------- installing

def _digest(path, algorithm):
    digest = hashlib.new(algorithm)
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest().lower()


def _download(url, expected, algorithm, directory, fetch_file=None):
    target = os.path.join(directory, 'download')
    if fetch_file:
        fetch_file(url, target)
    else:
        with _open(url, 600) as response, open(target, 'wb') as output:
            shutil.copyfileobj(response, output, 1 << 20)
    if _digest(target, algorithm) != expected.lower():
        raise RuntimeError_('Checksum mismatch for %s; the download was discarded.' % url.rsplit('/', 1)[-1])
    return target


def _safe_extract(archive, destination, strip=0):
    """Extract a tarball refusing absolute paths, traversal, devices and links escaping destination."""
    real_destination = os.path.realpath(destination)
    with tarfile.open(archive) as bundle:
        members = []
        for member in bundle.getmembers():
            parts = member.name.split('/')[strip:]
            if not parts or parts == ['']:
                continue
            member.name = '/'.join(parts)
            target = os.path.realpath(os.path.join(destination, member.name))
            if not (target == real_destination or target.startswith(real_destination + os.sep)):
                raise RuntimeError_('Archive member escapes the destination: %s' % member.name)
            if member.isdev():
                raise RuntimeError_('Archive contains device files.')
            if member.issym() or member.islnk():
                link = os.path.realpath(os.path.join(os.path.dirname(target), member.linkname)) if member.issym() \
                    else os.path.realpath(os.path.join(destination, '/'.join(member.linkname.split('/')[strip:])))
                if not (link == real_destination or link.startswith(real_destination + os.sep)):
                    raise RuntimeError_('Archive link escapes the destination: %s' % member.name)
            member.uid = member.gid = 0
            member.uname = member.gname = 'root'
            members.append(member)
        bundle.extractall(destination, members=members)


def _smoke(argv, runner=subprocess.run, timeout=60):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return out.returncode == 0, (out.stdout or '').strip()[-400:]


def install(kind, version, root=RUNTIME_ROOT, fetcher=fetch, fetch_file=None, runner=subprocess.run, log=None,
            variant='', build=None):
    """Download, verify, extract (or build) and smoke-test a runtime. Returns the installed entry.

    variant: 'jdk' installs a Temurin JDK instead of the JRE (Java only).
    build: runs one build command, (argv, cwd, env, log, timeout) -> (code, tail); Ruby only, for tests.
    """
    say = log or (lambda text: None)
    if kind not in KINDS or not VERSION_RE.match(version or ''):
        raise RuntimeError_('Unknown runtime.')
    if variant and (kind != 'java' or variant not in JAVA_VARIANTS):
        raise RuntimeError_('Unknown runtime variant.')
    machine = arch()
    os.makedirs(root, mode=0o755, exist_ok=True)
    work = tempfile.mkdtemp(prefix='cp-runtime-', dir=root)  # mkdtemp: 0700, root only
    try:
        if kind in ('ruby', 'go', 'deno', 'bun'):
            staged = {'ruby': _install_ruby, 'go': _install_go, 'deno': _install_github,
                      'bun': _install_github}[kind](kind, version, root, work, machine, fetcher, fetch_file, runner, say,
                                                    build or _run_streamed)
            _place(staged, os.path.join(root, kind, version))
        elif kind == 'node':
            name = 'node-v%s-linux-%s.tar.xz' % (version, machine)
            sums = fetcher(NODE_DIST % ('v' + version) + 'SHASUMS256.txt').decode()
            match = re.search(r'^([0-9a-f]{64})\s+%s$' % re.escape(name), sums, re.M)
            if not match:
                raise RuntimeError_('Node.js %s has no %s build.' % (version, machine))
            archive = _download(NODE_DIST % ('v' + version) + name, match.group(1), 'sha256', work, fetch_file)
            destination = os.path.join(root, 'node', version)
            staged = os.path.join(work, 'tree')
            os.makedirs(staged)
            _safe_extract(archive, staged, strip=1)
            for extra in ('include', 'share/doc', 'share/man', 'CHANGELOG.md', 'README.md'):
                path = os.path.join(staged, extra)  # headers and docs are not needed to run apps
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.exists(path):
                    os.unlink(path)
            ok, out = _smoke([os.path.join(staged, 'bin', 'node'), '--version'], runner)
            if not ok:
                raise RuntimeError_('Node.js %s does not run on this server: %s' % (version, out))
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            if os.path.exists(destination):
                shutil.rmtree(destination)
            os.rename(staged, destination)
        elif kind == 'dotnet':
            channel = '.'.join(version.split('.')[:2])
            index = json.loads(fetcher(DOTNET_INDEX))
            entry = next((c for c in index['releases-index'] if c['channel-version'] == channel), None)
            if not entry:
                raise RuntimeError_('Unknown .NET channel %s.' % channel)
            releases = json.loads(fetcher(entry['releases.json']))['releases']
            release = next((r for r in releases if (r.get('aspnetcore-runtime') or {}).get('version') == version), None)
            if not release:
                raise RuntimeError_('ASP.NET Core runtime %s not found.' % version)
            files = [f for f in release['aspnetcore-runtime']['files']
                     if f.get('rid') == 'linux-%s' % machine and f['name'] == 'aspnetcore-runtime-linux-%s.tar.gz' % machine]
            if not files:
                raise RuntimeError_('No linux-%s build of ASP.NET Core runtime %s.' % (machine, version))
            archive = _download(files[0]['url'], files[0]['hash'], 'sha512', work, fetch_file)
            staged = os.path.join(work, 'tree')
            os.makedirs(staged)
            _safe_extract(archive, staged)
            dotnet_root = os.path.join(root, 'dotnet')
            os.makedirs(dotnet_root, exist_ok=True)
            # Merge side by side: host/ and dotnet are shared; frameworks are per version.
            for current, dirs, names in os.walk(staged):
                relative = os.path.relpath(current, staged)
                os.makedirs(os.path.join(dotnet_root, relative), exist_ok=True)
                for name in names:
                    source = os.path.join(current, name)
                    target = os.path.join(dotnet_root, relative, name)
                    if os.path.islink(source):
                        continue
                    shutil.copy2(source, target)
            ok, out = _smoke([os.path.join(dotnet_root, 'dotnet'), '--list-runtimes'], runner)
            if not ok or version not in out:
                for framework in ('Microsoft.AspNetCore.App', 'Microsoft.NETCore.App'):
                    shutil.rmtree(os.path.join(dotnet_root, 'shared', framework, version), ignore_errors=True)
                raise RuntimeError_('.NET %s does not run on this server: %s' % (version, out))
        elif kind == 'java':
            image = variant or 'jre'
            feature = int(version.split('.')[0])
            destination = os.path.join(root, 'java', version)
            if image == 'jre' and os.path.exists(os.path.join(destination, 'bin', 'javac')):
                raise RuntimeError_('Java %s is already installed as a JDK, which includes the JRE.' % version)
            assets = json.loads(fetcher(ADOPTIUM_LATEST % (feature, adoptium_arch(machine), image)))
            entry = next((e for e in java_catalogue(assets, machine, image) if e['version'] == version), None)
            if not entry:
                raise RuntimeError_('Java %s is not the current Temurin %d %s build; refresh the list.'
                                    % (version, feature, image.upper()))
            archive = _download(entry['url'], entry['sha256'], 'sha256', work, fetch_file)
            staged = os.path.join(work, 'tree')
            os.makedirs(staged)
            _safe_extract(archive, staged, strip=1)
            # legal/ (licences) stays; sources, jmods (jlink only) and man pages are not needed to build or run.
            for extra in ('man', 'jmods', 'lib/src.zip'):
                path = os.path.join(staged, extra)
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.exists(path):
                    os.unlink(path)
            ok, out = _smoke([os.path.join(staged, 'bin', 'java'), '-version'], runner)
            if not ok:
                raise RuntimeError_('Java %s does not run on this server: %s' % (version, out))
            _place(staged, destination)  # a JDK replaces the JRE of the same version in place
        else:
            sums = fetcher(PYTHON_SUMS).decode()
            entry = next((p for p in python_catalogue(sums, 'x86_64' if machine == 'x64' else 'aarch64')
                          if p['version'] == version), None)
            if not entry:
                raise RuntimeError_('Python %s is not in the current standalone release.' % version)
            archive = _download(PYTHON_DOWNLOAD % (entry['tag'], entry['file'].replace('+', '%2B')), entry['sha256'],
                                'sha256', work, fetch_file)
            staged = os.path.join(work, 'tree')
            os.makedirs(staged)
            _safe_extract(archive, staged, strip=1)
            _prune_python(staged)
            ok, out = _smoke([os.path.join(staged, 'bin', 'python3'), '-c', 'import ssl, venv, sqlite3; print(1)'], runner)
            if not ok:
                raise RuntimeError_('Python %s does not run on this server: %s' % (version, out))
            destination = os.path.join(root, 'python', version)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            if os.path.exists(destination):
                shutil.rmtree(destination)
            os.rename(staged, destination)
        _world_readable(root)
        say('%s %s installed' % (kind, version))
        return find(kind, version, root, runner)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _place(staged, destination):
    """Move a smoke-tested tree into place; an existing version is retired into the work directory."""
    os.makedirs(os.path.dirname(destination), mode=0o755, exist_ok=True)
    if os.path.exists(destination):
        os.rename(destination, os.path.join(os.path.dirname(staged), 'retired'))
    os.rename(staged, destination)


def _run_streamed(argv, cwd, env, log, timeout, popen=subprocess.Popen, clock=time.monotonic):
    """Run a long build step, forwarding its output to the job log every few seconds (keeps the job alive).

    Returns (exit code, last lines of output). The process is killed after `timeout` seconds.
    """
    import collections
    import threading
    try:
        process = popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, universal_newlines=True, errors='replace')
    except OSError as exc:
        return 127, str(exc)
    expired = []

    def kill():
        expired.append(True)
        process.kill()
    timer = threading.Timer(timeout, kill)
    timer.daemon = True
    timer.start()
    tail, pending, last = collections.deque(maxlen=60), [], clock()
    try:
        for line in process.stdout:
            line = line.rstrip()
            tail.append(line)
            pending.append(line)
            if clock() - last >= 10:
                log('\n'.join(pending[-15:]))
                pending, last = [], clock()
        code = process.wait()
    finally:
        timer.cancel()
    if pending:
        log('\n'.join(pending[-15:]))
    if expired:
        tail.append('stopped after %d s' % timeout)
    return code, '\n'.join(tail)


def _install_ruby(kind, version, root, work, machine, fetcher, fetch_file, runner, say, build):
    entry = next((e for e in ruby_catalogue(fetcher(RUBY_INDEX).decode('utf-8', 'replace'), newest=99)
                  if e['version'] == version), None)
    if not entry:
        raise RuntimeError_('Ruby %s is not a current ruby-lang.org release; refresh the list.' % version)
    say('Ruby %s is compiled on this server: %s.' % (version, ESTIMATE['ruby']))
    ensure_packages(RUBY_BUILD_PACKAGES, root, runner, say, 'Ruby build')
    if entry['sha512']:
        archive = _download(entry['url'], entry['sha512'], 'sha512', work, fetch_file)
    else:
        archive = _download(entry['url'], entry['sha256'], 'sha256', work, fetch_file)
    say('%s matches the %s in ruby-lang.org index.txt.' % (entry['file'], 'SHA-512' if entry['sha512'] else 'SHA-256'))
    source = os.path.join(work, 'src')
    os.makedirs(source)
    _safe_extract(archive, source, strip=1)
    os.unlink(archive)
    prefix = os.path.join(root, 'ruby', version)
    destdir = os.path.join(work, 'dest')
    # TMPDIR inside the root-only work directory: /tmp may be noexec, and configure runs test programs.
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': work, 'TMPDIR': work}
    low = ['nice', '-n', '19', 'ionice', '-c', '3']  # the server keeps serving sites while this compiles
    jobs = max(1, min(2, os.cpu_count() or 1))     # -j2 at most: ~3.7 GB RAM hosts
    steps = (('configure', ['./configure', '--prefix=' + prefix, '--enable-load-relative', '--disable-install-doc',
                            '--disable-install-rdoc'], 1200),
             ('make -j%d' % jobs, ['make', '-j%d' % jobs], 5400),
             ('make install', ['make', 'install', 'DESTDIR=' + destdir], 1200))
    for title, argv, timeout in steps:
        say('--> %s' % title)
        started = time.time()
        code, tail = build(low + argv, source, env, say, timeout)
        if code != 0:
            raise RuntimeError_('Ruby %s: %s failed (exit %s): %s' % (version, title, code, tail[-800:]))
        say('    %s took %d s' % (title, time.time() - started))
    shutil.rmtree(source, ignore_errors=True)  # ~600 MB of objects, gone before the smoke test
    staged = os.path.join(destdir, prefix.lstrip('/'))
    ruby = os.path.join(staged, 'bin', 'ruby')
    if not os.path.exists(ruby) or not os.path.exists(os.path.join(staged, 'bin', 'bundle')):
        raise RuntimeError_('Ruby %s: the build did not produce bin/ruby and bin/bundle.' % version)
    # configure silently skips extensions whose headers are missing; Rails needs all three.
    ok, out = _smoke([ruby, '-ropenssl', '-rpsych', '-rzlib', '-e', 'print RUBY_VERSION'], runner)
    if not ok or not out.endswith(version):
        raise RuntimeError_('Ruby %s was built but cannot load openssl, psych (libyaml) or zlib: %s' % (version, out))
    return staged


def _install_go(kind, version, root, work, machine, fetcher, fetch_file, runner, say, build):
    entry = next((e for e in go_catalogue(json.loads(fetcher(GO_INDEX)), machine, newest=99)
                  if e['version'] == version), None)
    if not entry:
        raise RuntimeError_('Go %s is not a current go.dev release; refresh the list.' % version)
    archive = _download(entry['url'], entry['sha256'], 'sha256', work, fetch_file)
    say('%s matches the SHA-256 published on go.dev/dl.' % entry['file'])
    staged = os.path.join(work, 'tree')
    os.makedirs(staged)
    _safe_extract(archive, staged, strip=1)
    os.unlink(archive)
    shutil.rmtree(os.path.join(staged, 'test'), ignore_errors=True)  # Go's own test suite
    ok, out = _smoke([os.path.join(staged, 'bin', 'go'), 'version'], runner)
    if not ok or 'go%s ' % version not in out + ' ':
        raise RuntimeError_('Go %s does not run on this server: %s' % (version, out))
    return staged


def published_sha256(entry, fetcher):
    """(sha256, where it came from) for a GitHub release asset; the publisher's checksum file wins,
    GitHub's asset digest must agree with it when both exist, and no checksum at all is refused."""
    published, digest = '', entry.get('digest') or ''
    if entry.get('sums_url'):
        text = fetcher(entry['sums_url']).decode('utf-8', 'replace')
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and re.match(r'^[0-9a-fA-F]{64}$', parts[0]) and \
                    os.path.basename(parts[1].lstrip('*')) == entry['file']:
                published = parts[0].lower()
                break
        if not published and entry['sums_url'].endswith('.sha256sum'):
            values = set(v.lower() for v in re.findall(r'\b[0-9a-fA-F]{64}\b', text))  # a one-file sum
            published = values.pop() if len(values) == 1 else ''
        if not published:
            raise RuntimeError_('%s lists no SHA-256 for %s.' % (entry['sums_url'].rsplit('/', 1)[-1], entry['file']))
    if published and digest and published != digest:
        raise RuntimeError_("The published checksum of %s and GitHub's asset digest disagree; refused." % entry['file'])
    if published:
        return published, entry['sums_url'].rsplit('/', 1)[-1] + (" (GitHub's digest agrees)" if digest else '')
    if digest:
        return digest, "GitHub's asset digest"
    raise RuntimeError_('No checksum is published for %s; refused.' % entry['file'])


def _install_github(kind, version, root, work, machine, fetcher, fetch_file, runner, say, build):
    if kind == 'deno':
        entries = deno_catalogue([json.loads(fetcher(DENO_RELEASE % version))], machine, newest=99)
    else:
        entries = bun_catalogue([json.loads(fetcher(BUN_RELEASE % version))], machine, newest=99)
    entry = next((e for e in entries if e['version'] == version), None)
    if not entry:
        raise RuntimeError_('%s %s has no verifiable linux-%s build; refresh the list.' % (kind, version, machine))
    if entry.get('warning'):
        say('Warning: ' + entry['warning'])
    sha, source = published_sha256(entry, fetcher)
    archive = _download(entry['url'], sha, 'sha256', work, fetch_file)
    say('%s matches the SHA-256 from %s.' % (entry['file'], source))
    unpacked = os.path.join(work, 'unpacked')
    os.makedirs(unpacked)
    _safe_extract_zip(archive, unpacked)
    os.unlink(archive)
    found = [os.path.join(current, kind) for current, dirs, files in os.walk(unpacked) if kind in files]
    if len(found) != 1:
        raise RuntimeError_('Unexpected layout in %s.' % entry['file'])
    staged = os.path.join(work, 'tree')
    os.makedirs(os.path.join(staged, 'bin'))
    binary = os.path.join(staged, 'bin', kind)
    os.rename(found[0], binary)
    os.chmod(binary, 0o755)
    ok, out = _smoke([binary, '--version'], runner)
    if not ok or version not in out:
        raise RuntimeError_('%s %s does not run on this server: %s' % (kind, version, out))
    return staged


def _safe_extract_zip(archive, destination, strip=0):
    """Extract a zip refusing absolute paths, traversal and symlinks. Modes are taken from the archive."""
    real_destination = os.path.realpath(destination)
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            name = '/'.join(info.filename.split('/')[strip:])
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise RuntimeError_('Archive contains links: %s' % info.filename)
            target = os.path.realpath(os.path.join(destination, name))
            if info.filename.startswith('/') or not (target == real_destination or
                                                       target.startswith(real_destination + os.sep)):
                raise RuntimeError_('Archive member escapes the destination: %s' % info.filename)
            if not name or info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with bundle.open(info) as source, open(target, 'wb') as output:
                shutil.copyfileobj(source, output, 1 << 20)
            os.chmod(target, (mode & 0o755) or 0o644)


# ----------------------------------------------------------------------------- OS packages

PACKAGE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$')


def ledger(root=RUNTIME_ROOT):
    """{package: {'reason', 'installed'}} for OS packages this module installed (and may remove again)."""
    try:
        with open(os.path.join(root, LEDGER)) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _ledger_write(root, data):
    os.makedirs(root, mode=0o755, exist_ok=True)
    path = os.path.join(root, LEDGER)
    with open(path + '.tmp', 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)


def missing_packages(names, runner=subprocess.run):
    return [name for name in names if not _smoke(['rpm', '-q', '--quiet', name], runner, timeout=30)[0]]


def os_repo_args(repo_dir=None):
    """dnf arguments limiting an install to the OS repositories plus PowerTools/CRB (for -devel packages).

    Third-party repositories stay out of it, so no other vendor's key is imported along the way.
    """
    import glob
    ids = set()
    for path in glob.glob(os.path.join(repo_dir or REPO_DIR, '*.repo')):
        try:
            with open(path) as handle:
                ids.update(re.findall(r'^\s*\[([^\]\s]+)\]', handle.read(), re.M))
        except OSError:
            continue
    devel = next((r for r in ('powertools', 'PowerTools', 'crb') if r in ids), None) or next(
        (r for r in sorted(ids) if r.startswith('codeready-builder') and r.endswith('-rpms')), None)
    base = [r for r in ('baseos', 'appstream') if r in ids]
    if devel and len(base) == 2:
        return ['--disablerepo=*', '--enablerepo=%s' % ','.join(base + [devel])]
    return ['--enablerepo=%s' % devel] if devel else []


def ensure_packages(names, root=RUNTIME_ROOT, runner=subprocess.run, log=None, reason=''):
    """Install the missing ones of `names` with dnf and record them as panel-installed. Returns those added."""
    say = log or (lambda text: None)
    missing = missing_packages(names, runner)
    if not missing:
        say('Build packages already installed: %s' % ' '.join(names))
        return []
    say('Installing OS packages with dnf (signed packages from the OS repositories): %s' % ' '.join(missing))
    ok, out = _smoke(['dnf', '-y', '-q', 'install'] + os_repo_args() + missing, runner, timeout=1800)
    say(out[-2000:])
    still = missing_packages(missing, runner)
    added = [name for name in missing if name not in still]
    if added:
        data = ledger(root)
        for name in added:
            data[name] = {'reason': reason, 'installed': int(time.time())}
        _ledger_write(root, data)
    if still:
        raise RuntimeError_('dnf could not install %s: %s' % (' '.join(still), out[-400:]))
    return added


def rpm_info(target, runner=subprocess.run, by_file=False):
    """{'package', 'size'} of an installed package (or of the package owning a file), or None."""
    argv = ['rpm', '-q', '--qf', r'%{NAME}\t%{SIZE}\n'] + (['-f'] if by_file else []) + [target]
    ok, out = _smoke(argv, runner, timeout=30)
    line = out.splitlines()[0].split('\t') if ok and out else []
    if len(line) != 2 or not PACKAGE_RE.match(line[0]) or not line[1].isdigit():
        return None
    return {'package': line[0], 'size': int(line[1])}


def panel_packages(root=RUNTIME_ROOT, runner=subprocess.run):
    out = []
    for name, info in sorted(ledger(root).items()):
        current = rpm_info(name, runner)
        out.append({'name': name, 'reason': (info or {}).get('reason', ''), 'installed': (info or {}).get('installed'),
                    'present': bool(current), 'size': current['size'] if current else 0})
    return out


def annotate_system(installed_runtimes, root=RUNTIME_ROOT, runner=subprocess.run):
    """Give OS-provided runtimes their package, its size, and whether the panel installed it (removable)."""
    owned = ledger(root)
    for entries in installed_runtimes.values():
        for entry in entries:
            if entry.get('source') != 'system':
                continue
            info = rpm_info(os.path.realpath(entry['path']), runner, by_file=True)
            entry.update(package=info['package'] if info else '', size=info['size'] if info else 0,
                         panel_installed=bool(info and info['package'] in owned))
    return installed_runtimes


def remove_package(name, in_use, root=RUNTIME_ROOT, runner=subprocess.run):
    """rpm -e exactly one panel-installed package; refused while apps need it or other packages depend on it."""
    if not PACKAGE_RE.match(name or '') or name not in ledger(root):
        raise RuntimeError_('Only OS packages installed by IndiansCloud can be removed here.')
    if in_use:
        raise RuntimeError_('%s is needed to deploy: %s' % (name, ', '.join(sorted(in_use))))
    if rpm_info(name, runner):
        ok, out = _smoke(['rpm', '-e', '--test', name], runner, timeout=120)
        if not ok:
            raise RuntimeError_('Other packages depend on %s: %s' % (name, out[-400:]))
        ok, out = _smoke(['rpm', '-e', name], runner, timeout=600)
        if not ok:
            raise RuntimeError_('rpm -e %s failed: %s' % (name, out[-400:]))
    data = ledger(root)
    data.pop(name, None)
    _ledger_write(root, data)
    return {'removed': name}


def _prune_python(tree):
    """Drop the GUI toolkit and its demos (Tcl/Tk, IDLE, turtle) and man pages: never used by web apps.

    C headers stay: pip needs them to build packages with C extensions.
    """
    import glob
    patterns = ('lib/tcl*', 'lib/tk*', 'lib/itcl*', 'lib/thread*', 'lib/libtcl*', 'lib/libtk*', 'share/man',
                'lib/python3.*/idlelib', 'lib/python3.*/tkinter', 'lib/python3.*/turtledemo',
                'lib/python3.*/turtle.py', 'lib/python3.*/lib-dynload/_tkinter*')
    for pattern in patterns:
        for path in glob.glob(os.path.join(tree, pattern)):
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)


def _world_readable(root):
    """Runtimes are shared by every site user: readable/executable by all, writable by root only."""
    for current, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(current, name)
            if os.path.islink(path):
                continue
            mode = os.lstat(path).st_mode & 0o777
            os.chmod(path, (mode | 0o444 | (0o111 if mode & 0o100 or os.path.isdir(path) else 0)) & ~0o022)


def uninstall(kind, version, in_use, root=RUNTIME_ROOT):
    """Remove a runtime that no app uses."""
    if in_use:
        raise RuntimeError_('%s %s is used by: %s' % (kind, version, ', '.join(sorted(in_use))))
    if kind == 'node' and VERSION_RE.match(version):
        shutil.rmtree(os.path.join(root, 'node', version))
    elif kind in ('python', 'java', 'ruby', 'go', 'deno', 'bun') and VERSION_RE.match(version):
        if not os.path.isdir(os.path.join(root, kind, version)):
            raise RuntimeError_('%s %s is not installed by the panel.' % (kind, version))
        shutil.rmtree(os.path.join(root, kind, version))
    elif kind == 'dotnet' and VERSION_RE.match(version.split('-')[0]):
        for framework in ('Microsoft.AspNetCore.App', 'Microsoft.NETCore.App'):
            shutil.rmtree(os.path.join(root, 'dotnet', 'shared', framework, version), ignore_errors=True)
    else:
        raise RuntimeError_('Only runtimes installed by the panel can be removed.')
    return {'removed': '%s %s' % (kind, version)}


# ----------------------------------------------------------------------------- Java tools

def webapp_runner_path(root=RUNTIME_ROOT):
    return os.path.join(root, 'java-tools', 'webapp-runner-%s.jar' % WEBAPP_RUNNER_VERSION)


def ensure_webapp_runner(root=RUNTIME_ROOT, fetcher=fetch, fetch_file=None, log=None):
    """Make sure the pinned webapp-runner jar is present; download and verify it once if not.

    The download is checked against Maven Central's .sha1 and then against the SHA-256 pinned here,
    so a changed artifact (or a compromised mirror publishing a matching .sha1) is refused.
    """
    say = log or (lambda text: None)
    target = webapp_runner_path(root)
    if os.path.isfile(target) and _digest(target, 'sha256') == WEBAPP_RUNNER_SHA256:
        return target
    tools = os.path.dirname(target)
    os.makedirs(tools, mode=0o755, exist_ok=True)
    os.chmod(tools, 0o755)
    url = WEBAPP_RUNNER_URL % (WEBAPP_RUNNER_VERSION, WEBAPP_RUNNER_VERSION)
    work = tempfile.mkdtemp(prefix='cp-tool-', dir=tools)
    try:
        sha1 = (fetcher(url + '.sha1').decode().split() or [''])[0].lower()
        if not re.match(r'^[0-9a-f]{40}$', sha1):
            raise RuntimeError_('Maven Central returned no SHA-1 for webapp-runner %s.' % WEBAPP_RUNNER_VERSION)
        path = _download(url, sha1, 'sha1', work, fetch_file)
        if _digest(path, 'sha256') != WEBAPP_RUNNER_SHA256:
            raise RuntimeError_('webapp-runner %s does not match the pinned SHA-256; the download was discarded.'
                                % WEBAPP_RUNNER_VERSION)
        os.chmod(path, 0o644)
        os.replace(path, target)
        say('webapp-runner %s installed at %s' % (WEBAPP_RUNNER_VERSION, target))
        return target
    finally:
        shutil.rmtree(work, ignore_errors=True)
