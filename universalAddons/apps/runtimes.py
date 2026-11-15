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
  pinned by version and SHA-256 and fetched from Maven Central on first use.

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
import subprocess
import tarfile
import tempfile
import urllib.request

RUNTIME_ROOT = '/opt/cp-runtimes'
KINDS = ('node', 'dotnet', 'python', 'java')
NODE_INDEX = 'https://nodejs.org/dist/index.json'
NODE_DIST = 'https://nodejs.org/dist/%s/'
DOTNET_INDEX = 'https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json'
PYTHON_SUMS = 'https://github.com/astral-sh/python-build-standalone/releases/latest/download/SHA256SUMS'
PYTHON_DOWNLOAD = 'https://github.com/astral-sh/python-build-standalone/releases/download/%s/%s'
SYSTEM_PYTHONS = ('/usr/bin/python3.13', '/usr/bin/python3.12', '/usr/bin/python3.11', '/usr/bin/python3.10',
                  '/usr/bin/python3.9')
VERSION_RE = re.compile(r'^\d{1,3}(\.\d{1,4}){1,3}$')
ADOPTIUM_RELEASES = 'https://api.adoptium.net/v3/info/available_releases'
ADOPTIUM_LATEST = ('https://api.adoptium.net/v3/assets/latest/%d/hotspot?architecture=%s&image_type=jre&os=linux'
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


def java_catalogue(assets_json, machine='x64'):
    """Entries from one Adoptium /assets/latest/<feature>/hotspot response (Temurin JRE, linux, glibc)."""
    out = []
    for asset in assets_json:
        binary, version = asset.get('binary') or {}, asset.get('version') or {}
        package = binary.get('package') or {}
        if (binary.get('os') != 'linux' or binary.get('architecture') != adoptium_arch(machine)
                or binary.get('image_type') != 'jre' or binary.get('jvm_impl') != 'hotspot'
                or binary.get('heap_size', 'normal') != 'normal' or asset.get('vendor', 'eclipse') != 'eclipse'):
            continue
        sha = str(package.get('checksum') or '').lower()
        link, name = str(package.get('link') or ''), str(package.get('name') or '')
        if not re.match(r'^[0-9a-f]{64}$', sha) or not link.startswith('https://') or not name.endswith('.tar.gz'):
            continue
        number = '%d.%d.%d' % (int(version['major']), int(version.get('minor') or 0), int(version.get('security') or 0))
        out.append({'kind': 'java', 'version': number, 'feature': int(version['major']), 'sha256': sha, 'url': link,
                    'file': name, 'size': package.get('size'), 'release': asset.get('release_name', ''),
                    'label': 'Java %d (Temurin JRE %s)' % (int(version['major']),
                                                          version.get('openjdk_version') or number)})
    return out[:1]


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
    result = {'node': [], 'dotnet': [], 'python': [], 'java': [], 'errors': {}}
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
            result['java'] += java_catalogue(json.loads(fetcher(ADOPTIUM_LATEST % (feature, adoptium_arch(machine)))),
                                             machine)
    except Exception as exc:
        result['errors']['java'] = str(exc)[:200]
    return result


# ----------------------------------------------------------------------------- installed

def installed(root=RUNTIME_ROOT, runner=subprocess.run):
    """{'node': [...], 'dotnet': [...], 'python': [...], 'java': [...]} of usable runtimes, with binary paths."""
    out = {'node': [], 'dotnet': [], 'python': system_pythons(runner=runner), 'java': []}
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
                out['java'].append({'kind': 'java', 'version': version, 'feature': int(version.split('.')[0]),
                                    'path': binary, 'source': 'Temurin', 'size': _du(os.path.join(java_root, version))})
    managed = {entry['version'] for entry in out['java']}
    out['java'] += [entry for entry in system_javas(runner=runner) if entry['version'] not in managed]
    return out


def _version_key(text):
    return [int(p) if p.isdigit() else -1 for p in text.split('.')]


def find(kind, version, root=RUNTIME_ROOT, runner=subprocess.run):
    for runtime in installed(root, runner).get(kind, []):
        if runtime['version'] == version:
            return runtime
    raise RuntimeError_('%s %s is not installed.' % (kind, version))


def _du(path):
    total = 0
    for current, dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(current, name)).st_size
            except OSError:
                pass
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


def _smoke(argv, runner=subprocess.run):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return out.returncode == 0, (out.stdout or '').strip()[-400:]


def install(kind, version, root=RUNTIME_ROOT, fetcher=fetch, fetch_file=None, runner=subprocess.run, log=None):
    """Download, verify, extract and smoke-test a runtime. Returns the installed entry."""
    say = log or (lambda text: None)
    if kind not in KINDS or not VERSION_RE.match(version or ''):
        raise RuntimeError_('Unknown runtime.')
    machine = arch()
    os.makedirs(root, mode=0o755, exist_ok=True)
    work = tempfile.mkdtemp(prefix='cp-runtime-', dir=root)
    try:
        if kind == 'node':
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
            feature = int(version.split('.')[0])
            assets = json.loads(fetcher(ADOPTIUM_LATEST % (feature, adoptium_arch(machine))))
            entry = next((e for e in java_catalogue(assets, machine) if e['version'] == version), None)
            if not entry:
                raise RuntimeError_('Java %s is not the current Temurin %d JRE build; refresh the list.' % (version, feature))
            archive = _download(entry['url'], entry['sha256'], 'sha256', work, fetch_file)
            staged = os.path.join(work, 'tree')
            os.makedirs(staged)
            _safe_extract(archive, staged, strip=1)
            shutil.rmtree(os.path.join(staged, 'man'), ignore_errors=True)  # legal/ (licences) stays
            ok, out = _smoke([os.path.join(staged, 'bin', 'java'), '-version'], runner)
            if not ok:
                raise RuntimeError_('Java %s does not run on this server: %s' % (version, out))
            destination = os.path.join(root, 'java', version)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            if os.path.exists(destination):
                shutil.rmtree(destination)
            os.rename(staged, destination)
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
    elif kind in ('python', 'java') and VERSION_RE.match(version):
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
