"""Root side of the App catalogue: verified downloads and installs, as the site user.

Root only resolves the site, creates the database through the panel's own code
(mysqlUtilities.submitDBCreation: package quota, unique names, registration), registers a Ghost
app with the Universal Apps add-on and reads small files the site user wrote (O_NOFOLLOW, owner
checked). Downloading, checksums, signature checks, extraction, copying and the apps' own CLI
installers all run as the site user (siteinfo.run_as) in a work directory inside the site home.
"""
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request

from universalAddons import jobs, siteinfo
from universalAddons.appcatalog import service as svc
from universalAddons.appcatalog.service import CatalogError

WORK_ROOT = '.ic-appcatalog'             # below the site home, removed after each install
BACKUP_ROOT = 'appcatalog-backups'       # below the site home: what "overwrite" moved aside
CURL = ['curl', '-fsSL', '--proto', '=https', '--tlsv1.2', '--retry', '2', '--connect-timeout', '20',
        '--max-filesize', str(svc.MAX_DOWNLOAD), '-A', 'IndiansCloud-AppCatalog/1.0']


def _site(domain):
    try:
        return siteinfo.resolve(svc.clean_domain(domain))
    except siteinfo.SiteError as exc:
        raise CatalogError(str(exc))


def target_dir(site, app, rel):
    if svc.NEW[app]['kind'] == 'node':
        return os.path.join(site.home, 'apps', rel)
    return site.path(rel)


def target_problem(path, listdir=os.listdir):
    """Why `path` is not an empty install target ('' when it is empty or missing)."""
    if os.path.islink(path):
        return 'The target is a symbolic link.'
    if not os.path.exists(path):
        return ''
    if not os.path.isdir(path):
        return 'The target exists and is not a directory.'
    entries = svc.blocking_entries(listdir(path))
    if entries:
        shown = ', '.join(entries[:8]) + (' …' if len(entries) > 8 else '')
        return 'The target directory is not empty (%d item(s): %s).' % (len(entries), shown)
    return ''


def catalogue(domain, tools=None):
    site = _site(domain)
    tools = tools or {'composer': bool(shutil.which('composer')), 'gpg': bool(shutil.which('gpg')),
                      'unzip': bool(shutil.which('unzip')), 'bzip2': bool(shutil.which('bzip2'))}
    apps = svc.catalogue(site.domain)
    for app in apps:
        if not app['new']:
            continue
        needs = []
        if app['key'] == 'drupal' and not tools['composer']:
            needs.append('Composer (for drush)')
        if app['key'] in ('nextcloud', 'mediawiki', 'matomo') and not tools['gpg']:
            needs.append('gpg')
        if app['key'] in ('phpbb', 'matomo', 'grav') and not tools['unzip']:
            needs.append('unzip')
        if app['key'] == 'nextcloud' and not tools['bzip2']:
            needs.append('bzip2')
        if app['key'] == 'ghost' and not _node_versions():
            needs.append('a Node.js runtime (Universal Apps add-on)')
        app['missing'] = needs
        default = target_dir(site, app['key'], 'ghost' if app['kind'] == 'node' else '')
        app['default_target'] = default
        app['target_problem'] = target_problem(default)
    return {'domain': site.domain, 'docroot': site.docroot, 'home': site.home, 'apps': apps}


def check_target(domain, app, path):
    site = _site(domain)
    request = svc.clean_request({'app': app, 'path': path, 'admin_email': 'x@example.com'}, site.domain)
    target = target_dir(site, app, request['path'])
    return {'target': target, 'problem': target_problem(target)}


def _node_versions():
    try:
        from universalAddons.apps import runtimes as rt
        return [r['version'] for r in rt.installed().get('node', [])]
    except Exception:
        return []


# ----------------------------------------------------------------------------- install (job)

def install(domain, request):
    site = _site(domain)
    request = svc.clean_request(request, site.domain)
    target = target_dir(site, request['app'], request['path'])
    problem = target_problem(target)
    if problem and not request['overwrite']:
        raise CatalogError(problem + ' Tick "overwrite" and confirm to move the existing files aside first.')
    if problem and os.path.islink(target):
        raise CatalogError(problem)
    if request['app'] == 'ghost':
        from universalAddons.apps import service as apps_svc
        if request['path'] in apps_svc.load_apps():
            raise CatalogError('A Universal App called %s already exists.' % request['path'])
    return jobs.spawn('appcatalog', 'install_run', {'domain': site.domain, 'request': request})


class Installer:
    """One install: the site, its work directory, the job log and the secrets to keep out of it."""

    def __init__(self, site, request, job, runner=subprocess.run):
        self.site, self.request, self.job, self.runner = site, request, job, runner
        self.app = svc.NEW[request['app']]
        self.target = target_dir(site, request['app'], request['path'])
        self.work = os.path.join(site.home, WORK_ROOT, job.job_id if job else 'test')
        self.secrets = []
        self.credentials = {}
        self.result = {}

    # -- helpers

    def log(self, text):
        if self.job:
            self.job.log(svc.redact(str(text), self.secrets)[-4000:])

    def run(self, argv, cwd=None, timeout=900, env=None, input=None, check=True, what=None):
        code, out = siteinfo.run_as(self.site, argv, cwd=cwd or self.work, extra_env=env, timeout=timeout,
                                    input=input, runner=self.runner)
        if check and code != 0:
            self.log(out[-3000:])
            raise CatalogError('%s failed (exit %d).' % (what or os.path.basename(argv[0]), code))
        return out

    def path(self, name):
        return os.path.join(self.work, name)

    def fetch(self, url, name):
        self.run(CURL + ['-o', self.path(name), url], timeout=1800, what='Download of %s' % url)
        return self.path(name)

    def fetch_text(self, url, name, limit=4 * 1024 * 1024):
        self.fetch(url, name)
        text = siteinfo.read_owned(self.site, self.path(name), max_bytes=limit)
        if text is None:
            raise CatalogError('Download of %s gave no file.' % url)
        return text

    def digest(self, path, algorithm):
        tool = {'sha256': 'sha256sum', 'sha512': 'sha512sum', 'md5': 'md5sum'}[algorithm]
        return svc.parse_digest_output(self.run([tool, '--', path], what=tool))

    def verify_digest(self, path, algorithm, expected):
        actual = self.digest(path, algorithm)
        svc.check_digest(actual, expected, os.path.basename(path))
        self.log('%s %s: OK (%s)' % (algorithm.upper(), os.path.basename(path), actual))
        return actual

    def verify_signature(self, path, sig_path, key_path, fingerprint=None):
        home = self.path('gnupg')
        self.run(['mkdir', '-m', '0700', '-p', home], what='mkdir')
        base = ['gpg', '--homedir', home, '--batch', '--no-tty', '--no-autostart']
        self.run(base + ['--import', key_path], what='gpg --import')
        status = self.run(base + ['--status-fd', '1', '--verify', sig_path, path], check=False)
        found = svc.check_signature(status, fingerprint)
        self.log('Signature of %s: good, by %s' % (os.path.basename(path), ', '.join(found)))
        return found

    def extract(self, archive):
        """Extract into work/src as the site user after checking every name; returns the top directory."""
        if archive.endswith('.zip'):
            names = self.run(['unzip', '-Z1', archive], what='unzip -Z1').splitlines()
        else:
            names = self.run(['tar', '-tf', archive], what='tar -t').splitlines()
        top = svc.check_archive_names(names, self.app['top'])
        source = self.path('src')
        self.run(['mkdir', '-p', source], what='mkdir')
        if archive.endswith('.zip'):
            self.run(['unzip', '-q', archive, '-d', source], what='unzip')
        else:
            self.run(['tar', '-xf', archive, '-C', source, '--no-same-owner', '--no-same-permissions'], what='tar -x')
        return os.path.join(source, top)

    def prepare_target(self):
        """Create the target, or move what is in it to ~/appcatalog-backups/<time>/ when overwriting."""
        self.site.inside(self.target)
        problem = target_problem(self.target)
        if problem:
            if not self.request['overwrite']:
                raise CatalogError(problem)
            if os.path.islink(self.target):
                raise CatalogError(problem)
            backup = os.path.join(self.site.home, BACKUP_ROOT, '%s-%s' % (time.strftime('%Y%m%d-%H%M%S'),
                                                                         self.request['app']))
            self.run(['mkdir', '-p', '-m', '0700', backup], what='mkdir')
            entries = [os.path.join(self.target, n) for n in svc.blocking_entries(os.listdir(self.target))]
            self.run(['mv', '-t', backup, '--'] + entries, what='Moving the existing files aside')
            self.result['backup'] = backup
            self.log('Moved %d existing item(s) to %s' % (len(entries), backup))
        elif not os.path.isdir(self.target):
            self.run(['mkdir', '-p', '-m', '0755', self.target], what='mkdir')

    def copy_in(self, source):
        self.run(['cp', '-a', '--', source + '/.', self.target + '/'], timeout=1800, what='Copying the files')

    def create_database(self):
        name, user = svc.database_names(self.site.user, self.request['app'])
        password = svc.new_password(24)
        self.secrets.append(password)
        from universalAddons import django_env
        django_env.setup()
        from plogical.mysqlUtilities import mysqlUtilities
        from websiteFunctions.models import ChildDomains, Websites
        try:
            website = Websites.objects.get(domain=self.site.domain)
        except Websites.DoesNotExist:
            website = ChildDomains.objects.get(domain=self.site.domain).master
        # The panel's database code: package quota, unique names, creation and registration.
        status, message = mysqlUtilities.submitDBCreation(name, user, password, website.domain)
        if status != 1:
            raise CatalogError('The database could not be created: %s' % message)
        self.log('Database %s created for %s (counts towards the package quota).' % (name, website.domain))
        self.result['database'] = name
        self.credentials['database'] = {'name': name, 'user': user, 'password': password, 'host': 'localhost'}
        return name, user, password

    def admin_password(self):
        password = svc.new_password(20)
        self.secrets.append(password)
        return password

    def secret_file(self, name, text):
        path = self.path(name)
        self.run(['sh', '-c', 'umask 077 && cat > "$1"', 'sh', path], input=text, what='Writing %s' % name)
        return path

    # -- per app

    def drupal(self):
        release = svc.parse_drupal_feed(self.fetch_text(self.app['feed'], 'release-history.xml'))
        self.log('Drupal %s' % release['version'])
        archive = self.fetch(release['url'], 'drupal.tar.gz')
        if release['size']:
            size = os.lstat(archive).st_size
            if size != release['size']:
                raise CatalogError('Size mismatch for the Drupal tarball (%d, expected %d).' % (size, release['size']))
        self.verify_digest(archive, 'md5', release['md5'])
        sha = self.digest(archive, 'sha256')
        self.result.update(version=release['version'], sha256=sha)
        source = self.extract(archive)
        self.prepare_target()
        self.copy_in(source)
        name, user, password = self.create_database()
        php = self.site.php
        env = {'COMPOSER_HOME': self.path('composer'), 'COMPOSER_NO_INTERACTION': '1'}
        self.log(self.run([php, shutil.which('composer') or '/usr/bin/composer', 'require', 'drush/drush',
                           '--no-interaction', '--no-progress', '--update-no-dev'], cwd=self.target, env=env,
                          timeout=1800, what='composer require drush/drush')[-2000:])
        settings = os.path.join(self.target, 'sites/default/settings.php')
        self.run(['cp', '--', os.path.join(self.target, 'sites/default/default.settings.php'), settings], what='cp')
        self.run(['sh', '-c', 'cat >> "$1"', 'sh', settings], input=svc.drush_settings(name, user, password),
                 what='Writing settings.php')
        drush = os.path.join(self.target, 'vendor/bin/drush')
        out = self.run([php] + svc.drush_install_args(drush, self.request['site_name'], self.request['admin_user'],
                                                      self.request['admin_email']),
                       cwd=self.target, env={'PATH': os.path.dirname(php) + ':' + siteinfo.USER_PATH},
                       timeout=1800, what='drush site:install')
        admin_password = svc.parse_drush_password(out)
        if admin_password:
            self.secrets.append(admin_password)
        self.log(out[-2000:])
        self.run(['chmod', '0440', settings], what='chmod')
        login = {'user': self.request['admin_user'], 'url': svc.site_url(self.site.domain, self.request['path']) +
                 'user/login'}
        if admin_password:
            login['password'] = admin_password
        else:
            login['one_time_link'] = self.run([php, drush, 'user:login', '--uri=' + svc.site_url(
                self.site.domain, self.request['path'])], cwd=self.target, what='drush user:login').strip()
        self.credentials['admin'] = login

    def nextcloud(self):
        archive = self.fetch(self.app['url'], 'latest.tar.bz2')
        expected = svc.parse_checksum_file(self.fetch_text(self.app['url'] + '.sha256', 'latest.sha256'),
                                           'latest.tar.bz2')
        self.result['sha256'] = self.verify_digest(archive, 'sha256', expected)
        sig = self.fetch(self.app['url'] + '.asc', 'latest.tar.bz2.asc')
        key = self.fetch(self.app['key_url'], 'nextcloud.asc')
        self.verify_signature(archive, sig, key, self.app['fingerprint'])
        source = self.extract(archive)
        data_dir = os.path.join(self.site.home, 'nextcloud-data' + ('-' + self.request['path'].replace('/', '-')
                                                                    if self.request['path'] else ''))
        if target_problem(data_dir):
            raise CatalogError('%s already exists and is not empty.' % data_dir)
        self.prepare_target()
        self.copy_in(source)
        self.run(['mkdir', '-p', '-m', '0750', data_dir], what='mkdir')
        name, user, password = self.create_database()
        php, occ = self.site.php, os.path.join(self.target, 'occ')
        temporary = self.admin_password()
        self.log(self.run(svc.occ_install_args(php, occ, name, user, password, self.request['admin_user'], temporary,
                                               data_dir), cwd=self.target, timeout=1800,
                          what='occ maintenance:install')[-2000:])
        url = svc.site_url(self.site.domain, self.request['path'])
        for argv in svc.occ_followup_args(php, occ, self.site.domain, url.rstrip('/')):
            self.run(argv, cwd=self.target, what='occ config:system:set')
        final = self.admin_password()
        # The password that stays never appears on a command line: occ reads it from OC_PASS.
        self.run([php, occ, 'user:resetpassword', '--password-from-env', self.request['admin_user']], cwd=self.target,
                 env={'OC_PASS': final}, what='occ user:resetpassword')
        self.result.update(data_dir=data_dir)
        self.credentials['admin'] = {'user': self.request['admin_user'], 'password': final, 'url': url}

    def phpbb(self):
        release = svc.parse_phpbb_feed(self.fetch_text(self.app['feed'], 'versions.json'))
        archive = self.fetch(release['url'], release['file'])
        expected = svc.parse_checksum_file(self.fetch_text(release['sha256_url'], 'phpbb.sha256'), release['file'])
        self.result.update(version=release['version'], sha256=self.verify_digest(archive, 'sha256', expected))
        source = self.extract(archive)
        self.prepare_target()
        self.copy_in(source)
        name, user, password = self.create_database()
        admin = self.admin_password()
        script_path = '/' + self.request['path'] if self.request['path'] else '/'
        config = self.secret_file('install-config.yml', svc.phpbb_config(
            self.request['site_name'], self.request['admin_user'], admin, self.request['admin_email'], name, user,
            password, self.site.domain, script_path))
        self.log(self.run(svc.phpbb_install_args(self.site.php, self.target, config), cwd=self.target,
                          timeout=1800, what='phpbbcli.php install')[-2000:])
        self.run(['rm', '-rf', '--', os.path.join(self.target, 'install')], what='Removing install/')
        self.credentials['admin'] = {'user': self.request['admin_user'], 'password': admin,
                                     'url': svc.site_url(self.site.domain, self.request['path'])}

    def mediawiki(self):
        release = svc.parse_mediawiki_feed(self.fetch_text(self.app['feed'], 'mw-version.json'))
        archive = self.fetch(release['url'], 'mediawiki.tar.gz')
        sig = self.fetch(release['sig_url'], 'mediawiki.tar.gz.sig')
        keys = self.fetch(self.app['key_url'], 'mediawiki-keys.txt')
        self.verify_signature(archive, sig, keys)
        self.result.update(version=release['version'], sha256=self.digest(archive, 'sha256'))
        source = self.extract(archive)
        self.prepare_target()
        self.copy_in(source)
        name, user, password = self.create_database()
        admin = self.admin_password()
        db_file = self.secret_file('dbpass', password)
        admin_file = self.secret_file('adminpass', admin)
        script_path = '/' + self.request['path'] if self.request['path'] else ''
        self.log(self.run(svc.mediawiki_install_args(
            self.site.php, self.target, name, user, db_file, admin_file, 'https://' + self.site.domain, script_path,
            self.request['site_name'], self.request['admin_user']), cwd=self.target, timeout=1800,
            what='maintenance/install.php')[-2000:])
        self.run(['chmod', '0640', os.path.join(self.target, 'LocalSettings.php')], what='chmod')
        self.credentials['admin'] = {'user': self.request['admin_user'], 'password': admin,
                                     'url': svc.site_url(self.site.domain, self.request['path'])}

    def matomo(self):
        archive = self.fetch(self.app['url'], 'matomo-latest.zip')
        sig = self.fetch(self.app['url'] + '.asc', 'matomo-latest.zip.asc')
        key = self.fetch(self.app['key_url'], 'matomo.asc')
        self.verify_signature(archive, sig, key, self.app['fingerprint'])
        self.result['sha256'] = self.digest(archive, 'sha256')
        source = self.extract(archive)
        self.prepare_target()
        self.copy_in(source)
        self.create_database()
        self.credentials['admin'] = {'url': svc.site_url(self.site.domain, self.request['path']),
                                     'next': 'Open the address now and finish the setup with the database details '
                                             'below (host localhost); you choose the Matomo superuser there.'}

    def grav(self):
        release = svc.parse_github_release(self.fetch_text(self.app['feed'], 'grav-release.json'))
        archive = self.fetch(release['url'], 'grav-admin.zip')
        self.result.update(version=release['version'], sha256=self.verify_digest(archive, 'sha256', release['sha256']))
        source = self.extract(archive)
        self.prepare_target()
        self.copy_in(source)
        admin = self.admin_password()
        hashed = self.run([self.site.php, '-r', 'echo password_hash(trim(fgets(STDIN)), PASSWORD_DEFAULT);'],
                          input=admin + '\n', what='php password_hash').strip()
        if not hashed.startswith('$2y$') and not hashed.startswith('$argon2'):
            raise CatalogError('Could not hash the admin password.')
        accounts = os.path.join(self.target, 'user/accounts')
        self.run(['mkdir', '-p', accounts], what='mkdir')
        siteinfo.write_as(self.site, os.path.join(accounts, self.request['admin_user'].lower() + '.yaml'),
                          svc.grav_account(self.request['admin_email'], hashed), runner=self.runner)
        self.credentials['admin'] = {'user': self.request['admin_user'].lower(), 'password': admin,
                                     'url': svc.site_url(self.site.domain, self.request['path']) + 'admin'}

    def ghost(self):
        from universalAddons.apps import actions as apps_actions
        from universalAddons.apps import runtimes as rt
        from universalAddons.apps import service as apps_svc
        release = svc.parse_npm_meta(self.fetch_text(self.app['feed'], 'ghost.json'))
        node = svc.pick_node(_node_versions(), release['node'])
        if not node:
            raise CatalogError('Ghost %s needs Node.js %s; install a matching runtime in Universal Apps first.'
                               % (release['version'], release['node']))
        archive = self.fetch(release['url'], 'ghost.tgz')
        self.result.update(version=release['version'], node=node,
                           sha512=self.verify_digest(archive, 'sha512', release['sha512']))
        source = self.extract(archive)
        self.prepare_target()
        self.copy_in(source)
        mysql8 = _mysql_major() >= 8
        database = {'client': 'sqlite3'}
        if mysql8:
            name, user, password = self.create_database()
            database = {'client': 'mysql', 'name': name, 'user': user, 'password': password}
        else:
            self.log('This server runs MariaDB; Ghost supports only MySQL 8 in production, so Ghost uses its '
                     'built-in SQLite database (content/data/ghost.db).')
            self.run(['mkdir', '-p', os.path.join(self.target, 'content/data')], what='mkdir')
        memory = min(768, apps_actions.load_policy()['max_memory_mb'])
        saved = apps_actions.save_app(self.site.domain, {
            'id': self.request['path'], 'kind': 'node', 'runtime': node, 'dir': self.target, 'entry': 'index.js',
            'prefix': '/', 'memory_mb': memory})
        app = apps_svc.load_apps()[saved['app']['id']]
        url = svc.site_url(self.site.domain, '')
        siteinfo.write_as(self.site, os.path.join(self.target, 'config.production.json'),
                          svc.ghost_config(url, app['port'], os.path.join(self.target, 'content'), database),
                          runner=self.runner)
        self.run(['chmod', '0600', os.path.join(self.target, 'config.production.json')], what='chmod')
        runtime = rt.find('node', node)
        apps_svc.install_dependencies(app, runtime, log=self.log)
        apps_actions._write_unit(app)
        apps_svc.run(['systemctl', 'enable', apps_svc.unit_name(app['id'])])
        code, out = apps_svc.run(['systemctl', 'restart', apps_svc.unit_name(app['id'])])
        if code != 0 or not apps_svc.wait_listening(app['port'], seconds=120):
            self.log('\n'.join(apps_svc.logs(app, 60)))
            raise CatalogError('Ghost did not start; see the log above. The app stays registered in Universal Apps.')
        apps_actions._sync_vhost(self.site.domain)
        admin = self.admin_password()
        _ghost_setup(app['port'], self.site.domain, url, self.request['admin_email'], admin, self.request['site_name'])
        self.result.update(app=app['id'], port=app['port'], database=database['client'])
        self.credentials['admin'] = {'user': self.request['admin_email'], 'password': admin, 'url': url + 'ghost/'}


def _mysql_major(runner=subprocess.run):
    code, out = siteinfo.run(['mysql', '--version'], runner, timeout=30)
    if code != 0 or 'mariadb' in out.lower():
        return 0
    match = re.search(r'(?:Ver|Distrib)\s+(\d+)\.', out)
    return int(match.group(1)) if match else 0


def _ghost_setup(port, domain, url, email, password, title, opener=urllib.request.urlopen):
    """Create the Ghost owner account through Ghost's own setup endpoint (local port, not public)."""
    request = urllib.request.Request(
        'http://127.0.0.1:%d/ghost/api/admin/authentication/setup/' % port,
        data=svc.ghost_setup_body('Administrator', email, password, title).encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json', 'Host': domain, 'Origin': url.rstrip('/'),
                 'X-Forwarded-Proto': 'https', 'Accept-Version': 'v5.0'})
    last = None
    for attempt in range(10):
        try:
            with opener(request, timeout=60) as response:
                if 200 <= response.status < 300:
                    return True
                last = 'HTTP %d' % response.status
        except Exception as exc:
            last = exc
        time.sleep(3)
    raise CatalogError('Ghost started, but the owner account could not be created (%s). Open %sghost/ now and '
                       'create it yourself.' % (str(last)[:200], url))


def install_run(job_id, domain, request):
    site = _site(domain)
    request = svc.clean_request(request, site.domain)
    job = jobs.Job(job_id)
    installer = Installer(site, request, job)

    def prepare(job_):
        siteinfo.run_as(site, ['rm', '-rf', '--', installer.work], cwd=site.home, timeout=300)
        installer.run(['mkdir', '-p', '-m', '0700', installer.work], cwd=site.home, what='mkdir')

    def install_app(job_):
        getattr(installer, request['app'])()

    def finish(job_):
        siteinfo.run_as(site, ['rm', '-rf', '--', installer.work], cwd=site.home, timeout=300)
        return dict(installer.result, target=installer.target, credentials=installer.credentials)

    try:
        return jobs.run_job(job_id, [('Prepare', prepare), ('Install %s' % installer.app['title'], install_app),
                                     ('Finish', finish)])
    finally:
        if jobs.Job(job_id).data.get('state') == 'failed':
            siteinfo.run_as(site, ['rm', '-rf', '--', installer.work], cwd=site.home, timeout=300)


def job_status(job_id):
    """Job status; admin credentials are returned once and then removed from the status file."""
    data = jobs.status(job_id)
    if data.get('state') != 'done':
        return data
    job = jobs.Job(job_id)
    changed = False
    for value in (job.data.get('result') or {}).values():
        if isinstance(value, dict) and 'credentials' in value:
            value.pop('credentials')
            value['credentials_shown'] = True
            changed = True
    if changed:
        job._save()
    return data


ACTIONS = {
    'catalogue': lambda domain: catalogue(domain),
    'check_target': lambda domain, app, path='': check_target(domain, app, path),
    'install': lambda domain, request: install(domain, request),
    'install_run': install_run,
    'job': job_status,
}
