(function () {
    'use strict';
    var root = document.getElementById('ua-apps');
    if (!root || !document.getElementById('app-list')) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1';
    var KINDS = ['node', 'python', 'dotnet', 'java', 'ruby', 'go', 'deno', 'bun'];
    var KIND_LABEL = {node: 'Node.js', python: 'Python', dotnet: '.NET', java: 'Java', kotlin: 'Kotlin (JVM)', ruby: 'Ruby',
        go: 'Go', deno: 'Deno', bun: 'Bun'};
    var state = {runtimes: {node: [], python: [], dotnet: [], java: [], ruby: [], go: [], deno: [], bun: [], java_jdk: []}, apps: []};
    var HINT = {
        node: 'Upload your app into the app directory (it is created as ~/apps/<name>). Entry: the file to run (server.js) or "npm-start". Dependencies are installed with npm ci --omit=dev. Listen on process.env.PORT.',
        python: 'WSGI: module:callable (e.g. myproject.wsgi:application). ASGI: module:app (e.g. main:app). requirements.txt is installed into a private virtualenv.',
        dotnet: 'Upload the output of "dotnet publish -c Release" and name the .dll. The app listens on ASPNETCORE_URLS automatically.',
        jar: 'Upload the built .jar and name it. Spring Boot jars pick up SERVER_PORT and the context path (URL path) automatically; other apps listen on the PORT variable, on 127.0.0.1. The heap is 3/4 of the memory limit; Spring Boot usually needs 512 MB or more.',
        war: 'Upload the .war and name it. WARs run on embedded Tomcat 9 (javax.servlet); Jakarta EE 9+ WARs (jakarta.servlet) need Tomcat 10+ and will not start. The URL path becomes the context path.',
        kotlin: 'Ktor, Spring Boot (Kotlin) and http4k apps run as a JAR on the Java runtime. Upload the built JAR, or the project with gradlew and choose a Gradle task: it runs on deploy as your user with JAVA_HOME at the selected Java, which must be a JDK. Ktor EngineMain: tick the Ktor option (it binds 0.0.0.0 otherwise). embeddedServer and http4k: listen on System.getenv("PORT") and host 127.0.0.1.',
        rails: 'Upload the app with Gemfile and Gemfile.lock (puma in it). Deploy runs bundle install in deployment mode into vendor/bundle, assets:precompile and db:migrate, as your user. RAILS_ENV=production; SECRET_KEY_BASE is generated once and kept with the app (never shown). Put DATABASE_URL in the variables. Behind the proxy set config.assume_ssl = true when force_ssl is on.',
        rack: 'config.ru served by puma (bundle exec puma). Gemfile and Gemfile.lock with puma are required; gems go to vendor/bundle. Under a URL path, wrap the app in map ENV["APP_BASE_PATH"] do ... end.',
        go: 'Upload a binary built for linux (GOOS=linux GOARCH=amd64) and name it, or upload the module and tick go build (needs a Go toolchain; GOTOOLCHAIN=local, CGO off). Listen on os.Getenv("PORT") and host 127.0.0.1.',
        deno: 'deno run: call Deno.serve({port: Number(Deno.env.get("PORT")), hostname: "127.0.0.1"}, handler). deno serve: export default {fetch}; the panel passes --host and --port. Dependencies are cached into .deno in the app directory on deploy.',
        bun: 'Entry: the file to run (index.ts) or "bun-start" for the start script. Dependencies: bun install --production (--frozen-lockfile when bun.lock exists). Listen on process.env.PORT, hostname 127.0.0.1.'
    };
    var PLACEHOLDER = {node: 'server.js', python: 'app:app', dotnet: 'MyApp.dll', jar: 'app.jar', war: 'app.war',
        kotlin: 'build/libs/app-all.jar', rails: 'config.ru', rack: 'config.ru', go: 'app', deno: 'main.ts', bun: 'index.ts'};
    function show(id, visible) { $(id).style.display = visible ? '' : 'none'; }

    function size(bytes) { return bytes ? (bytes / 1048576).toFixed(0) + ' MB' : ''; }

    function watch(jobId, after) {
        $('app-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('app-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-100).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (after) { after(j); }
            }).catch(function (e) { UA.showError($('app-job-out'), e); });
        })();
        $('app-job').scrollIntoView({behavior: 'smooth'});
    }

    function fillRuntimes() {
        var choice = $('app-kind').value, kotlin = choice === 'kotlin', kind = kotlin ? 'java' : choice;
        var versions = state.runtimes[kind] || [], jdks = state.runtimes.java_jdk || [], current = $('app-runtime').value;
        var options = versions.map(function (v) {
            return '<option value="' + esc(v) + '">' + esc(v) + (kind === 'java' && jdks.indexOf(v) >= 0 ? ' (JDK)' : '') + '</option>';
        });
        if (kind === 'go') { options.unshift('<option value="">(no toolchain: run an uploaded binary)</option>'); }
        $('app-runtime').innerHTML = options.join('') || '<option value="">(no ' + esc(KIND_LABEL[choice]) + ' runtime installed)</option>';
        if (current) { $('app-runtime').value = current; }
        var java = kind === 'java', key = java ? (kotlin && $('app-jmode').value === 'jar' ? 'kotlin' : $('app-jmode').value)
            : (kind === 'ruby' ? $('app-rmode').value : kind);
        show('app-mode', kind === 'python');
        show('app-jmode', java); show('app-jvm-row', java);
        show('app-rmode', kind === 'ruby'); show('app-dmode', kind === 'deno');
        show('app-workers', (kind === 'python' && $('app-mode').value !== 'script') || kind === 'ruby');
        $('app-workers').title = kind === 'ruby' ? 'puma workers (1 = single process)' : 'workers';
        var jar = java && $('app-jmode').value === 'jar';
        show('app-gradle-row', jar); show('app-ktor-row', jar && kotlin);
        show('app-gobuild-row', kind === 'go'); show('app-gopkg-row', kind === 'go' && $('app-gobuild').checked);
        show('app-rails-row', kind === 'ruby' && $('app-rmode').value === 'rails'); show('app-deno-row', kind === 'deno');
        show('app-build-row', jar || kind === 'go' || kind === 'ruby' || kind === 'deno');
        $('app-entry').placeholder = kind === 'python' && $('app-mode').value === 'script' ? 'main.py' : PLACEHOLDER[key];
        $('app-hint').textContent = HINT[key];
    }
    $('app-kind').addEventListener('change', function () {
        var kind = $('app-kind').value;
        if ((kind === 'java' || kind === 'kotlin' || kind === 'ruby') && Number($('app-memory').value) === 256) { $('app-memory').value = 512; }
        if (kind === 'ruby' && Number($('app-workers').value) === 2) { $('app-workers').value = 1; }
        $('app-runtime').value = '';
        fillRuntimes();
    });
    ['app-mode', 'app-jmode', 'app-rmode', 'app-gobuild'].forEach(function (id) { $(id).addEventListener('change', fillRuntimes); });

    function badge(s) {
        var cls = s.state === 'active' ? 'pass' : (s.state === 'failed' ? 'fail' : 'info');
        return '<span class="ua-badge ua-badge-' + cls + '">' + esc(s.state === 'active' ? 'running' : s.state) + '</span>';
    }

    function loadApps() {
        return api('apps', {}).then(function (d) {
            state.apps = d.result.apps;
            state.runtimes = d.result.runtimes;
            fillRuntimes();
            $('app-list').innerHTML = state.apps.length ? '<table class="ua-table"><thead><tr><th>App</th><th>Site & path</th><th>Runtime</th><th>Status</th><th>Limits</th><th></th></tr></thead><tbody>' +
                state.apps.map(function (a, i) {
                    var s = a.status;
                    return '<tr><td><strong>' + esc(a.id) + '</strong><div class="ua-fix">' + esc(a.dir) + '</div></td><td>' + esc(a.domain) + esc(a.prefix) +
                        (a.websocket ? '<div class="ua-fix">ws: ' + esc(a.websocket) + '</div>' : '') + '</td><td>' +
                        esc(KIND_LABEL[a.flavor === 'kotlin' ? 'kotlin' : a.kind] || a.kind) + ' ' + esc(a.runtime || '') +
                        '<div class="ua-fix">' + (a.mode ? esc(a.mode) + ' ' : '') + esc(a.entry) + (a.build ? ' · build: ' + esc(a.build === true ? 'go build' : a.build) : '') + '</div></td><td>' +
                        badge(s) + (s.memory_mb !== null && s.state === 'active' ? '<div class="ua-fix">' + esc(s.memory_mb) + ' MB used, restarts ' + esc(s.restarts) + '</div>' : '') +
                        '</td><td>' + esc(a.memory_mb) + ' MB · ' + esc(a.cpu_percent) + '% CPU · port ' + esc(a.port) + '</td><td>' +
                        '<button class="ua-btn app-act" data-i="' + i + '" data-act="deploy">Deploy</button> ' +
                        (s.state === 'active' ? '<button class="ua-btn ua-btn-secondary app-act" data-i="' + i + '" data-act="restart">Restart</button> ' +
                            '<button class="ua-btn ua-btn-secondary app-act" data-i="' + i + '" data-act="stop">Stop</button> '
                            : '<button class="ua-btn ua-btn-secondary app-act" data-i="' + i + '" data-act="start">Start</button> ') +
                        '<button class="ua-btn ua-btn-secondary app-act" data-i="' + i + '" data-act="logs">Logs</button> ' +
                        '<button class="ua-btn ua-btn-secondary app-act" data-i="' + i + '" data-act="edit">Edit</button> ' +
                        '<button class="ua-btn app-act" style="background:#dc2626" data-i="' + i + '" data-act="delete">Delete</button></td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No apps yet. Create one below.</p>';
        }).catch(function (e) { UA.showError($('app-list'), e); });
    }

    function edit(a) {
        $('app-form-title').textContent = 'Edit ' + a.id;
        $('app-domain').value = a.domain; $('app-id').value = a.id; $('app-kind').value = a.flavor === 'kotlin' ? 'kotlin' : a.kind;
        $('app-runtime').value = '';
        fillRuntimes();
        $('app-runtime').value = a.runtime || ''; $('app-entry').value = a.entry; $('app-prefix').value = a.prefix;
        $('app-websocket').value = a.websocket || ''; $('app-memory').value = a.memory_mb; $('app-cpu').value = a.cpu_percent;
        if (a.kind === 'python') { $('app-mode').value = a.mode; $('app-workers').value = a.workers; }
        if (a.kind === 'java') {
            $('app-jmode').value = a.mode; $('app-jvm').value = (a.jvm_opts || []).join(' ');
            $('app-gradle').value = a.build || ''; $('app-ktor').checked = !!a.ktor_args;
        }
        if (a.kind === 'ruby') {
            $('app-rmode').value = a.mode; $('app-workers').value = a.workers;
            $('app-precompile').checked = a.precompile !== false; $('app-migrate').checked = a.migrate !== false;
        }
        if (a.kind === 'go') { $('app-gobuild').checked = !!a.build; $('app-gopkg').value = a.package || '.'; }
        if (a.kind === 'deno') { $('app-dmode').value = a.mode; $('app-dperms').value = a.deno_perms || 'scoped'; }
        fillRuntimes();
        $('app-env').value = '';
        $('app-env').placeholder = a.env_keys.length ? 'Current variables: ' + a.env_keys.join(', ') + ' (type all of them again to change)' : 'KEY=value';
        $('app-form-title').scrollIntoView({behavior: 'smooth'});
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('.app-act');
        if (!t) { return; }
        var a = state.apps[Number(t.dataset.i)], act = t.dataset.act, ref = {app: a.id, domain: a.domain};
        if (act === 'edit') { return edit(a); }
        if (act === 'deploy') {
            return api('deploy', ref).then(function (d) { watch(d.result.job_id, loadApps); }).catch(function (e) { UA.showError($('app-out'), e); });
        }
        if (act === 'logs') {
            return api('logs', ref).then(function (d) {
                $('app-job').style.display = 'block';
                $('app-job-out').innerHTML = '<p><strong>' + esc(a.id) + '</strong> journal</p><div class="ua-pre">' + esc(d.result.lines.join('\n')) + '</div>';
                $('app-job').scrollIntoView({behavior: 'smooth'});
            }).catch(function (e) { UA.showError($('app-out'), e); });
        }
        if (act === 'delete') {
            if (!window.confirm('Delete app ' + a.id + '? The service and URL routing are removed.')) { return; }
            var removeFiles = window.confirm('Also delete the app files in ' + a.dir + '? Cancel keeps them.');
            return api('delete', {app: a.id, domain: a.domain, removeFiles: removeFiles}).then(loadApps).catch(function (e) { UA.showError($('app-out'), e); });
        }
        UA.busy(t, true);
        api('control', {app: a.id, domain: a.domain, action: act}).then(loadApps)
            .catch(function (e) { UA.busy(t, false); UA.showError($('app-out'), e); });
    });

    function parseEnv(text) {
        var out = [];
        text.split('\n').forEach(function (line) {
            line = line.trim();
            if (!line || line.charAt(0) === '#') { return; }
            var i = line.indexOf('=');
            if (i > 0) { out.push({key: line.slice(0, i).trim(), value: line.slice(i + 1)}); }
        });
        return out;
    }

    $('app-save').addEventListener('click', function () {
        var button = this, choice = $('app-kind').value, kind = choice === 'kotlin' ? 'java' : choice;
        var body = {domain: $('app-domain').value, id: $('app-id').value.trim().toLowerCase(), kind: kind, runtime: $('app-runtime').value,
            entry: $('app-entry').value.trim() || $('app-entry').placeholder, prefix: $('app-prefix').value.trim() || '/',
            websocket: $('app-websocket').value.trim(), memory_mb: Number($('app-memory').value), cpu_percent: Number($('app-cpu').value)};
        if (kind === 'python') { body.mode = $('app-mode').value; body.workers = Number($('app-workers').value); }
        if (kind === 'java') {
            body.mode = $('app-jmode').value; body.jvm_opts = $('app-jvm').value.trim().split(/\s+/).filter(Boolean);
            body.flavor = choice === 'kotlin' ? 'kotlin' : 'java';
            body.build = body.mode === 'jar' ? $('app-gradle').value : '';
            body.ktor_args = choice === 'kotlin' && body.mode === 'jar' && $('app-ktor').checked;
        }
        if (kind === 'ruby') {
            body.mode = $('app-rmode').value; body.workers = Number($('app-workers').value);
            body.precompile = $('app-precompile').checked; body.migrate = $('app-migrate').checked;
        }
        if (kind === 'go') { body.build = $('app-gobuild').checked; body.package = $('app-gopkg').value.trim() || '.'; }
        if (kind === 'deno') { body.mode = $('app-dmode').value; body.deno_perms = $('app-dperms').value; }
        if ($('app-env').value.trim()) { body.env = parseEnv($('app-env').value); }
        UA.busy(button, true);
        api('save', body).then(function (d) {
            $('app-env').value = '';
            $('app-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Saved</span> ' + (d.result.created
                ? 'Upload your files to <code>' + esc(d.result.app.dir) + '</code> (File Manager or SFTP), then press Deploy.' : 'Press Deploy to apply the changes.') + '</p>';
            loadApps();
        }).catch(function (e) { UA.showError($('app-out'), e); }).then(function () { UA.busy(button, false); });
    });
    $('app-reset').addEventListener('click', function () {
        ['app-id', 'app-entry', 'app-websocket', 'app-env', 'app-jvm', 'app-gopkg'].forEach(function (id) { $(id).value = ''; });
        $('app-gradle').value = ''; $('app-ktor').checked = $('app-gobuild').checked = false;
        $('app-precompile').checked = $('app-migrate').checked = true;
        fillRuntimes();
        $('app-prefix').value = '/'; $('app-form-title').textContent = 'New app';
    });

    // ---- administrator: runtimes and policy
    function uninstallButton(attrs, usedBy, allowed, why) {
        var blocked = usedBy.length ? 'In use by: ' + usedBy.join(', ') : (allowed ? '' : why);
        return '<button class="ua-btn ua-btn-secondary rt-remove" ' + attrs + (blocked ? ' disabled title="' + esc(blocked) + '"' : '') +
            '>Uninstall</button>' + (blocked && usedBy.length ? '<div class="ua-fix">' + esc(blocked) + '</div>' : '');
    }

    function loadRuntimes() {
        return api('runtimes', {}).then(function (d) {
            var r = d.result, rows = [], total = 0;
            $('rt-disk').textContent = '(' + (r.disk_free_mb / 1024).toFixed(1) + ' GB free)';
            KINDS.forEach(function (kind) {
                (r.installed[kind] || []).forEach(function (e) {
                    var system = e.source === 'system', used = e.used_by || [];
                    if (!system) { total += e.size || 0; }
                    rows.push('<tr><td>' + esc(KIND_LABEL[kind]) + '</td><td><strong>' + esc(e.version) + '</strong>' + (e.jdk ? ' <span class="ua-badge ua-badge-info">JDK</span>' : '') +
                        '</td><td>' + esc(e.source) + (system && e.package ? '<div class="ua-fix">package ' + esc(e.package) + (e.panel_installed ? ' (installed by IndiansCloud)' : '') + '</div>' : '') +
                        '</td><td>' + esc(size(e.size)) + '</td><td>' + esc(used.join(', ')) + '</td><td>' +
                        uninstallButton('data-kind="' + esc(kind) + '" data-version="' + esc(e.version) + '"', used, e.removable || (!system && !used.length),
                            'Part of the operating system; IndiansCloud did not install it') + '</td></tr>');
                });
            });
            $('rt-installed').innerHTML = rows.length ? '<table class="ua-table"><thead><tr><th></th><th>Version</th><th>Source</th><th>Size on disk</th><th>Used by</th><th></th></tr></thead><tbody>' +
                rows.join('') + '</tbody></table><p class="ua-muted">Installed by IndiansCloud: ' + esc(size(total) || '0 MB') + ' in /opt/cp-runtimes.</p>' : '<p class="ua-muted">No runtimes installed yet.</p>';
            var packages = r.packages || [];
            $('rt-packages').innerHTML = packages.length ? '<table class="ua-table"><thead><tr><th>Package</th><th>Installed for</th><th>Size</th><th>Needed by</th><th></th></tr></thead><tbody>' +
                packages.map(function (p) {
                    return '<tr><td><strong>' + esc(p.name) + '</strong>' + (p.present ? '' : ' <span class="ua-muted">(already removed)</span>') + '</td><td>' + esc(p.reason) +
                        '</td><td>' + esc(size(p.size)) + '</td><td>' + esc((p.used_by || []).join(', ')) + '</td><td>' +
                        uninstallButton('data-package="' + esc(p.name) + '"', p.used_by || [], true, '') + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">None.</p>';
            Object.keys(r.policy).forEach(function (k) {
                var box = $('pol-' + k);
                if (!box) { return; }
                if (box.type === 'checkbox') { box.checked = r.policy[k]; } else { box.value = r.policy[k]; }
            });
        }).catch(function (e) { UA.showError($('rt-installed'), e); });
    }
    if (isAdmin) {
        $('rt-catalogue').addEventListener('click', function () {
            var button = this;
            UA.busy(button, true);
            api('runtimes', {catalogue: true}).then(function (d) {
                var c = d.result.catalogue, html = '';
                KINDS.forEach(function (kind) {
                    html += '<div class="ua-row"><strong style="min-width:70px">' + esc(KIND_LABEL[kind]) + '</strong>' + (c[kind] || []).map(function (e) {
                        var note = [e.estimate, e.warning].filter(Boolean).join(' ');
                        return '<button class="ua-btn ua-btn-secondary rt-install" data-kind="' + esc(kind) + '" data-version="' + esc(e.version) + '" data-variant="' +
                            esc(e.variant === 'jdk' ? 'jdk' : '') + '"' + (note ? ' title="' + esc(note) + '"' : '') + '>' + esc(e.label) + (e.warning ? ' (!)' : '') + '</button>';
                    }).join(' ') + (c.errors[kind] ? ' <span class="ua-muted">unavailable: ' + esc(c.errors[kind]) + '</span>' : '') + '</div>';
                });
                $('rt-available').innerHTML = html + '<p class="ua-muted">Downloads need roughly 50–250 MB each (a JDK or Go about 200 MB). Ruby is compiled here: about 10–20 minutes and 2 GB of free space while it builds; missing compilers/headers (gcc, make, openssl/zlib/libffi/libyaml -devel) are installed with dnf from the OS repositories and listed below so they can be removed again. A version that cannot run on this OS is removed again automatically.</p>';
            }).catch(function (e) { UA.showError($('rt-available'), e); }).then(function () { UA.busy(button, false); });
        });
        root.addEventListener('click', function (event) {
            var t = event.target.closest('.rt-install, .rt-remove');
            if (!t) { return; }
            if (t.classList.contains('rt-install')) {
                if (t.title && t.dataset.kind !== 'go' && !window.confirm(t.textContent + '\n\n' + t.title + '\n\nInstall?')) { return; }
                var body = {kind: t.dataset.kind, version: t.dataset.version};
                if (t.dataset.variant) { body.variant = t.dataset.variant; }
                api('runtime_install', body)
                    .then(function (d) { watch(d.result.job_id, function () { loadRuntimes(); loadApps(); }); })
                    .catch(function (e) { UA.showError($('rt-available'), e); });
            } else if (t.dataset.package) {
                if (!window.confirm('Uninstall the OS package ' + t.dataset.package + ' (rpm -e)?')) { return; }
                api('package_uninstall', {name: t.dataset.package}).then(loadRuntimes).catch(function (e) { UA.showError($('rt-packages'), e); });
            } else if (window.confirm('Uninstall ' + KIND_LABEL[t.dataset.kind] + ' ' + t.dataset.version + ' to free its disk space?')) {
                api('runtime_uninstall', {kind: t.dataset.kind, version: t.dataset.version}).then(function () { loadRuntimes(); loadApps(); })
                    .catch(function (e) { UA.showError($('rt-installed'), e); });
            }
        });
        $('pol-save').addEventListener('click', function () {
            var body = {};
            ['apps_for_users', 'mssql_for_users'].forEach(function (k) { body[k] = $('pol-' + k).checked; });
            ['max_apps_per_site', 'default_memory_mb', 'max_memory_mb', 'max_cpu_percent', 'max_mssql_dbs_per_site'].forEach(function (k) { body[k] = Number($('pol-' + k).value); });
            api('policy', body).then(function () { $('pol-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Saved</span></p>'; })
                .catch(function (e) { UA.showError($('pol-out'), e); });
        });
        loadRuntimes();
    }
    loadApps();
})();
