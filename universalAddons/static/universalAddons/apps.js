(function () {
    'use strict';
    var root = document.getElementById('ua-apps');
    if (!root || !document.getElementById('app-list')) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1';
    var state = {runtimes: {node: [], python: [], dotnet: [], java: []}, apps: []};
    var HINT = {
        node: 'Upload your app into the app directory (it is created as ~/apps/<name>). Entry: the file to run (server.js) or "npm-start". Dependencies are installed with npm ci --omit=dev. Listen on process.env.PORT.',
        python: 'WSGI: module:callable (e.g. myproject.wsgi:application). ASGI: module:app (e.g. main:app). requirements.txt is installed into a private virtualenv.',
        dotnet: 'Upload the output of "dotnet publish -c Release" and name the .dll. The app listens on ASPNETCORE_URLS automatically.',
        jar: 'Upload the built .jar and name it. Spring Boot jars pick up SERVER_PORT and the context path (URL path) automatically; other apps listen on the PORT variable, on 127.0.0.1. The heap is 3/4 of the memory limit; Spring Boot usually needs 512 MB or more.',
        war: 'Upload the .war and name it. WARs run on embedded Tomcat 9 (javax.servlet); Jakarta EE 9+ WARs (jakarta.servlet) need Tomcat 10+ and will not start. The URL path becomes the context path.'
    };
    var PLACEHOLDER = {node: 'server.js', python: 'app:app', dotnet: 'MyApp.dll', jar: 'app.jar', war: 'app.war'};

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
        var kind = $('app-kind').value;
        $('app-runtime').innerHTML = (state.runtimes[kind] || []).map(function (v) { return '<option>' + esc(v) + '</option>'; }).join('') ||
            '<option value="">(no ' + esc(kind) + ' runtime installed)</option>';
        var java = kind === 'java', key = java ? $('app-jmode').value : kind;
        $('app-mode').style.display = kind === 'python' ? '' : 'none';
        $('app-jmode').style.display = $('app-jvm-row').style.display = java ? '' : 'none';
        $('app-workers').style.display = kind === 'python' && $('app-mode').value !== 'script' ? '' : 'none';
        $('app-entry').placeholder = kind === 'python' && $('app-mode').value === 'script' ? 'main.py' : PLACEHOLDER[key];
        $('app-hint').textContent = HINT[key];
    }
    $('app-kind').addEventListener('change', function () {
        if ($('app-kind').value === 'java' && Number($('app-memory').value) === 256) { $('app-memory').value = 512; }
        fillRuntimes();
    });
    $('app-mode').addEventListener('change', fillRuntimes);
    $('app-jmode').addEventListener('change', fillRuntimes);

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
                        (a.websocket ? '<div class="ua-fix">ws: ' + esc(a.websocket) + '</div>' : '') + '</td><td>' + esc(a.kind) + ' ' + esc(a.runtime) +
                        (a.kind === 'python' || a.kind === 'java' ? '<div class="ua-fix">' + esc(a.mode) + ' ' + esc(a.entry) + '</div>' : '<div class="ua-fix">' + esc(a.entry) + '</div>') + '</td><td>' +
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
        $('app-domain').value = a.domain; $('app-id').value = a.id; $('app-kind').value = a.kind;
        fillRuntimes();
        $('app-runtime').value = a.runtime; $('app-entry').value = a.entry; $('app-prefix').value = a.prefix;
        $('app-websocket').value = a.websocket || ''; $('app-memory').value = a.memory_mb; $('app-cpu').value = a.cpu_percent;
        if (a.kind === 'python') { $('app-mode').value = a.mode; $('app-workers').value = a.workers; fillRuntimes(); }
        if (a.kind === 'java') { $('app-jmode').value = a.mode; $('app-jvm').value = (a.jvm_opts || []).join(' '); fillRuntimes(); }
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
        var button = this, kind = $('app-kind').value;
        var body = {domain: $('app-domain').value, id: $('app-id').value.trim().toLowerCase(), kind: kind, runtime: $('app-runtime').value,
            entry: $('app-entry').value.trim() || $('app-entry').placeholder, prefix: $('app-prefix').value.trim() || '/',
            websocket: $('app-websocket').value.trim(), memory_mb: Number($('app-memory').value), cpu_percent: Number($('app-cpu').value)};
        if (kind === 'python') { body.mode = $('app-mode').value; body.workers = Number($('app-workers').value); }
        if (kind === 'java') { body.mode = $('app-jmode').value; body.jvm_opts = $('app-jvm').value.trim().split(/\s+/).filter(Boolean); }
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
        ['app-id', 'app-entry', 'app-websocket', 'app-env', 'app-jvm'].forEach(function (id) { $(id).value = ''; });
        $('app-prefix').value = '/'; $('app-form-title').textContent = 'New app';
    });

    // ---- administrator: runtimes and policy
    function loadRuntimes() {
        return api('runtimes', {}).then(function (d) {
            var r = d.result, rows = [];
            $('rt-disk').textContent = '(' + (r.disk_free_mb / 1024).toFixed(1) + ' GB free)';
            ['node', 'python', 'dotnet', 'java'].forEach(function (kind) {
                (r.installed[kind] || []).forEach(function (e) {
                    rows.push('<tr><td>' + esc(kind) + '</td><td><strong>' + esc(e.version) + '</strong></td><td>' + esc(e.source) + '</td><td>' + esc(size(e.size)) +
                        '</td><td>' + esc((e.used_by || []).join(', ')) + '</td><td>' + (e.source === 'system' ? '' :
                        '<button class="ua-btn ua-btn-secondary rt-remove" data-kind="' + esc(kind) + '" data-version="' + esc(e.version) + '"' +
                        ((e.used_by || []).length ? ' disabled title="in use"' : '') + '>Remove</button>') + '</td></tr>');
                });
            });
            $('rt-installed').innerHTML = rows.length ? '<table class="ua-table"><thead><tr><th></th><th>Version</th><th>Source</th><th>Size</th><th>Used by</th><th></th></tr></thead><tbody>' +
                rows.join('') + '</tbody></table>' : '<p class="ua-muted">No runtimes installed yet.</p>';
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
                ['node', 'python', 'dotnet', 'java'].forEach(function (kind) {
                    html += '<div class="ua-row"><strong style="min-width:70px">' + esc(kind) + '</strong>' + (c[kind] || []).map(function (e) {
                        return '<button class="ua-btn ua-btn-secondary rt-install" data-kind="' + esc(kind) + '" data-version="' + esc(e.version) + '">' + esc(e.label) + '</button>';
                    }).join(' ') + (c.errors[kind] ? ' <span class="ua-muted">unavailable: ' + esc(c.errors[kind]) + '</span>' : '') + '</div>';
                });
                $('rt-available').innerHTML = html + '<p class="ua-muted">Each install needs roughly 100–150 MB. A version that cannot run on this OS is removed again automatically.</p>';
            }).catch(function (e) { UA.showError($('rt-available'), e); }).then(function () { UA.busy(button, false); });
        });
        root.addEventListener('click', function (event) {
            var t = event.target.closest('.rt-install, .rt-remove');
            if (!t) { return; }
            if (t.classList.contains('rt-install')) {
                api('runtime_install', {kind: t.dataset.kind, version: t.dataset.version})
                    .then(function (d) { watch(d.result.job_id, function () { loadRuntimes(); loadApps(); }); })
                    .catch(function (e) { UA.showError($('rt-available'), e); });
            } else if (window.confirm('Remove ' + t.dataset.kind + ' ' + t.dataset.version + '?')) {
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
