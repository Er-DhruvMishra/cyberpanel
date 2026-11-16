(function () {
    'use strict';
    var root = document.getElementById('ua-laravel');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1';
    var state = {list: null, app: null, info: null};

    function badge(kind, text) { return '<span class="ua-badge ua-badge-' + kind + '">' + esc(text) + '</span>'; }
    function target() { return {domain: state.app.domain, path: state.app.path}; }
    function body(extra) { var b = target(); Object.keys(extra || {}).forEach(function (k) { b[k] = extra[k]; }); return b; }

    root.querySelectorAll('#lv-app .ua-tabs button').forEach(function (tab) {
        tab.addEventListener('click', function () {
            root.querySelectorAll('#lv-app .ua-tabs button').forEach(function (b) { b.classList.remove('active'); });
            root.querySelectorAll('#lv-app .ua-pane').forEach(function (p) { p.classList.remove('active'); });
            tab.classList.add('active');
            $('lv-pane-' + tab.dataset.pane).classList.add('active');
            if (tab.dataset.pane === 'env') { loadEnv(); }
            if (tab.dataset.pane === 'logs') { loadLogs(); }
        });
    });

    function watch(jobId, after) {
        $('lv-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('lv-job-out').innerHTML = '<p>' + esc(j.step || '') + ' ' + badge(j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail'), j.state) + '</p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-150).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (after) { after(j); }
            }).catch(function (e) { UA.showError($('lv-job-out'), e); });
        })();
        $('lv-job').scrollIntoView({behavior: 'smooth'});
    }
    function startJob(name, payload, after) {
        return api(name, payload).then(function (d) { watch(d.result.job_id, after); })
            .catch(function (e) { $('lv-job').style.display = 'block'; UA.showError($('lv-job-out'), e); });
    }

    function renderList() {
        var r = state.list, filter = $('lv-filter').value;
        var apps = r.apps.filter(function (a) { return !filter || a.domain === filter; });
        $('lv-apps').innerHTML = apps.length ? '<table class="ua-table"><thead><tr><th>Site</th><th>Directory</th><th>Laravel</th><th></th></tr></thead><tbody>' +
            apps.map(function (a, i) {
                return '<tr><td><strong>' + esc(a.domain) + '</strong></td><td>' + esc(a.path || '(document root)') + '</td><td>' +
                    esc(a.laravel || (a.constraint + ' (not installed: run composer install)')) +
                    '</td><td><button class="ua-btn ua-btn-secondary lv-open" data-i="' + r.apps.indexOf(a) + '">Manage</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No Laravel apps found (an app has artisan and a composer.json that requires laravel/framework).</p>';
    }

    function loadList() {
        return api('apps', {}).then(function (d) {
            var r = d.result;
            state.list = r;
            var options = r.sites.map(function (s) { return '<option value="' + esc(s) + '">' + esc(s) + '</option>'; }).join('');
            $('lv-filter').innerHTML = '<option value="">all my sites</option>' + options;
            $('lv-new-site').innerHTML = options;
            if (root.dataset.site && r.sites.indexOf(root.dataset.site) >= 0) {
                $('lv-filter').value = root.dataset.site;
                $('lv-new-site').value = root.dataset.site;
            }
            renderList();
            if (isAdmin) {
                $('lv-composer-card').style.display = 'block';
                $('lv-composer').innerHTML = r.composer ? '<p>Installed at <code>' + esc(r.composer) + '</code>.</p>' :
                    '<p>Composer is not installed. <button class="ua-btn" id="lv-composer-install">Install Composer to /usr/local/bin/composer</button></p>' +
                    '<p class="ua-muted">Downloads the official installer and installs it only if its SHA-384 matches composer.github.io/installer.sig.</p>';
            } else if (!r.composer) {
                $('lv-composer-card').style.display = 'block';
                $('lv-composer').innerHTML = '<p class="ua-muted">Composer is not installed on this server; ask your administrator to install it.</p>';
            }
            var mine = r.apps.filter(function (a) { return a.domain === root.dataset.site; });
            if (mine.length === 1 && !state.app) { openApp(mine[0]); }
        }).catch(function (e) { UA.showError($('lv-apps'), e); });
    }

    function renderInfo(i) {
        state.info = i;
        $('lv-app-title').textContent = i.domain + (i.path ? ' / ' + i.path : '') + ' — Laravel ' + (i.laravel || '?');
        var rows = [
            ['Laravel', i.laravel || ('not installed (' + (i.constraint || '') + ')')],
            ['PHP', (i.php_version || '?') + ' (' + i.php + ')'],
            ['APP_ENV', i.app_env || '(not set)'],
            ['APP_DEBUG', i.app_debug ? 'true' : 'false'],
            ['Maintenance mode', i.maintenance ? 'on (php artisan down)' : 'off'],
            ['Web root', i.public === 'vhost' ? 'public/ is the document root' : (i.public === 'htaccess' ? 'public/ through the .htaccess rewrite' : 'not pointed at public/')]
        ];
        $('lv-overview').innerHTML = (i.warnings || []).map(function (w) { return '<div class="ua-alert" style="margin-bottom:8px">' + esc(w) + '</div>'; }).join('') +
            '<table class="ua-table"><tbody>' + rows.map(function (r) { return '<tr><td>' + esc(r[0]) + '</td><td>' + esc(r[1]) + '</td></tr>'; }).join('') + '</tbody></table>' +
            '<p class="ua-muted">' + esc(i.dir) + '</p>';
        var w = i.worker || {};
        $('lv-background').innerHTML = '<table class="ua-table"><tbody>' +
            '<tr><td>Scheduler (cron: * * * * * php artisan schedule:run)</td><td>' + badge(i.scheduler ? 'pass' : 'info', i.scheduler ? 'on' : 'off') +
            '</td><td><button class="ua-btn ua-btn-secondary" id="lv-sched" data-enable="' + (i.scheduler ? '0' : '1') + '">' + (i.scheduler ? 'Turn off' : 'Turn on') + '</button></td></tr>' +
            '<tr><td>Queue worker (systemd, php artisan queue:work)</td><td>' + badge(w.enabled ? (w.unit && w.unit.state === 'active' ? 'pass' : 'warn') : 'info',
                w.enabled ? (w.unit ? w.unit.state : 'enabled') + (w.memory_mb ? ', ' + w.memory_mb + ' MB limit' : '') : 'off') +
            '</td><td><button class="ua-btn ua-btn-secondary" id="lv-worker" data-enable="' + (w.enabled ? '0' : '1') + '">' + (w.enabled ? 'Stop and remove' : 'Start') + '</button> ' +
            (w.enabled ? '<button class="ua-btn ua-btn-secondary" id="lv-worker-apply">Apply memory/queues</button> <button class="ua-btn ua-btn-secondary" id="lv-worker-logs">Worker log</button>' : '') + '</td></tr>' +
            '</tbody></table>';
        if (w.memory_mb) { $('lv-memory').value = w.memory_mb; }
        if (w.queue) { $('lv-queue').value = w.queue; }
    }

    function renderCommands() {
        var c = state.list.commands;
        function buttons(tool) {
            return c[tool].map(function (cmd) {
                return '<button class="ua-btn ua-btn-secondary lv-cmd" data-tool="' + tool + '" data-name="' + esc(cmd.name) + '" data-confirm="' + (cmd.confirm ? '1' : '0') + '">' +
                    esc(cmd.name) + (cmd.confirm ? ' *' : '') + '</button>';
            }).join('');
        }
        $('lv-artisan').innerHTML = buttons('artisan');
        $('lv-composer-cmds').innerHTML = buttons('composer');
    }

    function openApp(app) {
        state.app = app;
        $('lv-app').style.display = 'block';
        $('lv-app-title').textContent = app.domain + ' — loading…';
        $('lv-env').innerHTML = '';
        $('lv-logs').textContent = '';
        renderCommands();
        return refresh();
    }
    function refresh() {
        return api('info', target()).then(function (d) { renderInfo(d.result); })
            .catch(function (e) { UA.showError($('lv-overview'), e); });
    }

    function loadEnv() {
        $('lv-env').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('env', target()).then(function (d) {
            var r = d.result;
            if (!r.exists) { $('lv-env').innerHTML = '<p class="ua-muted">There is no .env file. Copy .env.example to .env in the File Manager first.</p>'; return; }
            $('lv-env').innerHTML = '<table class="ua-table"><thead><tr><th>Key</th><th>Value</th><th></th></tr></thead><tbody>' + r.entries.map(function (e) {
                return '<tr><td><code>' + esc(e.key) + '</code></td><td>' + (e.masked ? '<span class="ua-muted">' + (e.set ? '•••••• (hidden)' : '(empty)') + '</span>' : esc(e.value)) +
                    '</td><td><button class="ua-btn ua-btn-secondary lv-env-edit" data-key="' + esc(e.key) + '" data-value="' + (e.masked ? '' : esc(e.value)) + '">Edit</button></td></tr>';
            }).join('') + '</tbody></table>' + (r.backups && r.backups.length ? '<p class="ua-muted">Latest backup: ' + esc(r.backups[0]) + '</p>' : '');
        }).catch(function (e) { UA.showError($('lv-env'), e); });
    }

    function loadLogs() {
        $('lv-logs').textContent = 'Loading…';
        api('logs', target()).then(function (d) {
            $('lv-logs-file').textContent = d.result.file || 'no log file yet';
            $('lv-logs').textContent = (d.result.lines || []).join('\n') || '(empty)';
        }).catch(function (e) { UA.showError($('lv-logs'), e); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('button');
        if (!t) { return; }
        if (t.classList.contains('lv-open')) { openApp(state.list.apps[+t.dataset.i]); return; }
        if (t.classList.contains('lv-cmd')) {
            var tool = t.dataset.tool, name = t.dataset.name, options = {};
            if (t.dataset.confirm === '1' && !window.confirm('Run ' + tool + ' ' + name + ' on ' + state.app.domain + '? This changes the live app.')) { return; }
            if (name === 'migrate' && $('lv-seed').checked) { options.seed = true; }
            if (name === 'down' && $('lv-down-secret').value.trim()) { options.secret = $('lv-down-secret').value.trim(); }
            if (tool === 'composer' && name === 'dump-autoload') { options.optimize = true; }
            startJob('command', body({command: {tool: tool, name: name, options: options, confirmed: t.dataset.confirm === '1'}}), function () { refresh(); });
            return;
        }
        if (t.dataset.public) {
            var undo = t.dataset.public === 'undo';
            if (!undo && !window.confirm('Serve public/ for this app? The site\'s web root changes.')) { return; }
            UA.busy(t, true);
            api('public', body(undo ? {undo: true} : {method: t.dataset.public})).then(function (d) {
                $('lv-public-out').textContent = d.result.detail || (d.result.done || []).join('; ');
                refresh();
            }).catch(function (e) { UA.showError($('lv-public-out'), e); }).then(function () { UA.busy(t, false); });
            return;
        }
        if (t.id === 'lv-sched') {
            UA.busy(t, true);
            api('scheduler', body({enable: t.dataset.enable === '1'})).then(refresh).catch(function (e) { UA.showError($('lv-background'), e); });
            return;
        }
        if (t.id === 'lv-worker' || t.id === 'lv-worker-apply') {
            var enable = t.id === 'lv-worker-apply' || t.dataset.enable === '1';
            UA.busy(t, true);
            api('worker', body({enable: enable, memory_mb: parseInt($('lv-memory').value, 10) || 256, queue: $('lv-queue').value.trim() || 'default'}))
                .then(refresh).catch(function (e) { UA.showError($('lv-background'), e); });
            return;
        }
        if (t.id === 'lv-worker-logs') {
            api('worker_logs', target()).then(function (d) {
                $('lv-worker-log').style.display = 'block';
                $('lv-worker-log').textContent = d.result.lines.join('\n') || '(empty)';
            }).catch(function (e) { UA.showError($('lv-worker-log'), e); });
            return;
        }
        if (t.classList.contains('lv-env-edit')) {
            $('lv-env-key').value = t.dataset.key;
            $('lv-env-value').value = t.dataset.value;
            $('lv-env-value').focus();
            return;
        }
        if (t.id === 'lv-env-save') {
            var key = $('lv-env-key').value.trim().toUpperCase();
            UA.busy(t, true);
            api('env_set', body({entry: {key: key, value: $('lv-env-value').value}})).then(function (d) {
                $('lv-env-out').textContent = d.result.changed ? 'Saved (backup ' + d.result.backup + '). ' + (d.result.note || '') : 'No change.';
                $('lv-env-value').value = '';
                loadEnv();
                refresh();
            }).catch(function (e) { UA.showError($('lv-env-out'), e); }).then(function () { UA.busy(t, false); });
            return;
        }
        if (t.id === 'lv-logs-refresh') { loadLogs(); return; }
        if (t.id === 'lv-new-install') {
            var site = $('lv-new-site').value;
            if (!site || !window.confirm('Install Laravel on ' + site + '? The directory must be empty.')) { return; }
            startJob('install', {domain: site, path: $('lv-new-path').value.trim(), version: $('lv-new-version').value, point: $('lv-new-point').value}, function () { loadList(); });
            return;
        }
        if (t.id === 'lv-composer-install') {
            if (!window.confirm('Download and install Composer to /usr/local/bin/composer?')) { return; }
            startJob('composer', {}, function () { loadList(); });
        }
    });
    $('lv-filter').addEventListener('change', renderList);

    loadList();
})();
