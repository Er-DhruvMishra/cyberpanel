(function () {
    'use strict';
    var root = document.getElementById('ua-appsvc');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var apps = {}, previews = {};

    function pane(key) { return $('as-pane-' + key); }
    function q(key, sel) { return pane(key).querySelector(sel); }
    function show(key, sel, on) { var el = q(key, sel); if (el) { el.style.display = on ? 'block' : 'none'; } }
    function html(key, sel, text) { var el = q(key, sel); if (el) { el.innerHTML = text; } }

    function badge(kind, text) { return '<span class="ua-badge ua-badge-' + kind + '">' + esc(text) + '</span>'; }

    function size(bytes) {
        if (bytes === null || bytes === undefined) { return 'unknown'; }
        var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0, n = bytes;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
        return (i ? n.toFixed(1) : n) + ' ' + units[i];
    }

    function table(rows) {
        return '<table class="ua-table"><tbody>' + rows.map(function (r) {
            return '<tr><td style="width:220px">' + r[0] + '</td><td>' + r[1] + '</td></tr>';
        }).join('') + '</tbody></table>';
    }

    function checks(list) {
        return table(list.map(function (c) { return [badge(c.ok ? 'pass' : (c.hard ? 'fail' : 'warn'), c.ok ? 'OK' : 'No'), esc(c.detail)]; }));
    }

    function warn(text) { return '<div class="ua-alert" style="background:#fef3c7;color:#92400e;margin-top:6px">' + esc(text) + '</div>'; }

    function renderHost(d) {
        $('as-host').innerHTML = '<p>RAM ' + esc(d.ram_mb) + ' MB (' + esc(d.ram_available_mb) + ' MB available) · ' +
            esc(d.disk_free_mb) + ' MB free under /var/lib</p>';
        var b = d.budget || {}, caps = b.caps || {};
        var parts = Object.keys(caps).map(function (k) { return esc(k) + ' ' + esc(caps[k]) + ' MB'; });
        $('as-budget').innerHTML = '<p class="ua-muted">Memory caps: ' + (parts.length ? parts.join(', ') : 'none') +
            ' = ' + esc(b.total_mb || 0) + ' MB of the ' + esc(b.limit_mb || 0) + ' MB budget (70% of RAM).</p>' +
            (b.warning ? warn(b.warning) : '');
        var oracle = $('as-skipped-oracle_db');
        if (oracle && d.oracle_db) {
            oracle.querySelector('.as-skipped-checks').innerHTML = '<h3>Checks on this server</h3>' + checks(d.oracle_db.checks);
        }
    }

    function fieldHtml(f, value, key) {
        var id = 'as-f-' + key + '-' + f.name, input;
        if (f.type === 'bool') {
            input = '<input type="checkbox" data-name="' + esc(f.name) + '"' + (value === true ? ' checked' : '') + '>';
            return '<p><label>' + input + ' ' + esc(f.label) + '</label>' + (f.help ? '<span class="ua-fix">' + esc(f.help) + '</span>' : '') + '</p>';
        }
        if (f.type === 'select') {
            input = '<select id="' + id + '" data-name="' + esc(f.name) + '">' + f.options.map(function (o) {
                return '<option value="' + esc(o) + '"' + (String(value) === o ? ' selected' : '') + '>' + esc(o) + '</option>';
            }).join('') + '</select>';
        } else {
            var shown = f.type === 'list' ? (value || []).join(' ') : (value === null || value === undefined ? '' : value);
            input = '<input id="' + id + '" type="' + (f.type === 'number' ? 'number' : 'text') + '" data-name="' + esc(f.name) +
                '" data-type="' + esc(f.type) + '"' + (f.step ? ' step="' + esc(f.step) + '"' : '') + ' value="' + esc(shown) + '">';
        }
        return '<div class="ua-row"><label style="min-width:300px" for="' + id + '">' + esc(f.label) + '</label>' + input +
            (f.help ? '<span class="ua-fix">' + esc(f.help) + '</span>' : '') + '</div>';
    }

    function collect(key) {
        var settings = {};
        Array.prototype.forEach.call(q(key, '.as-form').querySelectorAll('[data-name]'), function (el) {
            var name = el.dataset.name;
            if (el.type === 'checkbox') { settings[name] = el.checked; return; }
            if (el.dataset.type === 'list') { settings[name] = el.value.trim().split(/[\s,]+/).filter(Boolean); return; }
            if (el.dataset.type === 'number') { settings[name] = el.value.trim() === '' ? '' : Number(el.value); return; }
            settings[name] = el.value.trim();
        });
        return settings;
    }

    function renderNotInstalled(a) {
        html(a.key, '.as-status', '<p>' + badge('info', 'not installed') + '</p>');
        html(a.key, '.as-preflight', checks(a.preflight || []));
        ['.as-controls', '.as-config', '.as-connect', '.as-logs-card', '.as-remove', '.as-pgdb', '.as-s3', '.as-s3-endpoint'].forEach(function (s) { show(a.key, s, false); });
        show(a.key, '.as-install', a.kind !== 'status');
        html(a.key, '.as-secret', '');
    }

    function renderApp(a) {
        apps[a.key] = a;
        var p = pane(a.key);
        html(a.key, '.as-msg', '');
        if (!a.installed) { renderNotInstalled(a); return; }
        show(a.key, '.as-install', false);
        var running = a.active === 'active', s = a.settings || {};
        var rows = [['Version', esc(a.version) + (a.major ? ' (PostgreSQL ' + esc(a.major) + ')' : '')],
                    ['Packages on disk', esc(size(a.package_bytes))]];
        if (a.kind === 'client') {
            rows.push(['SQL*Plus', a.sqlplus ? esc(a.sqlplus) : badge('warn', 'not found')]);
        } else {
            rows.push(['Service', esc(a.unit) + ' ' + badge(running ? 'pass' : 'fail', a.active) + ' ' + esc(a.sub) +
                       (a.busy ? ' ' + badge('info', 'change in progress') : '')]);
            rows.push(['Enabled at boot', badge(a.enabled === 'enabled' ? 'pass' : 'warn', a.enabled)]);
        }
        if (a.kind === 'service' || a.kind === 'bridge') {
            rows.push(['Memory', running ? esc(size(a.memory_bytes)) + (a.memory_source ? ' <span class="ua-muted">(' + esc(a.memory_source) + ')</span>' : '') : '–']);
            rows.push(['Listening', (a.listen || []).length ? (a.listen || []).map(function (l) {
                var loop = /^(127\.|\[::1\]|::1|\[::ffff:127\.)/.test(l);
                return badge(loop ? 'pass' : 'warn', loop ? 'local' : 'network') + ' ' + esc(l);
            }).join('<br>') : '–']);
            rows.push(['Data directory', a.data_dir ? esc(a.data_dir) + ' (' + esc(size(a.data_bytes)) + ')' : 'none (in memory only)']);
            if (a.password) {
                rows.push(['Password', a.password.set ? badge('pass', 'set') + (a.password.by_panel ? ' generated by the panel' : ' set outside the panel') : badge('warn', 'none')]);
            }
            rows.push(['Saved configurations', esc(a.backups) + ' (for revert)']);
        }
        if (a.key === 'mssql') {
            rows.push(['Memory cap', s.memory_limit_mb ? esc(s.memory_limit_mb) + ' MB' : 'not recorded']);
            rows.push(['max server memory in use', s.max_server_memory_mb ? esc(s.max_server_memory_mb) + ' MB' : '–']);
        }
        if (a.conflicts && a.conflicts.length) {
            rows.push(['Set outside the panel', esc(a.conflicts.join(', ')) + ' <span class="ua-muted">(the panel will not manage these until they are removed from elasticsearch.yml)</span>']);
        }
        html(a.key, '.as-status', table(rows));
        if (q(a.key, '.as-controls')) { q(a.key, '.as-controls').style.display = ''; }
        ['.as-config', '.as-connect', '.as-logs-card', '.as-remove', '.as-pgdb', '.as-s3', '.as-s3-endpoint'].forEach(function (sel) { show(a.key, sel, true); });

        if (a.password) {
            html(a.key, '.as-secret', a.password.reveal_pending ?
                '<div class="ua-card" style="background:#fef3c7"><p><strong>A generated password is ready.</strong> It can be shown only once.</p>' +
                '<button class="ua-btn as-reveal">Show the password once</button><div class="as-reveal-out"></div></div>' : '');
        }
        if (q(a.key, '.as-form')) {
            var note = a.config_problem ? '<div class="ua-alert">' + esc(a.config_problem) + '</div>' :
                (a.key === 'elasticsearch' ? 'Heap between ' + esc(a.heap_bounds[0]) + ' and ' + esc(a.heap_bounds[1]) + ' MB on this server. ' : '') +
                (a.key === 'mssql' && a.memory_bounds ? 'Cap between ' + esc(a.memory_bounds[0]) + ' and ' + esc(a.memory_bounds[1]) + ' MB on this server. ' : '') +
                (a.key === 's3' && a.memory_bounds ? 'Memory cap between ' + esc(a.memory_bounds[0]) + ' and ' + esc(a.memory_bounds[1]) + ' MB on this server. ' +
                    (a.endpoint ? 'HTTPS endpoint: ' + esc(a.endpoint) + '. ' : 'Listening beyond 127.0.0.1 needs the HTTPS endpoint first. ') : '') +
                (s.managed ? 'Managed by the panel.' : 'Not yet managed by the panel: the values shown are the current ones.');
            html(a.key, '.as-config-note', note);
            html(a.key, '.as-form', a.fields.map(function (f) { return fieldHtml(f, f.transient ? false : s[f.name], a.key); }).join(''));
            q(a.key, '.as-revert').style.display = a.backups ? '' : 'none';
        }
        if (a.key === 's3') { renderS3(a); }
        if (a.key === 'postgresql') {
            var dbs = a.databases;
            html(a.key, '.as-pgdb-list', dbs ? table(dbs.map(function (d) { return [esc(d.name), 'owner ' + esc(d.owner) + ' · ' + esc(size(d.bytes))]; })) :
                '<p class="ua-muted">Start PostgreSQL to list its databases.</p>');
        }
        var c = a.connection || {};
        if (q(a.key, '.as-connect-body')) {
            var info = [['Host', esc(c.host)], ['Port', esc(c.port)]];
            if (c.socket) { info.push(['Unix socket', esc(c.socket)]); }
            if (c.url) { info.push(['URL', esc(c.url)]); }
            if (c.region) { info.push(['Region', esc(c.region)]); }
            if (c.style) { info.push(['Addressing', esc(c.style)]); }
            info.push(['Authentication', esc(c.auth)]);
            var hint = c.backup ? '<div class="ua-alert" style="background:#e0f2fe;color:#075985;margin-top:6px">Use as backup destination: ' +
                '<a href="' + esc(c.backup.link) + '">Backup destinations</a> &rarr; S3-compatible &rarr; ' + esc(c.backup.preset) +
                ', endpoint ' + esc(c.backup.endpoint) + ', region ' + esc(c.backup.region) + (c.backup.use_http ? ', tick "Use plain http"' : '') +
                ', with an access key from above that may write to the bucket.</div>' : '';
            html(a.key, '.as-connect-body', table(info) + (c.note ? '<p class="ua-muted">' + esc(c.note) + '</p>' : '') + hint +
                (c.examples || []).map(function (e) { return '<h3>' + esc(e.title) + '</h3><div class="ua-pre">' + esc(e.code) + '</div>'; }).join(''));
        }
        if (p.dataset.logsShown) { loadLogs(a.key); }
    }

    function renderS3(a) {
        var inv = a.inventory, endpoint = a.endpoint;
        html('s3', '.as-s3-endpoint-now', endpoint ? '<p>' + badge('pass', 'active') + ' https://' + esc(endpoint) + '/</p>' :
            '<p>' + badge('info', 'none') + ' Local only (127.0.0.1).</p>');
        if (!inv) {
            html('s3', '.as-s3-buckets', a.inventory_error ? '<div class="ua-alert">' + esc(a.inventory_error) + '</div>' :
                '<p class="ua-muted">Start S3 Object Storage to manage buckets and keys.</p>');
            html('s3', '.as-s3-keys', '');
            return;
        }
        var perm = function (p) { return ['read', 'write', 'owner'].filter(function (k) { return p && p[k]; }).join('+') || 'none'; };
        html('s3', '.as-s3-buckets', inv.buckets.length ? table(inv.buckets.map(function (b) {
            var q = b.quotas || {};
            return ['<strong>' + esc(b.name) + '</strong>', esc(size(b.bytes)) + ' · ' + esc(b.objects) + ' objects · quota ' +
                (q.maxSize ? esc(size(q.maxSize)) : 'none') + (q.maxObjects ? ', ' + esc(q.maxObjects) + ' objects' : '') +
                '<br>' + (b.keys.length ? b.keys.map(function (k) { return esc(k.name || k.id) + ': ' + esc(perm(k.permissions)); }).join(', ') : '<span class="ua-muted">no keys</span>') +
                ' <button class="ua-btn ua-btn-secondary as-s3-bucket-quota" data-bucket="' + esc(b.name) + '">Set quota</button>' +
                ' <button class="ua-btn ua-btn-secondary as-s3-bucket-delete" data-bucket="' + esc(b.name) + '">Delete</button>'];
        })) : '<p class="ua-muted">No buckets yet.</p>');
        html('s3', '.as-s3-keys', inv.keys.length ? table(inv.keys.map(function (k) {
            return [esc(k.name), '<code>' + esc(k.id) + '</code>' + (k.expired ? ' ' + badge('warn', 'expired') : '') +
                ' <button class="ua-btn ua-btn-secondary as-s3-key-delete" data-key="' + esc(k.id) + '">Delete</button>'];
        })) : '<p class="ua-muted">No access keys yet.</p>');
        q('s3', '.as-s3-perm-bucket').innerHTML = inv.buckets.map(function (b) { return '<option>' + esc(b.name) + '</option>'; }).join('');
        q('s3', '.as-s3-perm-key').innerHTML = inv.keys.map(function (k) { return '<option value="' + esc(k.id) + '">' + esc(k.name) + ' (' + esc(k.id) + ')</option>'; }).join('');
    }

    function s3call(t, name, body, done) {
        UA.busy(t, true);
        return api(name, body).then(function (d) { if (done) { done(d.result || {}); } load(); })
            .catch(function (e) { UA.showError(q('s3', '.as-s3-out'), e); }).then(function () { UA.busy(t, false); });
    }

    function load() {
        return UA.retry(function () { return api('overview', {}); }).then(function (d) {
            renderHost(d.result);
            d.result.apps.forEach(renderApp);
        }).catch(function (e) { UA.showError($('as-out'), e); });
    }

    function loadLogs(key) {
        pane(key).dataset.logsShown = '1';
        UA.retry(function () { return api('logs', {app: key}); }).then(function (d) {
            q(key, '.as-logs').innerHTML = '<div class="ua-pre">' + esc(d.result.lines.join('\n') || '(empty)') + '</div>';
        }).catch(function (e) { UA.showError(q(key, '.as-logs'), e); });
    }

    function loadRuntimes() {
        UA.retry(function () { return api('runtimes', {}); }).then(function (d) {
            var r = d.result;
            if (r.error) { $('as-runtimes-body').innerHTML = '<div class="ua-alert">' + esc(r.error) + '</div>'; return; }
            $('as-runtimes-body').innerHTML = table(r.kinds.map(function (k) {
                return [esc({dotnet: '.NET', node: 'Node.js', java: 'Java', python: 'Python'}[k.kind] || k.kind),
                        (k.versions.length ? esc(k.versions.join(', ')) : '<span class="ua-muted">none</span>') +
                        (k.bytes ? ' · ' + esc(size(k.bytes)) : '') + (k.sources.length ? ' <span class="ua-muted">(' + esc(k.sources.join(', ')) + ')</span>' : '')];
            })) + '<p class="ua-muted">' + esc(r.root) + ' in total: ' + esc(size(r.bytes)) + '</p>';
        }).catch(function (e) { UA.showError($('as-runtimes-body'), e); });
    }

    function loadDisk(button) {
        UA.busy(button, true);
        api('disk', {}).then(function (d) {
            var r = d.result, rows = [];
            r.apps.forEach(function (a) {
                var logs = a.logs.map(function (l) { return esc(l.path) + ' ' + esc(size(l.bytes)); }).join(', ');
                rows.push(['<strong>' + esc(a.title) + '</strong>', 'packages ' + esc(size(a.package_bytes)) +
                    (a.data_dir ? ' · data ' + esc(a.data_dir) + ' ' + esc(size(a.data_bytes)) : '') + (logs ? ' · ' + logs : '') +
                    (a.removable ? ' <button class="ua-btn ua-btn-secondary as-goto" data-goto="' + esc(a.key) + '">Uninstall…</button>' : '')]);
            });
            (r.runtimes.kinds || []).forEach(function (k) {
                if (k.versions.length) { rows.push(['Runtime ' + esc(k.kind), esc(k.versions.join(', ')) + (k.bytes ? ' · ' + esc(size(k.bytes)) : '') +
                    ' <a href="' + esc(root.dataset.runtimes) + '">Runtime manager</a>']); }
            });
            r.caches.forEach(function (c) { rows.push([esc(c.title), esc(c.path) + ' ' + esc(size(c.bytes)) + ' <span class="ua-muted">(dnf clean all frees it)</span>']); });
            $('as-disk-body').innerHTML = table(rows);
        }).catch(function (e) { UA.showError($('as-disk-body'), e); }).then(function () { UA.busy(button, false); });
    }

    function watch(jobId, done) {
        $('as-job').style.display = 'block';
        $('as-job').scrollIntoView({behavior: 'smooth'});
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('as-job-out').innerHTML = '<p>' + esc(j.step || '') + ' ' + badge(j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail'), j.state) +
                    '</p>' + (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-120).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (done) { done(j); } else { load(); }
            }).catch(function (e) { UA.showError($('as-job-out'), e); });
        })();
    }

    // Starting a job is never retried (a lost reply must not start a second one).
    function start(key, button, name, body, done) {
        UA.busy(button, true);
        return api(name, body).then(function (d) {
            var r = d.result || {};
            if (r.warnings && r.warnings.length) { html(key, '.as-msg', r.warnings.map(warn).join('')); }
            if (r.job_id) { watch(r.job_id, done); } else { load(); }
        }).catch(function (e) { UA.showError(q(key, '.as-msg'), e); }).then(function () { UA.busy(button, false); });
    }

    function showPreview(key, job) {
        var r = (job.result || {})['Preview removal'];
        if (job.state !== 'done' || !r) { html(key, '.as-preview', '<div class="ua-alert">' + esc(job.error || 'The preview failed.') + '</div>'); return; }
        previews[key] = job.id;
        if (key === 's3') {
            html(key, '.as-preview', '<p>Would remove (' + esc(r.freed) + '):</p><div class="ua-pre">' + esc(r.files.join('\n')) + '</div>' +
                (r.endpoint ? '<p>The HTTPS endpoint on ' + esc(r.endpoint) + ' is taken off that site.</p>' : '') +
                (r.data_dir ? '<p>Data directory ' + esc(r.data_dir) + ' (' + esc(size(r.data_bytes)) + ') is kept unless you choose to delete it below.</p>' : ''));
            show(key, '.as-remove-confirm', true);
            return;
        }
        html(key, '.as-preview', '<p>dnf would remove ' + esc(r.packages.length) + ' package(s)' + (r.freed ? ', freeing ' + esc(r.freed) : '') +
            ':</p><div class="ua-pre">' + esc(r.packages.join('\n')) + '</div>' +
            (r.data_dir ? '<p>Data directory ' + esc(r.data_dir) + ' (' + esc(size(r.data_bytes)) + ') is kept unless you choose to delete it below.</p>' : ''));
        show(key, '.as-remove-confirm', true);
    }

    Array.prototype.forEach.call(document.querySelectorAll('#as-tabs button'), function (button) {
        button.addEventListener('click', function () {
            Array.prototype.forEach.call(document.querySelectorAll('#as-tabs button'), function (b) { b.classList.toggle('active', b === button); });
            Array.prototype.forEach.call(document.querySelectorAll('.ua-pane'), function (p) { p.classList.toggle('active', p.dataset.app === button.dataset.app); });
        });
    });

    $('as-disk-btn').addEventListener('click', function (event) { loadDisk(event.target); });
    $('as-disk-body').addEventListener('click', function (event) {
        var key = event.target.dataset.goto;
        if (!key) { return; }
        var tab = document.querySelector('#as-tabs button[data-app="' + key + '"]');
        if (tab) { tab.click(); q(key, '.as-remove').scrollIntoView({behavior: 'smooth'}); }
    });

    Array.prototype.forEach.call(document.querySelectorAll('.ua-pane[data-kind]'), function (p) {
        var key = p.dataset.app;
        p.addEventListener('click', function (event) {
            var t = event.target, a = apps[key] || {};
            if (t.dataset.op) {
                if (t.dataset.op === 'stop' && !window.confirm('Stop ' + a.title + '? Sites using it lose it until it is started again.')) { return; }
                start(key, t, 'control', {app: key, op: t.dataset.op});
            } else if (t.classList.contains('as-install-btn')) {
                if (!window.confirm('Install ' + a.title + ' now?')) { return; }
                var body = {app: key, force: q(key, '.as-force').checked};
                if (q(key, '.as-major')) { body.major = q(key, '.as-major').value; }
                start(key, t, 'install', body);
            } else if (t.classList.contains('as-apply')) {
                var exposed = q(key, '.as-exposed').checked;
                if (!window.confirm('Apply these settings and restart ' + a.title + '? If it does not come back healthy, the previous configuration is restored.')) { return; }
                start(key, t, 'configure', {app: key, settings: collect(key), confirmExposed: exposed});
            } else if (t.classList.contains('as-revert')) {
                if (!window.confirm('Go back to the configuration saved before the last change, and restart ' + a.title + '?')) { return; }
                start(key, t, 'revert', {app: key, confirm: true});
            } else if (t.classList.contains('as-preview-btn')) {
                show(key, '.as-remove-confirm', false);
                html(key, '.as-preview', '<p class="ua-muted">Asking dnf…</p>');
                start(key, t, 'remove_preview', {app: key}, function (job) { showPreview(key, job); });
            } else if (t.classList.contains('as-remove-btn')) {
                var del = q(key, '.as-delete').checked, name = q(key, '.as-confirm').value.trim().toLowerCase();
                if (!previews[key]) { UA.showError(q(key, '.as-msg'), new Error('Show what will be removed first.')); return; }
                if (del && name !== key) { UA.showError(q(key, '.as-msg'), new Error('Type ' + key + ' to confirm deleting its data.')); return; }
                if (!window.confirm(del ? 'Uninstall ' + a.title + ' and DELETE ' + a.data_dir + '? This cannot be undone.' : 'Uninstall ' + a.title + ' (keeping its data directory)?')) { return; }
                start(key, t, 'remove', {app: key, confirm: true, deleteData: del, confirmName: del ? name : '', previewJob: previews[key]}, function () {
                    delete previews[key];
                    html(key, '.as-preview', '');
                    show(key, '.as-remove-confirm', false);
                    load();
                });
            } else if (t.classList.contains('as-pg-create')) {
                var db = q(key, '.as-pg-db').value.trim(), user = q(key, '.as-pg-user').value.trim();
                UA.busy(t, true);
                api('pg_create', {database: db, user: user}).then(function (d) {
                    var r = d.result;
                    html(key, '.as-pg-out', '<p>Created database <strong>' + esc(r.database) + '</strong> owned by <strong>' + esc(r.user) +
                        '</strong>. Copy the password now; it is not stored and will not be shown again:</p><div class="ua-pre">' +
                        esc('host=' + r.host + ' port=' + r.port + ' dbname=' + r.database + ' user=' + r.user + ' password=' + r.password) + '</div>');
                    load();
                }).catch(function (e) { UA.showError(q(key, '.as-pg-out'), e); }).then(function () { UA.busy(t, false); });
            } else if (t.classList.contains('as-s3-bucket-create')) {
                s3call(t, 's3_bucket', {op: 'create', bucket: q(key, '.as-s3-bucket').value.trim(),
                    maxSizeMb: q(key, '.as-s3-maxsize').value.trim(), maxObjects: q(key, '.as-s3-maxobjects').value.trim()});
            } else if (t.classList.contains('as-s3-bucket-quota')) {
                var mb = window.prompt('Quota for ' + t.dataset.bucket + ' in MB (blank or 0 = no quota):', '');
                if (mb === null) { return; }
                var objs = window.prompt('Maximum number of objects (blank or 0 = no limit):', '');
                if (objs === null) { return; }
                s3call(t, 's3_bucket', {op: 'quota', bucket: t.dataset.bucket, maxSizeMb: mb.trim(), maxObjects: objs.trim()});
            } else if (t.classList.contains('as-s3-bucket-delete')) {
                var typed = window.prompt('Delete the (empty) bucket ' + t.dataset.bucket + '? Type its name to confirm:', '');
                if (typed === null) { return; }
                s3call(t, 's3_bucket', {op: 'delete', bucket: t.dataset.bucket, confirmName: typed.trim()});
            } else if (t.classList.contains('as-s3-key-create')) {
                s3call(t, 's3_key', {op: 'create', name: q(key, '.as-s3-keyname').value.trim()}, function (r) {
                    html(key, '.as-s3-secret', '<div class="ua-card" style="background:#fef3c7"><p><strong>Copy the secret now; it will not be shown again.</strong></p>' +
                        '<div class="ua-pre">' + esc('Access key ID:     ' + r.id + '\nSecret access key: ' + r.secret) + '</div></div>');
                });
            } else if (t.classList.contains('as-s3-key-delete')) {
                if (!window.confirm('Delete access key ' + t.dataset.key + '? Apps using it lose access at once.')) { return; }
                s3call(t, 's3_key', {op: 'delete', key: t.dataset.key, confirm: true});
            } else if (t.classList.contains('as-s3-perm-save')) {
                s3call(t, 's3_permission', {bucket: q(key, '.as-s3-perm-bucket').value, key: q(key, '.as-s3-perm-key').value,
                    read: q(key, '.as-s3-perm-read').checked, write: q(key, '.as-s3-perm-write').checked, owner: q(key, '.as-s3-perm-owner').checked});
            } else if (t.classList.contains('as-s3-endpoint-set')) {
                var domain = q(key, '.as-s3-domain').value.trim().toLowerCase();
                if (!window.confirm('Send every request for https://' + domain + '/ to the S3 API? The site\'s own pages there stop being served.')) { return; }
                start(key, t, 's3_endpoint', {op: 'set', domain: domain});
            } else if (t.classList.contains('as-s3-endpoint-remove')) {
                if (!window.confirm('Remove the HTTPS endpoint? Customers using it lose access.')) { return; }
                start(key, t, 's3_endpoint', {op: 'remove'});
            } else if (t.classList.contains('as-logs-btn')) {
                loadLogs(key);
            } else if (t.classList.contains('as-reveal')) {
                UA.busy(t, true);
                api('reveal', {app: key}).then(function (d) {
                    t.style.display = 'none';
                    q(key, '.as-reveal-out').innerHTML = '<p>Copy it now; it will not be shown again:</p><div class="ua-pre">' + esc(d.result.password) + '</div>';
                }).catch(function (e) { UA.showError(q(key, '.as-reveal-out'), e); UA.busy(t, false); });
            }
        });
    });
    load();
    loadRuntimes();
})();
