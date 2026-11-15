(function () {
    'use strict';
    var root = document.getElementById('ua-appsvc');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var apps = {};

    function pane(key) { return $('as-pane-' + key); }
    function q(key, sel) { return pane(key).querySelector(sel); }

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

    function renderHost(d) {
        $('as-host').innerHTML = '<p>RAM ' + esc(d.ram_mb) + ' MB (' + esc(d.ram_available_mb) + ' MB available) · ' +
            esc(d.disk_free_mb) + ' MB free under /var/lib</p>';
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
                '" data-type="' + esc(f.type) + '" value="' + esc(shown) + '">';
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

    function renderApp(a) {
        apps[a.key] = a;
        var p = pane(a.key);
        q(a.key, '.as-msg').innerHTML = '';
        if (!a.installed) {
            q(a.key, '.as-status').innerHTML = '<p>' + badge('info', 'not installed') + '</p>';
            q(a.key, '.as-preflight').innerHTML = checks(a.preflight || []);
            ['.as-controls', '.as-config', '.as-connect', '.as-logs-card', '.as-remove'].forEach(function (s) { q(a.key, s).style.display = 'none'; });
            q(a.key, '.as-install').style.display = 'block';
            q(a.key, '.as-secret').innerHTML = '';
            return;
        }
        var running = a.active === 'active';
        var rows = [
            ['Version', esc(a.version)],
            ['Service', badge(running ? 'pass' : 'fail', a.active) + ' ' + esc(a.sub) + (a.busy ? ' ' + badge('info', 'change in progress') : '')],
            ['Enabled at boot', badge(a.enabled === 'enabled' ? 'pass' : 'warn', a.enabled)],
            ['Memory', running ? esc(size(a.memory_bytes)) + (a.memory_source ? ' <span class="ua-muted">(' + esc(a.memory_source) + ')</span>' : '') : '–'],
            ['Listening', (a.listen || []).length ? (a.listen || []).map(function (l) {
                var loop = /^(127\.|\[::1\]|::1|\[::ffff:127\.)/.test(l);
                return badge(loop ? 'pass' : 'warn', loop ? 'local' : 'network') + ' ' + esc(l);
            }).join('<br>') : '–'],
            ['Data directory', a.data_dir ? esc(a.data_dir) + ' (' + esc(size(a.data_bytes)) + ')' : 'none (in memory only)'],
            ['Password', a.password.set ? badge('pass', 'set') + (a.password.by_panel ? ' generated by the panel' : ' set outside the panel') : badge('warn', 'none')],
            ['Saved configurations', esc(a.backups) + ' (for revert)']
        ];
        if (a.conflicts && a.conflicts.length) {
            rows.push(['Set outside the panel', esc(a.conflicts.join(', ')) + ' <span class="ua-muted">(the panel will not manage these until they are removed from elasticsearch.yml)</span>']);
        }
        q(a.key, '.as-status').innerHTML = table(rows);
        q(a.key, '.as-controls').style.display = '';
        q(a.key, '.as-install').style.display = 'none';
        ['.as-config', '.as-connect', '.as-logs-card', '.as-remove'].forEach(function (s) { q(a.key, s).style.display = 'block'; });

        q(a.key, '.as-secret').innerHTML = a.password.reveal_pending ?
            '<div class="ua-card" style="background:#fef3c7"><p><strong>A generated password is ready.</strong> It can be shown only once.</p>' +
            '<button class="ua-btn as-reveal">Show the password once</button><div class="as-reveal-out"></div></div>' : '';

        var s = a.settings || {};
        var note = a.config_problem ? '<div class="ua-alert">' + esc(a.config_problem) + '</div>' :
            (a.key === 'elasticsearch' ? 'Heap between ' + esc(a.heap_bounds[0]) + ' and ' + esc(a.heap_bounds[1]) + ' MB on this server. ' : '') +
            (s.managed ? 'Managed by the panel.' : 'Not yet managed by the panel: the values shown are the current ones.');
        q(a.key, '.as-config-note').innerHTML = note;
        q(a.key, '.as-form').innerHTML = a.fields.map(function (f) { return fieldHtml(f, f.transient ? false : s[f.name], a.key); }).join('');
        q(a.key, '.as-revert').style.display = a.backups ? '' : 'none';

        var c = a.connection || {}, info = [['Host', esc(c.host)], ['Port', esc(c.port)]];
        if (c.socket) { info.push(['Unix socket', esc(c.socket)]); }
        if (c.url) { info.push(['URL', esc(c.url)]); }
        info.push(['Authentication', esc(c.auth)]);
        q(a.key, '.as-connect-body').innerHTML = table(info) + (c.note ? '<p class="ua-muted">' + esc(c.note) + '</p>' : '') +
            (c.examples || []).map(function (e) { return '<h3>' + esc(e.title) + '</h3><div class="ua-pre">' + esc(e.code) + '</div>'; }).join('');
        if (p.dataset.logsShown) { loadLogs(a.key); }
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

    function watch(jobId) {
        $('as-job').style.display = 'block';
        $('as-job').scrollIntoView({behavior: 'smooth'});
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('as-job-out').innerHTML = '<p>' + esc(j.step || '') + ' ' + badge(j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail'), j.state) +
                    '</p>' + (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-120).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else { load(); }
            }).catch(function (e) { UA.showError($('as-job-out'), e); });
        })();
    }

    // Starting a job is never retried (a lost reply must not start a second one).
    function start(key, button, name, body) {
        UA.busy(button, true);
        return api(name, body).then(function (d) {
            var r = d.result || {};
            if (r.warnings && r.warnings.length) {
                q(key, '.as-msg').innerHTML = r.warnings.map(function (w) { return '<div class="ua-alert" style="background:#fef3c7;color:#92400e;margin-top:6px">' + esc(w) + '</div>'; }).join('');
            }
            if (r.job_id) { watch(r.job_id); } else { load(); }
        }).catch(function (e) { UA.showError(q(key, '.as-msg'), e); }).then(function () { UA.busy(button, false); });
    }

    Array.prototype.forEach.call(document.querySelectorAll('#as-tabs button'), function (button) {
        button.addEventListener('click', function () {
            Array.prototype.forEach.call(document.querySelectorAll('#as-tabs button'), function (b) { b.classList.toggle('active', b === button); });
            Array.prototype.forEach.call(document.querySelectorAll('.ua-pane'), function (p) { p.classList.toggle('active', p.dataset.app === button.dataset.app); });
        });
    });

    Array.prototype.forEach.call(document.querySelectorAll('.ua-pane'), function (p) {
        var key = p.dataset.app;
        p.addEventListener('click', function (event) {
            var t = event.target, a = apps[key] || {};
            if (t.dataset.op) {
                if (t.dataset.op === 'stop' && !window.confirm('Stop ' + a.title + '? Sites using it lose it until it is started again.')) { return; }
                start(key, t, 'control', {app: key, op: t.dataset.op});
            } else if (t.classList.contains('as-install-btn')) {
                if (!window.confirm('Install ' + a.title + ' now?')) { return; }
                start(key, t, 'install', {app: key, force: q(key, '.as-force').checked});
            } else if (t.classList.contains('as-apply')) {
                var exposed = q(key, '.as-exposed').checked;
                if (!window.confirm('Apply these settings and restart ' + a.title + '? If it does not come back healthy, the previous configuration is restored.')) { return; }
                start(key, t, 'configure', {app: key, settings: collect(key), confirmExposed: exposed});
            } else if (t.classList.contains('as-revert')) {
                if (!window.confirm('Go back to the configuration saved before the last change, and restart ' + a.title + '?')) { return; }
                start(key, t, 'revert', {app: key, confirm: true});
            } else if (t.classList.contains('as-remove-btn')) {
                var del = q(key, '.as-delete').checked, name = q(key, '.as-confirm').value.trim().toLowerCase();
                if (del && name !== key) { UA.showError(q(key, '.as-msg'), new Error('Type ' + key + ' to confirm deleting its data.')); return; }
                if (!window.confirm(del ? 'Remove ' + a.title + ' and DELETE ' + a.data_dir + '? This cannot be undone.' : 'Remove ' + a.title + ' (keeping its data directory)?')) { return; }
                start(key, t, 'remove', {app: key, confirm: true, deleteData: del, confirmName: del ? name : ''});
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
})();
