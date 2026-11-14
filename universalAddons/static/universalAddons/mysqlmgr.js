(function () {
    'use strict';
    var root = document.getElementById('ua-mysqlmgr');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {recs: [], processes: []};
    var LEVEL = {change: 'warn', ok: 'pass', warn: 'warn', critical: 'fail', info: 'info'};
    var loaded = {};

    function human(bytes) {
        var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
        bytes = Number(bytes || 0);
        while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i += 1; }
        return (i < 2 ? bytes.toFixed(0) : bytes.toFixed(1)) + ' ' + units[i];
    }
    function pct(x) { return x === null || x === undefined ? 'n/a' : (x * 100).toFixed(1) + '%'; }
    function duration(s) {
        var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
        return (d ? d + 'd ' : '') + (d || h ? h + 'h ' : '') + m + 'm';
    }
    function tile(label, value, sub) {
        return '<div class="ua-card"><div class="ua-muted">' + esc(label) + '</div><div style="font-size:20px;font-weight:600">' +
            esc(value) + '</div>' + (sub ? '<div class="ua-muted">' + esc(sub) + '</div>' : '') + '</div>';
    }
    function fail(target, e) { UA.showError(target, e); }

    function showPane(name) {
        root.querySelectorAll('.ua-tabs button').forEach(function (b) { b.classList.toggle('active', b.dataset.pane === name); });
        root.querySelectorAll('.ua-pane').forEach(function (p) { p.classList.toggle('active', p.id === 'pane-' + name); });
        if (!loaded[name]) {
            loaded[name] = true;
            if (name === 'processes') { loadProcesses(); }
            if (name === 'tuning') { loadAdvice(); }
        }
    }
    root.querySelectorAll('.ua-tabs button').forEach(function (tab) {
        tab.addEventListener('click', function () { showPane(tab.dataset.pane); });
    });

    // ------------------------------------------------------------------ status
    function loadStatus() {
        var button = $('my-status-refresh');
        UA.busy(button, true);
        UA.retry(function () { return api('status', {}); }).then(function (d) {
            UA.busy(button, false);
            var m = d.result.metrics;
            var html = '';
            if (m.force_recovery) {
                html += '<div class="ua-alert">innodb_force_recovery = ' + esc(m.force_recovery) +
                    ': InnoDB is in emergency recovery mode. See the Tuning advisor.</div>';
            }
            html += '<div class="ua-grid">' +
                tile('Version', m.version, 'up ' + duration(m.uptime)) +
                tile('Connections', m.connections + ' / ' + m.max_connections, 'peak ' + m.peak_connections + ', running ' + m.running) +
                tile('Queries per second', m.qps, 'average since start') +
                tile('Slow queries', m.slow_queries, 'slow log ' + m.slow_log + ', threshold ' + m.long_query_time + ' s') +
                tile('InnoDB buffer pool', human(m.buffer_pool_bytes), pct(m.buffer_pool_used) + ' used, hit ratio ' + pct(m.buffer_pool_hit)) +
                tile('Temporary tables on disk', pct(m.tmp_disk_ratio), m.tmp_disk_tables + ' of ' + m.tmp_tables) +
                tile('Table open cache', m.open_tables + ' / ' + m.table_open_cache, 'efficiency ' + pct(m.table_cache_efficiency) + ', ' + m.opened_tables_per_hour + ' opened/h') +
                tile('Aborted connects', m.aborted_connects, m.aborted_clients + ' aborted clients') +
                '</div>';
            $('my-status').innerHTML = html;
        }).catch(function (e) { UA.busy(button, false); fail($('my-status'), e); });
    }
    $('my-status-refresh').addEventListener('click', loadStatus);

    $('my-db-load').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('databases', {}).then(function (d) {
            UA.busy(button, false);
            var dbs = d.result.databases;
            $('my-databases').innerHTML = '<table class="ua-table"><thead><tr><th>Database</th><th>Tables</th><th>Size</th><th>Free in tablespace</th></tr></thead><tbody>' +
                dbs.map(function (db) {
                    return '<tr><td><strong>' + esc(db.name) + '</strong>' + (db.system ? ' <span class="ua-badge ua-badge-info">system</span>' : '') +
                        '</td><td>' + esc(db.tables) + '</td><td>' + esc(human(db.bytes)) + '</td><td class="ua-muted">' + esc(human(db.free_bytes)) + '</td></tr>';
                }).join('') + '</tbody></table><p class="ua-muted">' + dbs.filter(function (x) { return !x.system; }).length + ' databases, ' +
                esc(human(dbs.reduce(function (a, x) { return a + (x.system ? 0 : x.bytes); }, 0))) + ' of data.</p>';
        }).catch(function (e) { UA.busy(button, false); fail($('my-databases'), e); });
    });

    // ------------------------------------------------------------------ processes
    function renderProcesses() {
        var showSleep = $('my-proc-sleep').checked;
        var rows = state.processes.filter(function (p) { return showSleep || p.command !== 'Sleep'; });
        $('my-processes').innerHTML = '<table class="ua-table"><thead><tr><th>Id</th><th>User</th><th>Database</th><th>Command</th><th>Time</th><th>State / query</th><th></th></tr></thead><tbody>' +
            rows.map(function (p) {
                var action = p.protected ? '<span class="ua-muted" title="' + esc(p.protected) + '">protected</span>' :
                    '<button class="ua-btn ua-btn-secondary my-kill" data-id="' + esc(p.id) + '" data-mode="query">Kill query</button> ' +
                    '<button class="ua-btn ua-btn-secondary my-kill" data-id="' + esc(p.id) + '" data-mode="connection">Kill connection</button>';
                return '<tr><td>' + esc(p.id) + '</td><td>' + esc(p.user) + '<div class="ua-muted">' + esc(p.host) + '</div></td><td>' + esc(p.db) +
                    '</td><td>' + esc(p.command) + '</td><td>' + esc(p.time) + ' s</td><td>' + esc(p.state) +
                    (p.info ? '<div><code>' + esc(p.info) + '</code></div>' : '') + '</td><td>' + action + '</td></tr>';
            }).join('') + '</tbody></table><p class="ua-muted">' + rows.length + ' shown of ' + state.processes.length + ' threads.</p>';
    }
    function loadProcesses() {
        var button = $('my-proc-refresh');
        UA.busy(button, true);
        api('processes', {}).then(function (d) {
            UA.busy(button, false);
            state.processes = d.result.processes;
            renderProcesses();
        }).catch(function (e) { UA.busy(button, false); fail($('my-proc-out'), e); });
    }
    $('my-proc-refresh').addEventListener('click', function () { $('my-proc-out').innerHTML = ''; loadProcesses(); });
    $('my-proc-sleep').addEventListener('change', renderProcesses);
    root.addEventListener('click', function (e) {
        var button = e.target.closest('.my-kill');
        if (!button) { return; }
        var id = Number(button.dataset.id), mode = button.dataset.mode;
        if (!window.confirm((mode === 'query' ? 'Stop the running query of thread ' : 'Close connection ') + id + '?')) { return; }
        UA.busy(button, true);
        api('kill', {thread: id, mode: mode}).then(function (d) {
            $('my-proc-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Done</span> Thread ' + esc(d.result.killed) + ' (' + esc(d.result.user) + '): ' +
                esc(d.result.mode === 'query' ? 'query stopped' : 'connection closed') + '.</p>';
            loadProcesses();
        }).catch(function (err) { UA.busy(button, false); fail($('my-proc-out'), err); });
    });

    // ------------------------------------------------------------------ tuning
    function renderAdvice(r) {
        state.recs = r.recommendations;
        var notes = r.notes.map(function (n) { return '<div class="ua-alert">' + esc(n) + '</div>'; }).join('');
        notes += '<p class="ua-muted">RAM ' + esc(human(r.ram)) + '. MySQL memory: ' + esc(human(r.memory.global)) + ' global buffers + ' +
            esc(human(r.memory.per_thread)) + ' per connection; about ' + esc(human(r.memory.at_peak)) + ' at peak use, ' +
            esc(human(r.memory.worst_case)) + ' if every allowed connection were busy.</p>';
        $('my-notes').innerHTML = notes;
        $('my-recs').innerHTML = '<thead><tr><th></th><th>Setting</th><th>Now</th><th>Suggested</th><th>Why</th></tr></thead><tbody>' +
            r.recommendations.map(function (rec, n) {
                var box = rec.applicable ? '<input type="checkbox" class="my-rec" data-n="' + n + '"' + (rec.optional ? '' : ' checked') + '>' : '';
                var value = rec.applicable ? '<input type="text" class="my-val" data-n="' + n + '" value="' + esc(rec.recommended) + '" size="8">' : esc(rec.recommended || '');
                return '<tr><td>' + box + '</td><td><strong>' + esc(rec.variable) + '</strong><div><span class="ua-badge ua-badge-' + (LEVEL[rec.level] || 'info') + '">' +
                    esc(rec.level === 'change' ? (rec.optional ? 'optional' : 'suggested') : rec.level) + '</span>' +
                    (rec.tentative ? ' <span class="ua-badge ua-badge-info">tentative</span>' : '') + '</div></td><td><code>' + esc(rec.current) + '</code></td><td>' + value +
                    '</td><td>' + esc(rec.reason) + (rec.overridden ? '<div class="ua-fix">Also set in ' + esc(rec.overridden) + ', which overrides the drop-in.</div>' : '') + '</td></tr>';
            }).join('') + '</tbody>';
        var dropin = r.dropin;
        $('my-dropin-path').textContent = dropin.path ? 'Drop-in: ' + dropin.path : (dropin.error || '');
        $('my-dropin').innerHTML = (dropin.exists ? '<div class="ua-pre">' + esc(dropin.text) + '</div>' : '<p class="ua-muted">No tuning has been applied yet.</p>') +
            '<p class="ua-muted">' + r.backups.length + ' earlier version(s) kept for "Revert".</p>';
        $('my-revert').disabled = !r.backups.length;
    }
    function loadAdvice() {
        var button = $('my-advise');
        UA.busy(button, true);
        api('advise', {}).then(function (d) { UA.busy(button, false); renderAdvice(d.result); })
            .catch(function (e) { UA.busy(button, false); fail($('my-tuning-out'), e); });
    }
    $('my-advise').addEventListener('click', function () { $('my-tuning-out').innerHTML = ''; loadAdvice(); });

    function checkHtml(check) {
        if (!check) { return ''; }
        return '<p>Configuration check (' + esc(check.method) + '): <span class="ua-badge ua-badge-' + (check.ok ? 'pass">OK' : 'fail">Failed') + '</span></p>' +
            check.errors.map(function (x) { return '<div class="ua-fix">' + esc(x) + '</div>'; }).join('') +
            check.mismatches.map(function (x) {
                return '<div class="ua-fix">' + esc(x.variable) + ' will be ' + esc(x.effective) + ', not ' + esc(x.wanted) + ' (set again in another file).</div>';
            }).join('');
    }

    $('my-apply').addEventListener('click', function () {
        var settings = {}, names = [], button = this;
        // The drop-in is replaced as a whole: keep earlier settings unless they are re-chosen here.
        root.querySelectorAll('.my-rec:checked').forEach(function (box) {
            var n = Number(box.dataset.n), rec = state.recs[n];
            settings[rec.variable] = root.querySelector('.my-val[data-n="' + n + '"]').value.trim();
            names.push(rec.variable + ' = ' + settings[rec.variable]);
        });
        if (!names.length) { fail($('my-tuning-out'), new Error('Nothing selected.')); return; }
        var kept = {};
        api('advise', {}).then(function (d) {
            kept = d.result.dropin.settings || {};
            Object.keys(kept).forEach(function (k) { if (!(k in settings)) { settings[k] = kept[k]; } });
            if (!window.confirm('Write these settings to the tuning drop-in?\n\n' + Object.keys(settings).map(function (k) { return k + ' = ' + settings[k]; }).join('\n') +
                '\n\nMariaDB is not restarted; they take effect at the next restart.')) { return null; }
            UA.busy(button, true);
            return api('apply', {settings: settings});
        }).then(function (d) {
            UA.busy(button, false);
            if (!d) { return; }
            var r = d.result;
            $('my-tuning-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Saved</span> ' + esc(r.path) + '. Restart MariaDB to use it.</p>' +
                r.warnings.map(function (w) { return '<div class="ua-fix">' + esc(w) + '</div>'; }).join('') + checkHtml(r.check);
            loadAdvice();
        }).catch(function (e) { UA.busy(button, false); fail($('my-tuning-out'), e); });
    });

    $('my-revert').addEventListener('click', function () {
        var button = this;
        if (!window.confirm('Put back the tuning drop-in as it was before the last change? MariaDB is not restarted.')) { return; }
        UA.busy(button, true);
        api('revert', {}).then(function (d) {
            UA.busy(button, false);
            var r = d.result;
            $('my-tuning-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Reverted</span> ' +
                esc(r.removed ? 'The drop-in was removed (there was none before).' : 'Restored the version saved as ' + r.from + '.') +
                ' Restart MariaDB to use it.</p>' + checkHtml(r.check);
            loadAdvice();
        }).catch(function (e) { UA.busy(button, false); fail($('my-tuning-out'), e); });
    });

    $('my-check').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('check', {}).then(function (d) { UA.busy(button, false); $('my-tuning-out').innerHTML = checkHtml(d.result); })
            .catch(function (e) { UA.busy(button, false); fail($('my-tuning-out'), e); });
    });

    function watch(jobId, done) {
        $('my-job').style.display = 'block';
        (function poll() {
            // While MariaDB restarts the panel itself may fail requests; keep retrying.
            UA.retry(function () { return api('job', {job: jobId}); }, function (e, n) {
                $('my-job-out').insertAdjacentHTML('afterbegin', '<p class="ua-muted">Panel busy (' + esc(e.message) + '), reconnecting (' + n + ')…</p>');
            }).then(function (d) {
                var j = d.result;
                $('my-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (done) { done(j); }
            }).catch(function (e) { fail($('my-job-out'), e); if (done) { done({state: 'unknown'}); } });
        })();
    }

    $('my-restart').addEventListener('click', function () {
        var button = this;
        if (!window.confirm('Check the configuration and restart MariaDB? Every website loses its database connection for a few seconds. ' +
            'If the server does not come back, the previous tuning is restored and it is started again.')) { return; }
        UA.busy(button, true);
        api('restart', {confirm: true}).then(function (d) {
            watch(d.result.job_id, function () { UA.busy(button, false); loadAdvice(); loadStatus(); });
        }).catch(function (e) { UA.busy(button, false); fail($('my-tuning-out'), e); });
    });

    // ------------------------------------------------------------------ upgrade
    $('my-upgrade').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('upgrade', {}).then(function (d) {
            UA.busy(button, false);
            var r = d.result;
            var list = function (items, cls) { return items.map(function (x) { return '<div class="' + cls + '">' + esc(x) + '</div>'; }).join(''); };
            $('my-upgrade-out').innerHTML =
                '<table class="ua-table"><tbody>' +
                '<tr><td>Installed</td><td><strong>' + esc(r.installed) + '</strong> ' + (r.is_eol ? '<span class="ua-badge ua-badge-fail">end of life since ' + esc(r.eol) + '</span>' :
                    (r.eol ? '<span class="ua-badge ua-badge-pass">supported until ' + esc(r.eol) + '</span>' : '')) + '</td></tr>' +
                '<tr><td>Operating system</td><td>' + esc(r.os.name) + '</td></tr>' +
                '<tr><td>Available upgrades</td><td>' + (r.targets.length ? r.targets.map(function (t) {
                    return esc(t.version) + (t.lts ? ' LTS' : '') + ' <span class="ua-badge ua-badge-' + (t.supported ? 'pass">until ' : 'fail">ended ') + esc(t.eol) + '</span>' +
                        (t.version === r.recommended ? ' <strong>recommended</strong>' : '') + ' <span class="ua-muted">' + esc(t.source) + '</span>';
                }).join('<br>') : '<span class="ua-muted">No packaged target known for this OS.</span>') + '</td></tr>' +
                '<tr><td>Databases</td><td>' + esc(r.databases) + ' databases, ' + esc(human(r.data_bytes)) + ' of data; datadir ' + esc(r.datadir) + ' is ' + esc(human(r.datadir_bytes)) + ' on disk</td></tr>' +
                '<tr><td>Disk space</td><td><span class="ua-badge ua-badge-' + (r.disk_ok ? 'pass">OK' : 'fail">Too little') + '</span> ' + esc(human(r.free_bytes)) + ' free, about ' +
                    esc(human(r.needed_bytes)) + ' needed (backup + headroom)</td></tr>' +
                '</tbody></table>' +
                (r.django ? '<p>' + esc(r.django) + (r.shim_present ? '' : ' <strong>The shim was not found on this server.</strong>') + '</p>' : '') +
                list(r.blockers, 'ua-alert') + list(r.warnings, 'ua-fix') +
                '<h2 style="margin-top:18px">Steps</h2><ol>' + r.steps.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ol>' +
                '<p class="ua-muted">This page does not perform the upgrade.</p>';
        }).catch(function (e) { UA.busy(button, false); fail($('my-upgrade-out'), e); });
    });

    loadStatus();
})();
