(function () {
    'use strict';
    var root = document.getElementById('ua-apache');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {data: null, editing: null, preview: null};
    var FIELDS = [
        ['max_children', 'pm.max_children'], ['start_servers', 'pm.start_servers (dynamic)'],
        ['min_spare_servers', 'pm.min_spare_servers (dynamic)'], ['max_spare_servers', 'pm.max_spare_servers (dynamic)'],
        ['max_requests', 'pm.max_requests (0 = never recycle)'], ['memory_limit_mb', 'memory_limit (MB)']
    ];

    function badge(kind, text) { return '<span class="ua-badge ua-badge-' + kind + '">' + esc(text) + '</span>'; }
    function onOff(value) { return value === null || value === undefined ? badge('info', 'n/a') : (value ? badge('pass', 'active') : badge('warn', 'inactive')); }

    function watch(jobId, done) {
        $('ap-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }, function (e, n) {
                $('ap-job-out').innerHTML = '<p class="ua-muted">The panel is busy (' + esc(e.message) + '); reconnecting, attempt ' + n +
                    '. The job keeps running on the server.</p>';
            }).then(function (d) {
                var j = d.result;
                $('ap-job-out').innerHTML = '<p>' + esc(j.step || '') + ' ' + badge(j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail'), j.state) + '</p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (done) { done(j); }
            }).catch(function (e) {
                UA.showError($('ap-job-out'), e);
                var again = document.createElement('button');
                again.type = 'button';
                again.className = 'ua-btn ua-btn-secondary';
                again.textContent = 'Check again';
                again.onclick = function () { watch(jobId, done); };
                $('ap-job-out').appendChild(again);
            });
        })();
    }

    function renderHost(d) {
        var h = d.host, a = d.httpd;
        $('ap-host').innerHTML = '<table class="ua-table"><tbody>' +
            '<tr><td><strong>RAM / CPU</strong></td><td>' + esc(h.total_mb) + ' MB total, <strong>' + esc(h.available_mb) + ' MB available</strong>, ' +
            esc(h.swap_free_mb) + ' MB swap free, ' + esc(h.cores) + ' core(s)</td></tr>' +
            '<tr><td><strong>Apache httpd</strong></td><td>' + (a.installed ? badge('pass', 'installed') + ' ' + onOff(a.active) +
                ' <span class="ua-muted">enabled: ' + esc(a.enabled) + ', runs as ' + esc(a.run_user) + ':' + esc(a.run_group) + '</span>' : badge('warn', 'not installed')) + '</td></tr>' +
            '<tr><td><strong>Internal backend</strong></td><td>' + (a.base_ok ? badge('pass', '127.0.0.1:' + a.port) : badge('warn', 'not configured')) +
                ' <code>' + esc(a.base_conf) + '</code>' + (a.listens.length ? '<div class="ua-muted">httpd Listen: ' + esc(a.listens.join(', ')) + '</div>' : '') + '</td></tr>' +
            '<tr><td><strong>PHP-FPM</strong></td><td>' + (d.fpm.length ? d.fpm.map(function (f) {
                return esc(f.dotted) + ' <span class="ua-muted">(' + esc(f.kind) + ', ' + esc(f.service) + ', ' + esc(f.pools) + ' site pool(s))</span> ' + onOff(f.active);
            }).join('<br>') : badge('warn', 'none')) + '</td></tr>' +
            '<tr><td><strong>PHP used by sites</strong></td><td>' + esc(d.in_use.map(function (v) { return v[0] + '.' + v.slice(1); }).join(', ') || '-') + '</td></tr>' +
            '</tbody></table>' + d.notes.map(function (n) { return '<div class="ua-fix">&#9888; ' + esc(n) + '</div>'; }).join('');
    }

    function renderInstall(d) {
        var p = d.install, have = {};
        d.fpm.forEach(function (f) { have[f.version] = true; });
        $('ap-install').innerHTML = '<p><strong>PHP-FPM versions</strong> <span class="ua-muted">(pre-selected: used by sites and not installed yet)</span></p>' +
            '<div class="ua-row">' + d.versions.map(function (v) {
                return '<label style="margin-right:10px"><input type="checkbox" class="ap-version" value="' + esc(v) + '"' +
                    (have[v] ? ' disabled checked' : (p.missing.indexOf(v) >= 0 ? ' checked' : '')) + '> ' + esc(v[0] + '.' + v.slice(1)) + '</label>';
            }).join('') + '</div>' +
            '<table class="ua-table" style="margin-top:8px"><tbody>' +
            '<tr><td><strong>Would install</strong></td><td>' + (p.packages.length ? '<code>' + esc(p.packages.join(' ')) + '</code>' : 'nothing (only the backend configuration)') + '</td></tr>' +
            (p.repo ? '<tr><td><strong>Repository</strong></td><td><code>' + esc(p.repo) + '</code><div class="ua-pre">' + esc(p.repo_text) + '</div></td></tr>' : '') +
            '<tr><td><strong>RAM</strong></td><td>about ' + esc(p.ram_steady_mb) + ' MB more at idle, plus ~' + esc(p.ram_transient_mb) +
                ' MB while dnf runs. ' + esc(p.per_site_note) + '</td></tr>' +
            '</tbody></table>' + p.warnings.map(function (w) { return '<div class="ua-fix">&#9888; ' + esc(w) + '</div>'; }).join('') +
            (d.remi_key ? '' : '<div class="ua-fix">&#9888; The remi signing key is missing; PHP-FPM packages cannot be verified.</div>');
        $('ap-confirm-wrap').style.display = p.needs_confirm ? '' : 'none';
    }

    function modeBadge(s) {
        if (s.error) { return badge('fail', 'unavailable'); }
        return {apache: badge('info', 'Apache'), ols: badge('pass', 'OpenLiteSpeed'), partial: badge('warn', 'incomplete')}[s.mode] || '';
    }

    function renderSites() {
        var d = state.data, filter = ($('ap-filter').value || '').toLowerCase();
        $('ap-sites').innerHTML = '<table class="ua-table"><thead><tr><th>Site</th><th>PHP</th><th>Mode</th><th>Pool</th><th>PHP-FPM</th><th></th></tr></thead><tbody>' +
            d.sites.map(function (s, n) {
                if (filter && s.domain.indexOf(filter) < 0) { return ''; }
                var pool = s.pool_file ? (s.socket ? badge('pass', 'socket up') : badge('warn', 'no socket')) + ' <span class="ua-muted">' + esc(s.workers) + ' worker(s), ' +
                    esc(s.pool.pm) + ', max ' + esc(s.pool.max_children) + ', ' + esc(s.pool.memory_limit_mb) + 'M</span>' : '<span class="ua-muted">-</span>';
                var buttons = '';
                if (!s.error && s.state === 1) {
                    if (s.mode !== 'apache') { buttons += '<button class="ua-btn ua-btn-secondary ap-open" data-mode="apache" data-n="' + n + '">Switch to Apache</button> '; }
                    if (s.mode === 'apache') { buttons += '<button class="ua-btn ua-btn-secondary ap-open" data-mode="tune" data-n="' + n + '">Tune pool</button> '; }
                    if (s.mode !== 'ols' || s.pool_file || s.httpd_conf) { buttons += '<button class="ua-btn ua-btn-secondary ap-back" data-n="' + n + '">Back to OpenLiteSpeed</button>'; }
                }
                return '<tr><td><strong>' + esc(s.domain) + '</strong><div class="ua-muted">' + esc(s.user) + '</div></td>' +
                    '<td>' + esc(s.php ? s.php[0] + '.' + s.php.slice(1) : '') + '</td><td>' + modeBadge(s) +
                    (s.error ? '<div class="ua-fix">' + esc(s.error) + '</div>' : '') +
                    s.warnings.map(function (w) { return '<div class="ua-fix">&#9888; ' + esc(w) + '</div>'; }).join('') + '</td>' +
                    '<td>' + pool + '</td><td>' + (s.fpm ? esc(s.fpm) + ' ' + onOff(s.fpm_active) : (s.php ? badge('warn', 'not installed') : '')) + '</td>' +
                    '<td style="white-space:nowrap">' + buttons + '</td></tr>';
            }).join('') + '</tbody></table>';
    }

    function load() {
        return api('overview', {}).then(function (d) {
            state.data = d.result;
            renderHost(state.data);
            renderInstall(state.data);
            renderSites();
        }).catch(function (e) { UA.showError($('ap-host'), e); });
    }

    function childrenMax(memory) {
        var total = state.data.host.total_mb;
        return Math.max(1, Math.min(50, Math.floor(Math.floor(total / 2) / Math.max(memory || 128, 32))));
    }

    function readPool() {
        var pool = {pm: $('ap-pm').value};
        root.querySelectorAll('.ap-field').forEach(function (input) { if (input.value !== '') { pool[input.dataset.key] = Number(input.value); } });
        return pool;
    }

    function updateRam() {
        var pool = readPool(), memory = pool.memory_limit_mb || 0, max = childrenMax(memory);
        $('ap-ram').textContent = 'At most ' + max + ' children with memory_limit ' + memory + ' MB on this server. Worst case for this pool: ' +
            ((pool.max_children || 0) * memory) + ' MB; typical peak about ' + ((pool.max_children || 0) * Math.min(60, memory)) + ' MB' +
            (pool.pm === 'ondemand' ? '; idle 0 MB.' : '.');
        root.querySelectorAll('.ap-dynamic').forEach(function (row) { row.style.display = pool.pm === 'dynamic' ? '' : 'none'; });
    }

    function openEditor(n, mode) {
        var s = state.data.sites[n], b = state.data.bounds;
        state.editing = {site: s.domain, mode: mode};
        $('ap-editor-title').textContent = (mode === 'apache' ? 'Switch to Apache: ' : 'Tune the PHP-FPM pool: ') + s.domain;
        $('ap-editor-bounds').textContent = 'PHP ' + (s.php ? s.php[0] + '.' + s.php.slice(1) : '?') + '. memory_limit ' + b.memory_limit_mb[0] + '-' + b.memory_limit_mb[1] +
            ' MB. pm.max_children is capped so one pool cannot claim more than half of the RAM even if every child reaches memory_limit.';
        $('ap-form').innerHTML = '<tbody><tr><td>pm</td><td><select id="ap-pm">' + state.data.pm_modes.map(function (m) {
                return '<option value="' + esc(m) + '"' + (m === s.pool.pm ? ' selected' : '') + '>' + esc(m) + '</option>';
            }).join('') + '</select> <span class="ua-muted">ondemand starts workers only when requests arrive (lowest RAM)</span></td></tr>' +
            FIELDS.map(function (f) {
                var dynamic = ['start_servers', 'min_spare_servers', 'max_spare_servers'].indexOf(f[0]) >= 0;
                return '<tr' + (dynamic ? ' class="ap-dynamic"' : '') + '><td>' + esc(f[1]) + '</td><td><input type="number" min="0" class="ap-field" data-key="' + esc(f[0]) +
                    '" value="' + esc(s.pool[f[0]]) + '" style="min-width:110px"></td></tr>';
            }).join('') + '</tbody>';
        $('ap-editor').style.display = 'block';
        $('ap-pm').addEventListener('change', updateRam);
        root.querySelectorAll('.ap-field').forEach(function (input) { input.addEventListener('input', updateRam); });
        updateRam();
        $('ap-editor').scrollIntoView({behavior: 'smooth'});
    }

    function showPreview(target) {
        $('ap-preview').style.display = 'block';
        $('ap-preview-title').textContent = target.site + ' (' + {apache: 'to Apache', ols: 'back to OpenLiteSpeed', tune: 'pool tuning'}[target.mode] + ')';
        $('ap-preview-out').innerHTML = '<p class="ua-muted">Computing…</p>';
        $('ap-apply').disabled = true;
        state.preview = null;
        api('preview', target).then(function (d) {
            var r = d.result;
            state.preview = {site: target.site, mode: target.mode, pool: target.pool, token: r.token, changed: r.changed};
            $('ap-preview-out').innerHTML = '<p>' + (r.changed ? esc(r.files.length) + ' file(s) change:' : 'Nothing to change.') + '</p>' +
                '<ul>' + r.files.map(function (f) { return '<li><code>' + esc(f.path) + '</code> <span class="ua-muted">' + esc(f.action) + ' (' + esc(f.role) + ')</span></li>'; }).join('') + '</ul>' +
                r.warnings.map(function (w) { return '<div class="ua-fix">&#9888; ' + esc(w) + '</div>'; }).join('') +
                (r.diff ? '<div class="ua-pre">' + esc(r.diff) + '</div>' : '');
            $('ap-apply').disabled = !r.changed;
        }).catch(function (e) { UA.showError($('ap-preview-out'), e); });
    }

    $('ap-preview-run').addEventListener('click', function () {
        if (!state.editing) { return; }
        showPreview({site: state.editing.site, mode: state.editing.mode, pool: readPool()});
    });
    $('ap-editor-close').addEventListener('click', function () { $('ap-editor').style.display = 'none'; });

    $('ap-apply').addEventListener('click', function () {
        var p = state.preview, button = this;
        if (!p || !window.confirm('Apply this change to ' + p.site + '? php-fpm, httpd and OpenLiteSpeed are reloaded; the change is rolled back if the site answers differently.')) { return; }
        UA.busy(button, true);
        api('apply', {site: p.site, mode: p.mode, token: p.token, pool: p.pool}).then(function (d) {
            watch(d.result.job_id, function () { UA.busy(button, false); button.disabled = true; load(); });
        }).catch(function (e) { UA.busy(button, false); UA.showError($('ap-preview-out'), e); });
    });

    $('ap-install-run').addEventListener('click', function () {
        var button = this, versions = [];
        root.querySelectorAll('.ap-version:checked:not(:disabled)').forEach(function (box) { versions.push(box.value); });
        var confirmLow = $('ap-confirm').checked;
        if (!window.confirm(versions.length ? 'Install PHP-FPM ' + versions.join(', ') + ' (and Apache if missing) and configure the internal backend?' :
            'Configure the internal Apache backend?')) { return; }
        UA.busy(button, true);
        $('ap-install-note').textContent = '';
        api('install', {versions: versions, confirm: confirmLow}).then(function (d) {
            watch(d.result.job_id, function () { UA.busy(button, false); load(); });
        }).catch(function (e) { UA.busy(button, false); $('ap-install-note').textContent = e.message; });
    });

    root.addEventListener('click', function (e) {
        var button = e.target.closest('button');
        if (!button || !state.data) { return; }
        if (button.classList.contains('ap-open')) { openEditor(Number(button.dataset.n), button.dataset.mode); }
        if (button.classList.contains('ap-back')) {
            $('ap-editor').style.display = 'none';
            showPreview({site: state.data.sites[Number(button.dataset.n)].domain, mode: 'ols'});
        }
    });
    $('ap-filter').addEventListener('input', function () { if (state.data) { renderSites(); } });

    load();
})();
