(function () {
    'use strict';
    var root = document.getElementById('ua-mssql');
    if (!root || !document.getElementById('sq-list')) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1';

    function secret(r) {
        return '<div class="ua-card"><p><span class="ua-badge ua-badge-pass">Done</span> Copy these now; the password is not shown again.</p>' +
            '<table class="ua-table"><tbody><tr><td>Database / login</td><td><code>' + esc(r.name) + '</code></td></tr>' +
            '<tr><td>Password</td><td><code>' + esc(r.password) + '</code></td></tr>' +
            '<tr><td>Connection string</td><td><code style="word-break:break-all">' + esc(r.connection_string) + '</code></td></tr></tbody></table></div>';
    }

    function loadList() {
        return api('databases', {}).then(function (d) {
            var dbs = d.result.databases;
            $('sq-list').innerHTML = dbs.length ? '<table class="ua-table"><thead><tr><th>Database</th><th>Site</th><th>Size</th><th>Created</th><th></th></tr></thead><tbody>' +
                dbs.map(function (db) {
                    return '<tr><td><strong>' + esc(db.name) + '</strong></td><td>' + esc(db.domain) + '</td><td>' + (db.size_mb === null || db.size_mb === undefined ? '' : esc(db.size_mb) + ' MB') +
                        '</td><td>' + esc(new Date(db.created * 1000).toLocaleDateString()) + '</td><td>' +
                        '<button class="ua-btn ua-btn-secondary sq-browse" data-name="' + esc(db.name) + '" data-domain="' + esc(db.domain) + '">Browse</button> ' +
                        '<button class="ua-btn ua-btn-secondary sq-reset" data-name="' + esc(db.name) + '" data-domain="' + esc(db.domain) + '">New password</button> ' +
                        '<button class="ua-btn sq-drop" style="background:#dc2626" data-name="' + esc(db.name) + '" data-domain="' + esc(db.domain) + '">Delete</button></td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No SQL Server databases yet.</p>';
        }).catch(function (e) { UA.showError($('sq-list'), e); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('.sq-reset, .sq-drop');
        if (!t) { return; }
        if (t.classList.contains('sq-reset')) {
            if (!window.confirm('Generate a new password for ' + t.dataset.name + '? Apps using the old one stop connecting until updated.')) { return; }
            api('reset', {name: t.dataset.name, domain: t.dataset.domain}).then(function (d) { $('sq-created').innerHTML = secret(d.result); })
                .catch(function (e) { UA.showError($('sq-created'), e); });
        } else if (window.confirm('Delete database ' + t.dataset.name + ' and its login? This cannot be undone.')) {
            api('drop', {name: t.dataset.name, domain: t.dataset.domain}).then(loadList).catch(function (e) { UA.showError($('sq-list'), e); });
        }
    });

    // ------------------------------------------------------------------ viewer (read-only)
    var viewing = null;  // {name, domain, schema, table, page, total}

    function cell(value) {
        if (value === null || value === undefined) { return '<span class="ua-muted">NULL</span>'; }
        return esc(typeof value === 'object' ? JSON.stringify(value) : String(value));
    }

    function grid(columns, rows) {
        return '<table class="ua-table"><thead><tr>' + columns.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') +
            '</tr></thead><tbody>' + rows.map(function (r) {
                return '<tr>' + r.map(function (v) { return '<td style="white-space:pre-wrap;max-width:420px;word-break:break-word">' + cell(v) + '</td>'; }).join('') + '</tr>';
            }).join('') + '</tbody></table>';
    }

    function target(extra) {
        var body = {name: viewing.name, domain: viewing.domain};
        Object.keys(extra || {}).forEach(function (k) { body[k] = extra[k]; });
        return body;
    }

    function openViewer(name, domain) {
        viewing = {name: name, domain: domain};
        $('sq-viewer').style.display = 'block';
        $('sq-v-db').textContent = name;
        ['sq-v-columns', 'sq-v-rows', 'sq-v-result'].forEach(function (id) { $(id).innerHTML = ''; });
        $('sq-v-pager').style.display = 'none';
        $('sq-v-tables').innerHTML = '<p class="ua-muted">Loading…</p>';
        $('sq-viewer').scrollIntoView({behavior: 'smooth'});
        api('tables', target()).then(function (d) {
            var list = d.result.tables;
            $('sq-v-tables').innerHTML = list.length ? '<table class="ua-table"><thead><tr><th>Table</th><th>Rows</th><th>Size</th></tr></thead><tbody>' +
                list.map(function (t) {
                    return '<tr><td><a href="#" class="sq-v-table" data-schema="' + esc(t.schema) + '" data-table="' + esc(t.name) + '" data-rows="' + esc(t.rows === null ? '' : t.rows) + '">' +
                        esc(t.schema) + '.' + esc(t.name) + '</a>' + (t.kind === 'view' ? ' <span class="ua-badge ua-badge-info">view</span>' : '') + '</td><td>' +
                        (t.rows === null ? '' : esc(t.rows)) + '</td><td>' + (t.size_kb === null ? '' : esc(t.size_kb) + ' KB') + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No tables or views.</p>';
        }).catch(function (e) { UA.showError($('sq-v-tables'), e); });
    }

    function loadRows() {
        $('sq-v-rows').innerHTML = '<p class="ua-muted">Loading…</p>';
        return api('rows', target({schema: viewing.schema, table: viewing.table, page: viewing.page})).then(function (d) {
            var r = d.result, shown = r.rows.length, first = r.page * r.page_size;
            $('sq-v-rows').innerHTML = shown ? grid(r.columns, r.rows) : '<p class="ua-muted">No rows on this page.</p>';
            $('sq-v-pager').style.display = 'flex';
            $('sq-v-page').textContent = shown ? 'Rows ' + (first + 1) + '–' + (first + shown) + (viewing.total ? ' of about ' + viewing.total : '') : '';
            $('sq-v-prev').disabled = r.page === 0;
            $('sq-v-next').disabled = shown < r.page_size;
        }).catch(function (e) { UA.showError($('sq-v-rows'), e); });
    }

    function openTable(schema, table, total) {
        viewing.schema = schema; viewing.table = table; viewing.page = 0; viewing.total = total;
        $('sq-v-columns').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('columns', target({schema: schema, table: table})).then(function (d) {
            $('sq-v-columns').innerHTML = '<h3>' + esc(schema) + '.' + esc(table) + '</h3><table class="ua-table"><thead><tr><th>Column</th><th>Type</th><th>Null</th><th>Key</th></tr></thead><tbody>' +
                d.result.columns.map(function (c) {
                    return '<tr><td>' + esc(c.name) + '</td><td><code>' + esc(c.type) + '</code></td><td>' + (c.nullable ? 'yes' : 'no') + '</td><td>' +
                        (c.pk ? '<span class="ua-badge ua-badge-pass">PK</span>' : '') + '</td></tr>';
                }).join('') + '</tbody></table>';
        }).catch(function (e) { UA.showError($('sq-v-columns'), e); });
        loadRows();
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('.sq-browse, .sq-v-table');
        if (!t) { return; }
        event.preventDefault();
        if (t.classList.contains('sq-browse')) { openViewer(t.dataset.name, t.dataset.domain); } else { openTable(t.dataset.schema, t.dataset.table, t.dataset.rows); }
    });
    $('sq-v-close').addEventListener('click', function () { $('sq-viewer').style.display = 'none'; viewing = null; });
    $('sq-v-prev').addEventListener('click', function () { if (viewing.page > 0) { viewing.page -= 1; loadRows(); } });
    $('sq-v-next').addEventListener('click', function () { viewing.page += 1; loadRows(); });
    $('sq-v-run').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        $('sq-v-result').innerHTML = '';
        // 'content': the key CyberPanel's input filter leaves unscreened, as SQL needs ; ' ( [ etc.
        api('query', target({content: $('sq-v-sql').value})).then(function (d) {
            var r = d.result;
            $('sq-v-result').innerHTML = '<p class="ua-muted">' + esc(r.rows.length) + ' row(s)' + (r.capped ? ' (limit of 500 reached)' : '') + ', read-only and rolled back.</p>' +
                (r.columns.length ? grid(r.columns, r.rows) : '');
        }).catch(function (e) { UA.showError($('sq-v-result'), e); }).then(function () { UA.busy(button, false); });
    });

    $('sq-create').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('create', {domain: $('sq-domain').value, name: $('sq-name').value.trim().toLowerCase(), passwordByPass: $('sq-password').value})
            .then(function (d) { $('sq-password').value = ''; $('sq-created').innerHTML = secret(d.result); loadList(); })
            .catch(function (e) { UA.showError($('sq-created'), e); }).then(function () { UA.busy(button, false); });
    });

    function watch(jobId) {
        $('sq-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('sq-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' + (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) +
                    '">' + esc(j.state) + '</span></p>' + (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 5000); } else { loadServer(); loadList(); }
            }).catch(function (e) { UA.showError($('sq-job-out'), e); });
        })();
    }

    function loadServer() {
        return api('overview', {}).then(function (d) {
            var s = d.result;
            var checks = '<table class="ua-table"><tbody>' + s.preflight.filter(function (c) { return c.id !== 'installed'; }).map(function (c) {
                return '<tr><td><span class="ua-badge ua-badge-' + (c.ok ? 'pass' : 'fail') + '">' + (c.ok ? 'OK' : 'No') + '</span></td><td>' + esc(c.detail) + '</td></tr>';
            }).join('') + '</tbody></table>';
            if (s.installed) {
                $('sq-server').innerHTML = '<p>SQL Server ' + esc(s.product || '') + ' Express <span class="ua-badge ua-badge-' + (s.running ? 'pass' : 'fail') + '">' +
                    (s.running ? 'running' : 'stopped') + '</span> · memory cap ' + esc(s.memory_limit_mb || '?') + ' MB · 127.0.0.1:1433</p>' +
                    '<div class="ua-row"><button class="ua-btn ua-btn-secondary sq-svc" data-action="restart">Restart</button>' +
                    '<button class="ua-btn ua-btn-secondary sq-svc" data-action="' + (s.running ? 'stop' : 'start') + '">' + (s.running ? 'Stop' : 'Start') + '</button></div>';
                $('sq-install').style.display = 'none';
            } else {
                var ready = s.preflight.every(function (c) { return c.ok; });
                $('sq-server').innerHTML = '<p>Not installed. Requirements on this server:</p>' + checks +
                    (ready ? '' : '<div class="ua-alert">This server does not meet Microsoft\'s minimum requirements, so installation is disabled.</div>');
                $('sq-install').style.display = ready ? 'block' : 'none';
                $('sq-eula-link').href = s.eula_url;
                $('sq-memory').value = s.default_memory_limit_mb;
            }
        }).catch(function (e) { UA.showError($('sq-server'), e); });
    }

    if (isAdmin) {
        $('sq-install-btn').addEventListener('click', function () {
            if (!$('sq-eula').checked) { UA.showError($('sq-out'), new Error('Accept the licence terms first.')); return; }
            api('install', {acceptEula: true, memoryLimitMb: Number($('sq-memory').value)}).then(function (d) { watch(d.result.job_id); })
                .catch(function (e) { UA.showError($('sq-out'), e); });
        });
        root.addEventListener('click', function (event) {
            var t = event.target.closest('.sq-svc');
            if (t) { api('service', {action: t.dataset.action}).then(loadServer).catch(function (e) { UA.showError($('sq-out'), e); }); }
        });
        loadServer();
    }
    loadList();
})();
