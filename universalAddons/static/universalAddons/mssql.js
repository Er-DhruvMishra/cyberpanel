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
