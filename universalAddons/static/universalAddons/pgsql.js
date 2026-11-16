/* PostgreSQL databases for site owners. */
(function () {
    'use strict';
    var root = document.getElementById('ua-pgsql');
    if (!root || root.dataset.installed !== '1') { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/';
    var api = function (name, body) { return UA.api(base + 'ajax/' + name, body); };
    var state = {data: null};

    function human(bytes) {
        if (bytes === null || bytes === undefined) { return '–'; }
        var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0, n = Number(bytes);
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
        return (i ? n.toFixed(1) : n) + ' ' + units[i];
    }
    function prefix(domain) {
        var first = (domain || '').toLowerCase().replace(/-/g, '').split('.')[0];
        if (first.length > 5) { first = first.substring(0, 4); }
        return first.replace(/[^a-z0-9]/g, '') + '_';
    }
    function site() { return $('pg-site').value; }
    function notify(error) { window.alert(error.message || error); }
    function secret(lines) {
        $('pg-secret').style.display = 'block';
        $('pg-secret-out').textContent = lines.join('\n');
        $('pg-secret').scrollIntoView({behavior: 'smooth'});
    }

    function watch(jobId, done) {
        $('pg-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('pg-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (done) { done(j); }
            }).catch(function (e) { UA.showError($('pg-job-out'), e); });
        })();
    }

    function render() {
        var d = state.data, domain = site();
        var dbs = d.databases.filter(function (x) { return x.domain === domain; });
        var roles = d.roles.filter(function (x) { return x.domain === domain; });
        $('pg-prefix').textContent = prefix(domain);
        $('pg-quota').textContent = d.quotas && d.quotas[domain] ? 'Databases in use (MySQL + PostgreSQL): ' + d.quotas[domain] : '';
        $('pg-dbs').innerHTML = dbs.length ? '<table class="ua-table"><tr><th>Database</th><th>Owner</th><th>Size</th><th>Other roles</th><th></th></tr>' +
            dbs.map(function (x) {
                var grants = Object.keys(x.grants || {}).map(function (r) {
                    return esc(r) + ' (' + esc(x.grants[r]) + ') <a href="#" data-revoke="' + esc(r) + '" data-db="' + esc(x.name) + '">revoke</a>';
                }).join('<br>');
                return '<tr><td><strong>' + esc(x.name) + '</strong>' + (x.missing ? ' <span class="ua-badge ua-badge-warn">missing on server</span>' : '') +
                    '</td><td>' + esc(x.owner) + '</td><td>' + human(x.bytes) + '</td><td>' + (grants || '<span class="ua-muted">none</span>') + '</td><td>' +
                    (root.dataset.adminer === '1' ? '<button class="ua-btn ua-btn-secondary" data-adminer="' + esc(x.name) + '">Adminer</button> ' : '') +
                    '<button class="ua-btn ua-btn-secondary" data-backup="' + esc(x.name) + '">Back up</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-drop="' + esc(x.name) + '" style="color:#dc2626">Delete</button></td></tr>';
            }).join('') + '</table>' : '<p class="ua-muted">No PostgreSQL databases for this site yet.</p>';
        var options = dbs.map(function (x) { return '<option value="' + esc(x.name) + '">' + esc(x.name) + '</option>'; }).join('');
        $('pg-restore-db').innerHTML = options;
        $('pg-roles').innerHTML = roles.length ? '<table class="ua-table"><tr><th>Role</th><th>Owns</th><th>Access to</th><th></th></tr>' +
            roles.map(function (r) {
                return '<tr><td><strong>' + esc(r.name) + '</strong></td><td>' + esc(r.owns.join(', ') || '–') + '</td><td>' + esc(r.databases.join(', ') || '–') +
                    '</td><td><select data-grant-db="' + esc(r.name) + '">' + options + '</select> <select data-grant-level="' + esc(r.name) + '">' +
                    '<option value="all">all</option><option value="read">read only</option></select> ' +
                    '<button class="ua-btn ua-btn-secondary" data-grant="' + esc(r.name) + '"' + (dbs.length ? '' : ' disabled') + '>Grant</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-reset="' + esc(r.name) + '">Reset password</button> ' +
                    (r.owns.length ? '' : '<button class="ua-btn ua-btn-secondary" data-droprole="' + esc(r.name) + '" style="color:#dc2626">Delete</button>') +
                    '</td></tr>';
            }).join('') + '</table>' : '<p class="ua-muted">No roles yet.</p>';
        var c = d.connection;
        $('pg-connection').innerHTML = c ? '<p>' + esc(c.note) + '</p><div class="ua-pre">Host: ' + esc(c.host) + '\nPort: ' + esc(c.port) +
            '\npsql: ' + esc(c.psql) + '\nPHP:  ' + esc(c.php) + '</div>' +
            (d.adminer ? '<p>Adminer: <a href="/adminer/" target="_blank" rel="noopener">/adminer/</a> (use the Adminer button on a database to log in with one click).</p>' : '') : '';
        loadBackups();
    }

    function loadBackups() {
        if (!site()) { return; }
        api('backups', {domain: site()}).then(function (d) {
            var list = d.result.backups;
            $('pg-backups').innerHTML = list.length ? '<table class="ua-table"><tr><th>File</th><th>Database</th><th>Size</th><th>Made</th><th></th></tr>' +
                list.map(function (b) {
                    var href = base + 'download?domain=' + encodeURIComponent(site()) + '&file=' + encodeURIComponent(b.file);
                    return '<tr><td>' + esc(b.file) + '</td><td>' + esc(b.database) + '</td><td>' + human(b.bytes) + '</td><td>' +
                        esc(new Date(b.time * 1000).toLocaleString()) + '</td><td><a class="ua-btn ua-btn-secondary" href="' + esc(href) + '">Download</a> ' +
                        '<button class="ua-btn ua-btn-secondary" data-delbackup="' + esc(b.file) + '">Delete</button></td></tr>';
                }).join('') + '</table><p class="ua-muted">Saved in ' + esc(d.result.directory) + '</p>' : '<p class="ua-muted">No backups yet.</p>';
        }).catch(function (e) { UA.showError($('pg-backups'), e); });
    }

    function load() {
        return api('overview', {}).then(function (d) { state.data = d.result; render(); })
            .catch(function (e) { UA.showError($('pg-dbs'), e); });
    }

    function action(name, body, button, after) {
        UA.busy(button, true);
        return api(name, body).then(function (d) { if (after) { after(d.result); } return load(); })
            .catch(notify).then(function () { UA.busy(button, false); });
    }

    $('pg-site').addEventListener('change', render);
    $('pg-secret-close').onclick = function () { $('pg-secret').style.display = 'none'; $('pg-secret-out').textContent = ''; };
    $('pg-create-db').onclick = function () {
        action('create_db', {domain: site(), name: $('pg-name').value.trim()}, this, function (r) {
            secret(['Database: ' + r.database, 'Role:     ' + r.role, 'Password: ' + r.password, 'Host:     127.0.0.1:5432', 'URI:      ' + r.uri]);
            $('pg-name').value = '';
        });
    };
    $('pg-create-role').onclick = function () {
        action('create_role', {domain: site(), name: $('pg-name').value.trim()}, this, function (r) {
            secret(['Role:     ' + r.role, 'Password: ' + r.password]);
            $('pg-name').value = '';
        });
    };

    root.addEventListener('click', function (event) {
        var t = event.target, ds = t.dataset || {};
        if (ds.drop) {
            if (window.confirm('Delete database ' + ds.drop + ' and everything in it? Its owner role goes too unless it has access to another database. This cannot be undone.')) {
                action('drop_db', {domain: site(), name: ds.drop}, t);
            }
        } else if (ds.droprole) {
            if (window.confirm('Delete role ' + ds.droprole + '?')) { action('drop_role', {domain: site(), name: ds.droprole}, t); }
        } else if (ds.reset) {
            if (window.confirm('Give ' + ds.reset + ' a new password? Applications using the old one stop connecting.')) {
                action('reset_password', {domain: site(), role: ds.reset}, t, function (r) { secret(['Role:     ' + r.role, 'Password: ' + r.password]); });
            }
        } else if (ds.grant) {
            var db = root.querySelector('[data-grant-db="' + ds.grant + '"]').value;
            var level = root.querySelector('[data-grant-level="' + ds.grant + '"]').value;
            action('grant', {domain: site(), db: db, role: ds.grant, level: level}, t);
        } else if (ds.revoke) {
            event.preventDefault();
            action('revoke', {domain: site(), db: ds.db, role: ds.revoke}, null);
        } else if (ds.backup) {
            UA.busy(t, true);
            api('backup', {domain: site(), db: ds.backup}).then(function (d) {
                watch(d.result.job_id, loadBackups);
            }).catch(notify).then(function () { UA.busy(t, false); });
        } else if (ds.delbackup) {
            if (window.confirm('Delete ' + ds.delbackup + '?')) {
                api('delete_backup', {domain: site(), file: ds.delbackup}).then(loadBackups).catch(notify);
            }
        } else if (ds.adminer) {
            var form = $('pg-adminer-form');
            form.elements.domain.value = site();
            form.elements.db.value = ds.adminer;
            form.submit();
        }
    });

    $('pg-restore-form').addEventListener('submit', function (event) {
        event.preventDefault();
        var form = new FormData(this);
        form.append('domain', site());
        var token = (document.cookie.match(/(?:^|; )csrftoken=([^;]*)/) || [])[1] || '';
        fetch(base + 'restore', {method: 'POST', body: form, credentials: 'same-origin',
                                 headers: {'X-CSRFToken': decodeURIComponent(token)}})
            .then(function (r) { return r.json(); }).then(function (d) {
                if (d.status !== 1) { throw new Error(d.error_message || 'Restore failed.'); }
                watch(d.result.job_id, load);
            }).catch(notify);
    });

    var install = $('pg-adminer-install'), remove = $('pg-adminer-remove');
    if (install) {
        install.onclick = function () {
            UA.busy(install, true);
            api('adminer_install', {}).then(function (d) { watch(d.result.job_id, function () { window.location.reload(); }); })
                .catch(notify).then(function () { UA.busy(install, false); });
        };
    }
    if (remove) {
        remove.onclick = function () {
            if (window.confirm('Remove Adminer from the panel?')) {
                api('adminer_remove', {}).then(function () { window.location.reload(); }).catch(notify);
            }
        };
    }
    load();
})();
