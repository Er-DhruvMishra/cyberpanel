(function () {
    'use strict';
    var root = document.getElementById('ua-backupv2');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {overview: null, snapshot: null, path: '/', domain: ''};

    root.querySelectorAll('.ua-tabs button').forEach(function (tab) {
        tab.addEventListener('click', function () {
            root.querySelectorAll('.ua-tabs button').forEach(function (b) { b.classList.remove('active'); });
            root.querySelectorAll('.ua-pane').forEach(function (p) { p.classList.remove('active'); });
            tab.classList.add('active');
            $('pane-' + tab.dataset.pane).classList.add('active');
        });
    });

    function repoTypeFields() {
        var type = $('repo-type').value;
        root.querySelectorAll('.repo-f').forEach(function (row) { row.style.display = row.dataset.for === type ? 'flex' : 'none'; });
    }
    $('repo-type').addEventListener('change', repoTypeFields);

    function watch(jobId, after) {
        $('bk-job').style.display = 'block';
        (function poll() {
            api('job', {job: jobId}).then(function (d) {
                var j = d.result;
                $('bk-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 4000); } else if (after) { after(j); }
            }).catch(function (e) { UA.showError($('bk-job-out'), e); });
        })();
        $('bk-job').scrollIntoView({behavior: 'smooth'});
    }

    function describeRepo(r) {
        if (r.type === 'local') { return r.path; }
        if (r.type === 'sftp') { return 'sftp://' + r.user + '@' + r.host + ':' + r.port + r.path; }
        if (r.type === 's3') { return 's3://' + r.endpoint + '/' + r.bucket + (r.prefix ? '/' + r.prefix : ''); }
        return 'rclone ' + r.remote + ':' + r.path;
    }

    function render() {
        var o = state.overview;
        $('bk-repos').innerHTML = o.repos.length ? '<table class="ua-table"><tbody>' + o.repos.map(function (r) {
            return '<tr><td><strong>' + esc(r.id) + '</strong></td><td>' + esc(r.type) + '</td><td>' + esc(describeRepo(r)) + '</td><td>' +
                '<button class="ua-btn ua-btn-secondary bk-check" data-repo="' + esc(r.id) + '">Verify</button> ' +
                '<button class="ua-btn ua-btn-secondary bk-key" data-repo="' + esc(r.id) + '">Show encryption key</button></td></tr>';
        }).join('') + '</tbody></table>' : '<p class="ua-muted">No repository yet. Add one below.</p>';
        $('bk-policies').innerHTML = o.policies.length ? '<table class="ua-table"><thead><tr><th>Schedule</th><th>Repository</th><th>Sites</th>' +
            '<th>What</th><th>When</th><th>Keep</th><th></th></tr></thead><tbody>' + o.policies.map(function (p) {
                return '<tr><td><strong>' + esc(p.id) + '</strong></td><td>' + esc(p.repo) + '</td><td>' +
                    esc(p.sites === 'all' ? 'all' : p.sites.join(', ')) + '</td><td>' + esc(p.units.join(', ')) + '</td><td>' +
                    esc(p.schedule + (p.schedule === 'daily' || p.schedule === 'weekly' ? ' ' + p.hour + ':xx' : '')) + '</td><td>' +
                    esc(Object.keys(p.keep).map(function (k) { return k + ' ' + p.keep[k]; }).join(', ')) + '</td><td>' +
                    '<button class="ua-btn bk-run" data-policy="' + esc(p.id) + '">Run now</button> ' +
                    '<button class="ua-btn ua-btn-secondary bk-del" data-policy="' + esc(p.id) + '">Delete</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No schedule yet.</p>';
        var repoOptions = o.repos.map(function (r) { return '<option value="' + esc(r.id) + '">' + esc(r.id) + '</option>'; }).join('');
        $('pol-repo').innerHTML = repoOptions;
        $('rs-repo').innerHTML = repoOptions;
        var siteOptions = o.sites.map(function (s) { return '<option value="' + esc(s) + '">' + esc(s) + '</option>'; }).join('');
        $('pol-site-list').innerHTML = siteOptions;
        $('rs-site').innerHTML = '<option value="">all sites</option>' + siteOptions;
    }

    function load() {
        return api('overview', {}).then(function (d) { state.overview = d.result; render(); })
            .catch(function (e) { UA.showError($('bk-repos'), e); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target;
        if (t.classList.contains('bk-check')) {
            api('check', {repo: t.dataset.repo}).then(function (d) { watch(d.result.job_id); }).catch(function (e) { UA.showError($('repo-out'), e); });
        } else if (t.classList.contains('bk-key')) {
            if (!window.confirm('The encryption key decrypts every backup in this repository. Store it somewhere safe and offline. Show it now?')) { return; }
            api('export_key', {repo: t.dataset.repo}).then(function (d) {
                $('repo-out').innerHTML = '<p>Key for <strong>' + esc(t.dataset.repo) + '</strong> (needed to restore on another server):</p><div class="ua-pre">' + esc(d.result.key) + '</div>';
            }).catch(function (e) { UA.showError($('repo-out'), e); });
        } else if (t.classList.contains('bk-run')) {
            api('run_now', {policy: t.dataset.policy}).then(function (d) { watch(d.result.job_id); }).catch(function (e) { UA.showError($('pol-out'), e); });
        } else if (t.classList.contains('bk-del')) {
            if (window.confirm('Delete schedule ' + t.dataset.policy + '? Existing snapshots are kept.')) {
                api('delete_policy', {policy: t.dataset.policy}).then(load).catch(function (e) { UA.showError($('pol-out'), e); });
            }
        }
    });

    $('repo-sshkey').addEventListener('click', function () {
        api('ssh_key', {}).then(function (d) {
            $('repo-out').innerHTML = '<p>Add this key to <code>~/.ssh/authorized_keys</code> of the SFTP account:</p><div class="ua-pre">' + esc(d.result.public_key) + '</div>';
        }).catch(function (e) { UA.showError($('repo-out'), e); });
    });

    $('repo-save').addEventListener('click', function () {
        var type = $('repo-type').value, button = this;
        var body = {id: $('repo-id').value.trim(), type: type};
        if (type === 'local') { body.path = $('repo-path-local').value.trim(); }
        if (type === 'sftp') { body.host = $('repo-host').value.trim(); body.user = $('repo-user').value.trim(); body.port = Number($('repo-port').value || 22); body.path = $('repo-path-sftp').value.trim(); }
        if (type === 's3') { body.endpoint = ($('repo-endpoint').value.trim() || 's3.amazonaws.com').replace(/^https?:\/\//, '').replace(/\/$/, ''); body.bucket = $('repo-bucket').value.trim(); body.prefix = $('repo-prefix').value.trim(); body.region = $('repo-region').value.trim(); body.accessKey = $('repo-access').value.trim(); body.secretKey = $('repo-secret').value; }
        if (type === 'rclone') { body.remote = $('repo-remote').value.trim(); body.path = $('repo-path-rclone').value.trim(); }
        UA.busy(button, true);
        api('save_repo', body).then(function (d) {
            $('repo-secret').value = '';
            $('repo-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">OK</span> ' + esc(d.result.init.detail) +
                ' Use "Show encryption key" and store the key safely: without it these backups cannot be restored elsewhere.</p>';
            load();
        }).catch(function (e) { UA.showError($('repo-out'), e); }).then(function () { UA.busy(button, false); });
    });

    $('pol-save').addEventListener('click', function () {
        var button = this, some = root.querySelector('input[name="pol-sites"]:checked').value === 'some';
        var body = {id: $('pol-id').value.trim(), repo: $('pol-repo').value, schedule: $('pol-schedule').value,
            hour: Number($('pol-hour').value), check: $('pol-check').checked,
            units: Array.prototype.slice.call(root.querySelectorAll('.pol-unit:checked')).map(function (c) { return c.value; }),
            sites: some ? Array.prototype.slice.call($('pol-site-list').selectedOptions).map(function (o) { return o.value; }) : 'all'};
        ['last', 'hourly', 'daily', 'weekly', 'monthly'].forEach(function (k) {
            var v = $('keep-' + k).value; if (v !== '') { body['keep_' + k] = Number(v); }
        });
        UA.busy(button, true);
        api('save_policy', body).then(function () { $('pol-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Saved</span> The schedule is active.</p>'; load(); })
            .catch(function (e) { UA.showError($('pol-out'), e); }).then(function () { UA.busy(button, false); });
    });

    function listSnapshots() {
        return api('snapshots', {repo: $('rs-repo').value, domain: $('rs-site').value}).then(function (d) {
            var snaps = d.result.snapshots;
            $('rs-snapshots').innerHTML = snaps.length ? '<table class="ua-table"><thead><tr><th>Time</th><th>Site</th><th>Content</th><th>ID</th><th></th></tr></thead><tbody>' +
                snaps.map(function (s) {
                    var what = s.unit === 'db' ? 'database ' + s.database : (s.unit || s.tags.join(', '));
                    var action = s.unit === 'db'
                        ? '<button class="ua-btn rs-db" data-snap="' + esc(s.id) + '" data-site="' + esc(s.site) + '" data-db="' + esc(s.database) + '">Restore database</button>'
                        : '<button class="ua-btn ua-btn-secondary rs-browse" data-snap="' + esc(s.id) + '" data-site="' + esc(s.site) + '" data-path="' + esc((s.paths || ['/'])[0]) + '">Browse</button>';
                    return '<tr><td>' + esc(s.time.replace('T', ' ')) + '</td><td>' + esc(s.site) + '</td><td>' + esc(what) +
                        (s.tags.indexOf('pre-restore') >= 0 ? ' <span class="ua-badge ua-badge-info">safety copy</span>' : '') +
                        '</td><td><code>' + esc(s.id) + '</code></td><td>' + action + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No snapshots.</p>';
        }).catch(function (e) { UA.showError($('rs-snapshots'), e); });
    }
    $('rs-list').addEventListener('click', listSnapshots);

    function browse(path) {
        state.path = path;
        $('rs-path').textContent = path;
        return api('ls', {repo: $('rs-repo').value, snapshot: state.snapshot, path: path}).then(function (d) {
            var entries = d.result.entries.filter(function (e) { return e.path !== path; });
            $('rs-files').innerHTML = '<table class="ua-table"><tbody>' + entries.map(function (e) {
                return '<tr><td>' + (e.type === 'dir' ? '<a href="#" class="rs-dir" data-path="' + esc(e.path) + '"><i class="fas fa-folder"></i> ' + esc(e.path) + '</a>'
                    : '<i class="fas fa-file"></i> ' + esc(e.path)) + '</td><td>' + (e.type === 'dir' ? '' : esc(e.size)) + '</td></tr>';
            }).join('') + '</tbody></table>';
        }).catch(function (e) { UA.showError($('rs-files'), e); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('.rs-browse, .rs-dir, .rs-db');
        if (!t) { return; }
        event.preventDefault();
        if (t.classList.contains('rs-browse')) {
            state.snapshot = t.dataset.snap; state.domain = t.dataset.site;
            $('rs-snap-id').textContent = t.dataset.snap + ' (' + t.dataset.site + ')';
            $('rs-browser').style.display = 'block';
            browse(t.dataset.path || '/');
        } else if (t.classList.contains('rs-dir')) {
            browse(t.dataset.path);
        } else if (window.confirm('Replace database ' + t.dataset.db + ' with the copy from snapshot ' + t.dataset.snap + '? The current database is backed up first.')) {
            api('restore', {repo: $('rs-repo').value, snapshot: t.dataset.snap, domain: t.dataset.site, kind: 'db', database: t.dataset.db})
                .then(function (d) { watch(d.result.job_id, listSnapshots); }).catch(function (e) { UA.showError($('rs-snapshots'), e); });
        }
    });
    $('rs-up').addEventListener('click', function () { if (state.path !== '/') { browse(state.path.replace(/\/[^/]+$/, '') || '/'); } });

    function restoreFiles(include) {
        var target = $('rs-target').value.trim() || 'original';
        var text = target === 'original' ? 'Overwrite live files with ' + (include || 'the whole snapshot') + '? A safety snapshot of the current files is taken first.'
            : 'Restore ' + (include || 'the whole snapshot') + ' into ' + target + '?';
        if (!window.confirm(text)) { return; }
        api('restore', {repo: $('rs-repo').value, snapshot: state.snapshot, domain: state.domain, kind: 'files', target: target, include: include || ''})
            .then(function (d) { watch(d.result.job_id, listSnapshots); }).catch(function (e) { UA.showError($('rs-files'), e); });
    }
    $('rs-restore-path').addEventListener('click', function () { restoreFiles(state.path === '/' ? '' : state.path); });
    $('rs-restore-all').addEventListener('click', function () { restoreFiles(''); });

    repoTypeFields();
    load();
})();
