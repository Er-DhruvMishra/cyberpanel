(function () {
    'use strict';
    var root = document.getElementById('ua-appcatalog');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {site: '', apps: [], app: null};

    function tile(app) {
        var missing = app.missing && app.missing.length;
        var action = app.new ?
            '<button class="ua-btn ac-open" data-key="' + esc(app.key) + '"' + (missing ? ' disabled' : '') + '>Install</button>' :
            '<a class="ua-btn ua-btn-secondary" href="' + esc(app.url) + '">Open installer</a>';
        return '<div class="ua-card" style="display:inline-block;width:280px;vertical-align:top;margin:6px">' +
            '<h3><i class="' + esc(app.icon) + '"></i> ' + esc(app.title) + '</h3><p>' + esc(app.summary) + '</p>' +
            (app.source ? '<p class="ua-muted" style="font-size:12px">' + esc(app.source) + '</p>' : '') +
            (missing ? '<div class="ua-alert">Needs ' + esc(app.missing.join(', ')) + '.</div>' : '') + action + '</div>';
    }

    function loadApps() {
        $('ac-form').style.display = 'none';
        if (!state.site) { $('ac-apps').innerHTML = '<p class="ua-muted">Choose a site.</p>'; return; }
        $('ac-apps').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('catalogue', {domain: state.site}).then(function (d) {
            state.apps = d.result.apps;
            $('ac-apps').innerHTML = state.apps.map(tile).join('');
        }).catch(function (e) { UA.showError($('ac-apps'), e); });
    }

    function checkTarget() {
        if (!state.app) { return; }
        api('check', {domain: state.site, app: state.app.key, path: $('ac-path').value.trim()}).then(function (d) {
            var problem = d.result.problem;
            $('ac-target').innerHTML = '<p class="ua-muted">Target: <code>' + esc(d.result.target) + '</code></p>' +
                (problem ? '<div class="ua-alert">' + esc(problem) + '</div>' : '');
            $('ac-overwrite-row').style.display = problem ? '' : 'none';
            if (!problem) { $('ac-overwrite').checked = false; $('ac-confirm').value = ''; }
        }).catch(function (e) { UA.showError($('ac-target'), e); });
    }

    $('ac-apps').addEventListener('click', function (event) {
        var button = event.target.closest('.ac-open');
        if (!button) { return; }
        state.app = state.apps.filter(function (a) { return a.key === button.dataset.key; })[0];
        $('ac-form-title').textContent = 'Install ' + state.app.title + ' on ' + state.site;
        $('ac-form-source').textContent = state.app.source;
        var node = state.app.kind === 'node';
        $('ac-path-label').firstChild.textContent = node ? 'App name (Universal Apps; serves the whole site) ' :
            'Folder below the web root (empty = the site itself) ';
        $('ac-path').value = node ? 'ghost' : '';
        $('ac-name').value = state.app.title;
        $('ac-out').innerHTML = '';
        $('ac-form').style.display = '';
        checkTarget();
    });
    $('ac-path').addEventListener('change', checkTarget);
    $('ac-cancel').addEventListener('click', function () { $('ac-form').style.display = 'none'; });

    function credentials(result) {
        var html = '';
        Object.keys(result || {}).forEach(function (step) {
            var r = result[step];
            if (!r || typeof r !== 'object') { return; }
            if (r.credentials) {
                html += '<div class="ua-alert" style="background:#fef9c3;color:#713f12">Shown once: copy these now.</div><table class="ua-table"><tbody>';
                Object.keys(r.credentials).forEach(function (group) {
                    var c = r.credentials[group];
                    Object.keys(c).forEach(function (k) {
                        html += '<tr><td>' + esc(group + ' ' + k) + '</td><td><code>' + esc(c[k]) + '</code></td></tr>';
                    });
                });
                html += '</tbody></table>';
            } else if (r.credentials_shown) {
                html += '<p class="ua-muted">The credentials were already shown once.</p>';
            }
            ['version', 'sha256', 'sha512', 'backup', 'target'].forEach(function (k) {
                if (r[k]) { html += '<p class="ua-muted">' + esc(k) + ': <code>' + esc(r[k]) + '</code></p>'; }
            });
        });
        return html;
    }

    function poll(jobId) {
        UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
            var job = d.result;
            var log = '<pre class="ua-pre" style="max-height:300px;overflow:auto">' + esc((job.log || []).join('\n')) + '</pre>';
            if (job.state === 'running') {
                $('ac-out').innerHTML = '<p>' + esc(job.step || 'Working…') + '</p>' + log;
                setTimeout(function () { poll(jobId); }, 3000);
            } else if (job.state === 'done') {
                $('ac-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Installed</span></p>' + credentials(job.result) + log;
            } else {
                $('ac-out').innerHTML = '<div class="ua-alert">' + esc(job.error || job.state) + '</div>' + log;
            }
        }).catch(function (e) { UA.showError($('ac-out'), e); });
    }

    $('ac-install').addEventListener('click', function () {
        var button = this, overwrite = $('ac-overwrite').checked;
        if (overwrite && !window.confirm('The existing files in the target are moved to ~/appcatalog-backups. Continue?')) { return; }
        UA.busy(button, true);
        api('install', {domain: state.site, app: state.app.key, path: $('ac-path').value.trim(),
                        site_name: $('ac-name').value, admin_user: $('ac-admin').value.trim(),
                        admin_email: $('ac-email').value.trim(), overwrite: overwrite,
                        confirm: $('ac-confirm').value.trim()}).then(function (d) {
            poll(d.result.job_id);
        }).catch(function (e) { UA.showError($('ac-out'), e); }).then(function () { UA.busy(button, false); });
    });

    $('ac-site').addEventListener('change', function () { state.site = this.value; loadApps(); });
    api('sites', {}).then(function (d) {
        var wanted = root.dataset.site;
        $('ac-site').innerHTML = '<option value="">Choose…</option>' + d.result.sites.map(function (s) {
            return '<option' + (s === wanted ? ' selected' : '') + '>' + esc(s) + '</option>';
        }).join('');
        if (wanted && d.result.sites.indexOf(wanted) > -1) { state.site = wanted; loadApps(); }
    }).catch(function (e) { UA.showError($('ac-apps'), e); });
})();
