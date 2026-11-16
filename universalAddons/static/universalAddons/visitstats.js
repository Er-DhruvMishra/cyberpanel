(function () {
    'use strict';
    var root = document.getElementById('ua-visitstats');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var admin = root.dataset.admin === '1';
    var sites = [];

    function reportUrl(domain) { return root.dataset.report + '?site=' + encodeURIComponent(domain); }
    function when(ts) { return ts ? esc(new Date(ts * 1000).toLocaleString()) : 'never'; }

    function renderSites() {
        var filter = ($('vs-filter').value || '').toLowerCase();
        var rows = sites.filter(function (s) { return !filter || s.domain.indexOf(filter) >= 0; });
        $('vs-sites').innerHTML = rows.length ? '<table class="ua-table"><thead><tr><th>Site</th><th>Last report</th><th>Anonymise IPs</th><th></th></tr></thead><tbody>' +
            rows.map(function (s) {
                return '<tr><td><strong>' + esc(s.domain) + '</strong>' + (s.error ? '<div class="ua-muted">' + esc(s.error) + '</div>' : '') + '</td>' +
                    '<td>' + when(s.generated) + (s.engine ? ' <span class="ua-muted">(' + esc(s.engine === 'builtin' ? 'built-in summary' : 'GoAccess') + ')</span>' : '') + '</td>' +
                    '<td><input type="checkbox" data-anon="' + esc(s.domain) + '"' + (s.anonymize ? ' checked' : '') + '></td>' +
                    '<td style="white-space:nowrap">' + (s.report ? '<button class="ua-btn ua-btn-secondary" data-view="' + esc(s.domain) + '">View</button> ' : '') +
                    '<button class="ua-btn ua-btn-secondary" data-build="' + esc(s.domain) + '">Build now</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No sites.</p>';
    }

    function load() {
        api('overview', {}).then(function (d) {
            var r = d.result;
            sites = r.sites;
            renderSites();
            if (admin) {
                $('vs-engine-out').innerHTML = r.goaccess ? '<p><span class="ua-badge ua-badge-pass">GoAccess ' + esc(r.goaccess) + '</span> ' +
                    (r.persist ? 'Reports are incremental (persistent database).' : 'Each report reads the current log.') + '</p>' :
                    '<p><span class="ua-badge ua-badge-warn">GoAccess not installed</span> Reports use the built-in summary (visits, pages, referrers, status codes, top IPs).</p>';
                $('vs-engine-out').innerHTML += '<p class="ua-muted">Nightly rebuild: ' + (r.nightly ? 'scheduled' : 'not scheduled (install the cron entry)') + '.</p>';
            }
            if (root.dataset.site) { show(root.dataset.site); root.dataset.site = ''; }
        }).catch(function (e) { UA.showError($('vs-sites'), e); });
    }

    function show(domain) {
        var site = sites.filter(function (s) { return s.domain === domain; })[0];
        if (!site || !site.report) { return; }
        $('vs-view').style.display = 'block';
        $('vs-view-title').textContent = domain;
        $('vs-view-open').href = reportUrl(domain);
        $('vs-frame').src = reportUrl(domain);
    }

    function watch(jobId) {
        $('vs-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('vs-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-40).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else { load(); }
            }).catch(function (e) { UA.showError($('vs-job-out'), e); });
        })();
    }

    $('vs-filter').oninput = renderSites;
    $('vs-sites').onclick = function (event) {
        var t = event.target;
        if (t.dataset.view) { show(t.dataset.view); }
        if (t.dataset.build) {
            UA.busy(t, true);
            api('generate', {site: t.dataset.build}).then(function (d) { watch(d.result.job_id); })
                .catch(function (e) { window.alert(e.message); }).then(function () { UA.busy(t, false); });
        }
    };
    $('vs-sites').onchange = function (event) {
        var t = event.target;
        if (t.dataset.anon) {
            api('options', {site: t.dataset.anon, anonymize: t.checked}).then(load).catch(function (e) { window.alert(e.message); load(); });
        }
    };
    if (admin) {
        $('vs-check').onclick = function () {
            var button = this;
            UA.busy(button, true);
            $('vs-engine-note').textContent = 'Asking dnf (this can take a minute)…';
            api('check_available', {}).then(function (d) {
                var r = d.result;
                $('vs-engine-note').textContent = r.available ? 'GoAccess ' + r.version + ' is available from ' + r.repository + '.' :
                    'GoAccess is not available from the enabled repositories. ' + (r.detail || '');
                $('vs-install').style.display = r.available ? '' : 'none';
            }).catch(function (e) { $('vs-engine-note').textContent = e.message; }).then(function () { UA.busy(button, false); });
        };
        $('vs-install').onclick = function () {
            if (!window.confirm('Install GoAccess with dnf now?')) { return; }
            api('install', {}).then(function (d) { watch(d.result.job_id); }).catch(function (e) { window.alert(e.message); });
        };
    }
    load();
})();
