(function () {
    'use strict';
    var root = document.getElementById('ua-wordpress');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {sites: null, domain: null, info: null};

    root.querySelectorAll('#wp-site .ua-tabs button').forEach(function (tab) {
        tab.addEventListener('click', function () {
            root.querySelectorAll('#wp-site .ua-tabs button').forEach(function (b) { b.classList.remove('active'); });
            root.querySelectorAll('#wp-site .ua-pane').forEach(function (p) { p.classList.remove('active'); });
            tab.classList.add('active');
            $('pane-' + tab.dataset.pane).classList.add('active');
            if (tab.dataset.pane === 'security') { loadSecurity(); }
            if (tab.dataset.pane === 'snapshots') { loadSnapshots(); }
        });
    });

    function watch(jobId, after) {
        $('wp-job').style.display = 'block';
        (function poll() {
            api('job', {job: jobId}).then(function (d) {
                var j = d.result;
                $('wp-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 4000); } else if (after) { after(j); }
            }).catch(function (e) { UA.showError($('wp-job-out'), e); });
        })();
        $('wp-job').scrollIntoView({behavior: 'smooth'});
    }
    function startJob(name, body, after) {
        return api(name, body).then(function (d) { watch(d.result.job_id, after); }).catch(function (e) { UA.showError($('wp-job-out'), e); $('wp-job').style.display = 'block'; });
    }

    function loadSites() {
        return api('sites', {}).then(function (d) {
            var r = d.result;
            state.sites = r;
            $('wp-cli-version').textContent = r.wp_cli ? '(' + r.wp_cli + ')' : '(WP-CLI not found)';
            $('wp-sites').innerHTML = r.installs.length ? '<table class="ua-table"><thead><tr><th>Site</th><th>Version</th><th>Path</th><th></th></tr></thead><tbody>' +
                r.installs.map(function (i) {
                    return '<tr><td><strong>' + esc(i.domain) + '</strong></td><td>' + esc(i.version) + '</td><td class="ua-muted">' + esc(i.docroot) +
                        '</td><td><button class="ua-btn ua-btn-secondary wp-open" data-domain="' + esc(i.domain) + '">Manage</button></td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No WordPress installs found.</p>';
            var empty = r.other_sites.map(function (s) { return '<option value="' + esc(s) + '">' + esc(s) + '</option>'; }).join('');
            var wpOptions = r.installs.map(function (s) { return '<option value="' + esc(s.domain) + '">' + esc(s.domain) + '</option>'; }).join('');
            $('wp-clone-target').innerHTML = empty || '<option value="">(create an empty site first)</option>';
            $('wp-push-target').innerHTML = wpOptions;
            $('wp-new-site').innerHTML = empty;
            $('wp-install-card').style.display = r.other_sites.length ? 'block' : 'none';
        }).catch(function (e) { UA.showError($('wp-sites'), e); });
    }

    function badge(on, yes, no) { return '<span class="ua-badge ua-badge-' + (on ? 'pass' : 'info') + '">' + esc(on ? yes : no) + '</span>'; }

    function toggle(label, flag, on, help) {
        return '<tr><td>' + esc(label) + '</td><td>' + badge(on, 'on', 'off') + '</td><td><button class="ua-btn ua-btn-secondary wp-flag" data-flag="' +
            esc(flag) + '" data-enable="' + (on ? '0' : '1') + '">' + (on ? 'Turn off' : 'Turn on') + '</button> <span class="ua-muted">' + esc(help) + '</span></td></tr>';
    }

    function renderInfo(i) {
        state.info = i;
        $('wp-site-title').textContent = i.domain + ' — WordPress ' + i.version;
        $('wp-overview').innerHTML = '<p>Site URL <a href="' + esc(i.siteurl) + '" target="_blank" rel="noopener">' + esc(i.siteurl) + '</a>' +
            (i.core_updates.length ? ' · <span class="ua-badge ua-badge-warn">core update ' + esc(i.core_updates[0].version) + ' available</span>' : '') + '</p>' +
            '<table class="ua-table"><tbody>' +
            toggle('Maintenance mode', 'maintenance', i.maintenance, 'Visitors see a maintenance page.') +
            toggle('Search engine indexing', 'indexing', i.indexing, 'Turn off for staging sites.') +
            toggle('Debug mode (WP_DEBUG)', 'WP_DEBUG', i.flags.WP_DEBUG, 'Keep off in production.') +
            toggle('Disable file editor', 'DISALLOW_FILE_EDIT', i.flags.DISALLOW_FILE_EDIT, 'Recommended.') +
            toggle('WP-Cron from system cron', 'DISABLE_WP_CRON', i.flags.DISABLE_WP_CRON, 'Runs scheduled tasks every 5 minutes instead of on page loads.') +
            '</tbody></table>';
        function rows(kind, list) {
            return list.map(function (p) {
                var actions = (p.update === 'available' ? '<button class="ua-btn ua-btn-secondary wp-item" data-kind="' + kind + '" data-action="update" data-slug="' + esc(p.name) + '">Update to ' + esc(p.update_version) + '</button> ' : '') +
                    (p.status === 'active' ? (kind === 'plugin' ? '<button class="ua-btn ua-btn-secondary wp-item" data-kind="plugin" data-action="deactivate" data-slug="' + esc(p.name) + '">Deactivate</button> ' : '')
                        : '<button class="ua-btn ua-btn-secondary wp-item" data-kind="' + kind + '" data-action="activate" data-slug="' + esc(p.name) + '">Activate</button> ' +
                          '<button class="ua-btn ua-btn-secondary wp-item" data-kind="' + kind + '" data-action="delete" data-slug="' + esc(p.name) + '">Delete</button>');
                return '<tr><td>' + esc(kind) + '</td><td><strong>' + esc(p.name) + '</strong></td><td>' + esc(p.status) + '</td><td>' + esc(p.version) + '</td><td>' + actions + '</td></tr>';
            }).join('');
        }
        $('wp-items').innerHTML = '<table class="ua-table"><thead><tr><th></th><th>Name</th><th>Status</th><th>Version</th><th></th></tr></thead><tbody>' +
            rows('plugin', i.plugins) + rows('theme', i.themes) + '</tbody></table>';
        $('wp-auto-plugin').checked = i.plugins.length > 0 && i.plugins.every(function (p) { return p.auto_update === 'on'; });
    }

    function openSite(domain) {
        state.domain = domain;
        $('wp-site').style.display = 'block';
        $('wp-site-title').textContent = domain + ' — loading…';
        $('wp-security').innerHTML = '<p class="ua-muted">Open this tab to run the checks.</p>';
        return api('info', {domain: domain}).then(function (d) { renderInfo(d.result); })
            .catch(function (e) { UA.showError($('wp-overview'), e); });
    }

    function loadSecurity() {
        $('wp-security').innerHTML = '<p class="ua-muted">Checking (includes checksum verification against WordPress.org)…</p>';
        api('hardening', {domain: state.domain}).then(function (d) {
            $('wp-security').innerHTML = '<table class="ua-table"><tbody>' + d.result.checks.map(function (c) {
                return '<tr><td><span class="ua-badge ua-badge-' + (c.ok ? 'pass' : 'warn') + '">' + (c.ok ? 'OK' : 'Fix') + '</span></td><td>' + esc(c.title) +
                    (c.detail && !c.ok ? '<div class="ua-fix" style="white-space:pre-wrap">' + esc(c.detail) + '</div>' : '') + '</td><td>' +
                    (!c.ok && c.fix ? '<button class="ua-btn ua-btn-secondary wp-fix" data-fix="' + esc(c.fix) + '">Fix</button>' : '') + '</td></tr>';
            }).join('') + '<tr><td></td><td>Rotate security keys and salts (logs everyone out)</td><td><button class="ua-btn ua-btn-secondary wp-fix" data-fix="salts">Rotate</button></td></tr>' +
                '</tbody></table>';
        }).catch(function (e) { UA.showError($('wp-security'), e); });
    }

    function loadSnapshots() {
        api('snapshots', {domain: state.domain}).then(function (d) {
            var s = d.result.snapshots;
            $('wp-snapshots').innerHTML = s.length ? '<table class="ua-table"><tbody>' + s.map(function (x) {
                return '<tr><td><code>' + esc(x.id) + '</code></td><td>' + esc(x.label) + '</td><td>' + esc(new Date(x.created * 1000).toLocaleString()) +
                    '</td><td><button class="ua-btn ua-btn-secondary wp-rollback" data-snap="' + esc(x.id) + '">Roll back</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No snapshots yet.</p>';
        }).catch(function (e) { UA.showError($('wp-snapshots'), e); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('button');
        if (!t) { return; }
        var refresh = function () { openSite(state.domain); };
        if (t.classList.contains('wp-open')) { openSite(t.dataset.domain); window.scrollTo({top: $('wp-site').offsetTop - 20, behavior: 'smooth'}); }
        else if (t.classList.contains('wp-flag')) {
            UA.busy(t, true);
            api('flag', {domain: state.domain, flag: t.dataset.flag, enable: t.dataset.enable === '1'}).then(refresh)
                .catch(function (e) { UA.showError($('wp-overview'), e); });
        } else if (t.classList.contains('wp-item')) {
            if (t.dataset.action === 'delete' && !window.confirm('Delete ' + t.dataset.slug + '?')) { return; }
            UA.busy(t, true);
            api('item', {domain: state.domain, kind: t.dataset.kind, action: t.dataset.action, slug: t.dataset.slug}).then(refresh)
                .catch(function (e) { UA.busy(t, false); UA.showError($('wp-items'), e); });
        } else if (t.classList.contains('wp-fix')) {
            UA.busy(t, true);
            api('fix', {domain: state.domain, fix: t.dataset.fix}).then(loadSecurity).catch(function (e) { UA.showError($('wp-security'), e); });
        } else if (t.classList.contains('wp-rollback')) {
            if (window.confirm('Restore files and database from snapshot ' + t.dataset.snap + '? Changes since then are lost.')) {
                startJob('rollback', {domain: state.domain, snapshot: t.dataset.snap}, refresh);
            }
        } else if (t.dataset.update) {
            startJob('update', {domain: state.domain, scope: t.dataset.update}, refresh);
        } else if (t.dataset.perf) {
            UA.busy(t, true);
            api('performance', {domain: state.domain, what: t.dataset.perf}).then(function (d) {
                $('wp-perf-out').innerHTML = '<div class="ua-pre">' + esc(d.result.output) + '</div>';
            }).catch(function (e) { UA.showError($('wp-perf-out'), e); }).then(function () { UA.busy(t, false); });
        }
    });

    ['plugin', 'theme'].forEach(function (kind) {
        $('wp-auto-' + kind).addEventListener('change', function () {
            var box = this;
            api('autoupdates', {domain: state.domain, kind: kind, enable: box.checked})
                .catch(function (e) { box.checked = !box.checked; UA.showError($('wp-items'), e); });
        });
    });
    $('wp-install-plugin').addEventListener('click', function () {
        var slug = $('wp-install-slug').value.trim().toLowerCase(), button = this;
        UA.busy(button, true);
        api('item', {domain: state.domain, kind: 'plugin', action: 'install', slug: slug}).then(function () { openSite(state.domain); })
            .catch(function (e) { UA.showError($('wp-items'), e); }).then(function () { UA.busy(button, false); });
    });
    $('wp-refresh').addEventListener('click', function () { openSite(state.domain); });
    $('wp-login').addEventListener('click', function () {
        api('login', {domain: state.domain}).then(function (d) {
            window.open(d.result.url, '_blank', 'noopener');
            $('wp-login-out').innerHTML = '<span class="ua-muted">Opened as ' + esc(d.result.user) + ' (link valid once, 60 s).</span>';
        }).catch(function (e) { UA.showError($('wp-login-out'), e); });
    });
    $('wp-snapshot').addEventListener('click', function () { startJob('snapshot', {domain: state.domain}, loadSnapshots); });
    $('wp-clone').addEventListener('click', function () {
        var target = $('wp-clone-target').value;
        if (target && window.confirm('Copy ' + state.domain + ' into ' + target + ' (files and a new database)?')) {
            startJob('clone', {source: state.domain, target: target}, loadSites);
        }
    });
    $('wp-push').addEventListener('click', function () {
        var target = $('wp-push-target').value;
        if (target && target !== state.domain && window.confirm('Overwrite ' + target + ' with ' + state.domain + '? Production is snapshotted first.')) {
            startJob('push', {staging: state.domain, production: target});
        }
    });
    $('wp-new-install').addEventListener('click', function () {
        startJob('install', {domain: $('wp-new-site').value, title: $('wp-new-title').value.trim(),
            adminUser: $('wp-new-user').value.trim(), adminEmail: $('wp-new-email').value.trim()}, function (j) {
            loadSites();
            if (j.state === 'done') {
                $('wp-job-out').insertAdjacentHTML('afterbegin', '<p><span class="ua-badge ua-badge-pass">Installed</span> Open the site from the list and use "Log in to wp-admin", then set your password under Users &gt; Profile.</p>');
            }
        });
    });
    $('wp-cli-update').addEventListener('click', function () { startJob('wpcli', {}, loadSites); });

    loadSites();
})();
