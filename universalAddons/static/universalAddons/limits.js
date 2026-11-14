(function () {
    'use strict';
    var root = document.getElementById('ua-limits');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {data: null, editing: null, preview: null};
    var SHORT = {mem_soft_mb: 'mem soft', mem_hard_mb: 'mem hard', proc_soft: 'proc soft', proc_hard: 'proc hard',
                 max_conns: 'conns', children: 'workers', instances: 'inst', init_timeout: 'init', retry_timeout: 'retry', priority: 'nice'};

    function human(kb) {
        var units = ['KB', 'MB', 'GB', 'TB'], i = 0;
        kb = Number(kb || 0);
        while (kb >= 1024 && i < units.length - 1) { kb /= 1024; i += 1; }
        return (i < 2 ? kb.toFixed(0) : kb.toFixed(1)) + ' ' + units[i];
    }
    function compact(limits, keys) {
        limits = limits || {};
        return (keys || Object.keys(SHORT)).filter(function (k) { return limits[k] !== undefined && limits[k] !== null; }).map(function (k) {
            return '<span class="ua-muted">' + esc(SHORT[k]) + '</span> ' + esc(limits[k]) + (k.indexOf('mem_') === 0 ? 'M' : '');
        }).join(' &middot; ') || '<span class="ua-muted">defaults</span>';
    }

    function watch(jobId, done) {
        $('lim-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }, function (e, n) {
                $('lim-job-out').innerHTML = '<p class="ua-muted">The panel is busy (' + esc(e.message) + '); reconnecting, attempt ' + n +
                    '. The job keeps running on the server.</p>';
            }).then(function (d) {
                var j = d.result;
                $('lim-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (done) { done(j); }
            }).catch(function (e) {
                UA.showError($('lim-job-out'), e);
                var again = document.createElement('button');
                again.type = 'button';
                again.className = 'ua-btn ua-btn-secondary';
                again.textContent = 'Check again';
                again.onclick = function () { watch(jobId, done); };
                $('lim-job-out').appendChild(again);
            });
        })();
    }

    function renderHost(d) {
        var h = d.host, q = d.quota, c = d.cgroup;
        $('lim-host').innerHTML = '<table class="ua-table"><tbody>' +
            '<tr><td><strong>RAM / CPU</strong></td><td>' + esc(h.total_mb) + ' MB, ' + esc(h.cores) + ' core(s)</td></tr>' +
            '<tr><td><strong>Defaults for this size</strong></td><td>' + compact(d.defaults) + '</td></tr>' +
            '<tr><td><strong>Enforced</strong></td><td><span class="ua-badge ua-badge-pass">yes</span> memory per PHP process (RLIMIT_AS), ' +
            'processes of the site user (RLIMIT_NPROC), concurrent connections and PHP workers. Workers are the effective CPU cap: ' +
            'one site can keep at most that many PHP processes busy.</td></tr>' +
            '<tr><td><strong>CPU quota</strong></td><td><span class="ua-badge ua-badge-' + (c.cgroup_v2 ? 'info' : 'warn') + '">' +
            (c.cgroup_v2 ? 'cgroup v2' : 'cgroup v1') + '</span> ' + esc(c.note) + '</td></tr>' +
            '<tr><td><strong>Disk quota</strong></td><td>' + (q.usrquota ? '<span class="ua-badge ua-badge-pass">usrquota</span> ' : '<span class="ua-badge ua-badge-warn">no usrquota</span> ') +
            (q.grpquota ? '<span class="ua-badge ua-badge-pass">grpquota</span> ' : '') + 'report only, nothing is changed.</td></tr>' +
            '</tbody></table>';
    }

    function renderPackages(d) {
        $('lim-packages').innerHTML = '<table class="ua-table"><thead><tr><th>Package</th><th>Sites</th><th>Profile</th><th></th></tr></thead><tbody>' +
            d.packages.map(function (p, n) {
                return '<tr><td><strong>' + esc(p.name) + '</strong></td><td>' + esc(p.sites) + '</td><td>' + compact(p.profile) + '</td><td style="white-space:nowrap">' +
                    '<button class="ua-btn ua-btn-secondary lim-edit" data-scope="package" data-n="' + n + '">Edit</button> ' +
                    (p.sites ? '<button class="ua-btn ua-btn-secondary lim-preview" data-scope="package" data-n="' + n + '">Preview</button>' : '') + '</td></tr>';
            }).join('') + '</tbody></table>';
    }

    function usageCell(u) {
        if (!u) { return '<span class="ua-muted">-</span>'; }
        return esc(u.lsphp) + ' lsphp, ' + esc(human(u.rss_kb)) + '<div class="ua-muted">' + esc(u.tasks) + ' tasks</div>';
    }
    function diskCell(s) {
        var parts = [];
        if (s.quota) {
            parts.push(esc(human(s.quota.kb)) + (s.quota.kb_hard ? ' / ' + esc(human(s.quota.kb_hard)) : '') + ' <span class="ua-muted">quota</span>');
            parts.push(esc(s.quota.files) + (s.quota.files_hard ? ' / ' + esc(s.quota.files_hard) : '') + ' <span class="ua-muted">inodes</span>');
        }
        if (s.du) { parts.push(esc(human(s.du.kb)) + ' <span class="ua-muted">du ' + esc(new Date(s.du.at * 1000).toLocaleDateString()) + '</span>'); }
        return parts.join('<br>') || '<span class="ua-muted">-</span>';
    }

    function renderSites() {
        var d = state.data, filter = ($('lim-filter').value || '').toLowerCase();
        var keys = ['mem_soft_mb', 'mem_hard_mb', 'proc_soft', 'proc_hard', 'max_conns', 'children'];
        $('lim-sites').innerHTML = '<table class="ua-table"><thead><tr><th>Site</th><th>Package</th><th>Effective</th><th>Current (vhost.conf)</th><th>Usage now</th><th>Disk</th><th></th></tr></thead><tbody>' +
            d.sites.map(function (s, n) {
                if (filter && s.domain.indexOf(filter) < 0 && s.package.toLowerCase().indexOf(filter) < 0) { return ''; }
                var status = s.error ? '<div class="ua-fix">' + esc(s.error) + '</div>' :
                    (s.drift.length ? '<span class="ua-badge ua-badge-warn">differs</span>' : '<span class="ua-badge ua-badge-pass">applied</span>');
                return '<tr><td><strong>' + esc(s.domain) + '</strong><div class="ua-muted">' + esc(s.user) + (s.php ? ' &middot; ' + esc(s.php) : '') + '</div></td>' +
                    '<td>' + esc(s.package) + '</td><td>' + compact(s.effective) + (Object.keys(s.override || {}).length ? '<div class="ua-muted">site override</div>' : '') + '</td>' +
                    '<td>' + (s.current ? compact(s.current, keys) : '') + ' ' + status + '</td><td>' + usageCell(s.usage) + '</td><td>' + diskCell(s) + '</td>' +
                    '<td style="white-space:nowrap"><button class="ua-btn ua-btn-secondary lim-edit" data-scope="site" data-n="' + n + '">Override</button> ' +
                    (s.error || s.state !== 1 ? '' : '<button class="ua-btn ua-btn-secondary lim-preview" data-scope="site" data-n="' + n + '">Preview</button>') + '</td></tr>';
            }).join('') + '</tbody></table>';
    }

    function renderQuota(d) {
        var q = d.quota;
        $('lim-quota').innerHTML = '<table class="ua-table"><tbody>' +
            '<tr><td><strong>/ mount options</strong></td><td><code>' + esc((q.mount_options || []).join(',')) + '</code></td></tr>' +
            '<tr><td><strong>/etc/fstab</strong></td><td><code>' + esc((q.fstab_options || []).join(',')) + '</code></td></tr>' +
            '<tr><td><strong>repquota</strong></td><td>' + (q.repquota ? '<code>' + esc(q.repquota) + '</code>' : 'not installed') + '</td></tr>' +
            '<tr><td><strong>State</strong></td><td><div class="ua-pre">' + esc(q.state || 'unknown') + '</div></td></tr>' +
            '</tbody></table><p class="ua-muted">Per-site block and inode usage from quotas is shown in the Sites table. ' +
            'This page never remounts or enables quotas.</p>';
        $('lim-du-note').textContent = d.du_scanned ? 'Last measured ' + new Date(d.du_scanned * 1000).toLocaleString() + '.' :
            'Not measured yet. Runs in the background at idle priority; results are cached.';
    }

    function load() {
        return api('overview', {}).then(function (d) {
            state.data = d.result;
            renderHost(state.data);
            renderPackages(state.data);
            renderSites();
            renderQuota(state.data);
        }).catch(function (e) { UA.showError($('lim-host'), e); });
    }

    function target(button) {
        var n = Number(button.dataset.n), scope = button.dataset.scope;
        var item = scope === 'package' ? state.data.packages[n] : state.data.sites[n];
        return {scope: scope, name: scope === 'package' ? item.name : item.domain, item: item};
    }

    function openEditor(t) {
        state.editing = t;
        var profile = t.scope === 'package' ? t.item.profile : t.item.override;
        var inherited = t.scope === 'site' ? t.item.effective : state.data.defaults;
        $('lim-editor-title').textContent = (t.scope === 'package' ? 'Package profile: ' : 'Site override: ') + t.name;
        $('lim-form').innerHTML = '<thead><tr><th>Limit</th><th>OpenLiteSpeed key</th><th>Value</th><th>Inherited</th></tr></thead><tbody>' +
            state.data.fields.map(function (f) {
                var value = profile && profile[f.key] !== undefined ? profile[f.key] : '';
                return '<tr><td>' + esc(f.label) + '</td><td><code>' + esc(f.ols === 'children' ? 'env LSAPI_CHILDREN' : f.ols) + '</code></td>' +
                    '<td><input type="number" class="lim-field" data-key="' + esc(f.key) + '" min="' + esc(f.min) + '" max="' + esc(f.max) +
                    '" value="' + esc(value) + '" style="min-width:110px"></td><td class="ua-muted">' +
                    esc(inherited && inherited[f.key] !== undefined ? inherited[f.key] : 'unchanged') + ' <span>(' + esc(f.min) + '-' + esc(f.max) + ')</span></td></tr>';
            }).join('') + '</tbody>';
        $('lim-editor-note').textContent = '';
        $('lim-editor').style.display = 'block';
        $('lim-editor').scrollIntoView({behavior: 'smooth'});
    }

    function saveProfile(clear) {
        var limits = {};
        if (!clear) {
            root.querySelectorAll('.lim-field').forEach(function (input) {
                if (input.value !== '') { limits[input.dataset.key] = Number(input.value); }
            });
        }
        var button = clear ? $('lim-clear') : $('lim-save');
        UA.busy(button, true);
        api('save', {scope: state.editing.scope, name: state.editing.name, limits: limits}).then(function () {
            UA.busy(button, false);
            $('lim-editor-note').textContent = 'Saved. Preview to see what changes in vhost.conf.';
            return load();
        }).catch(function (e) { UA.busy(button, false); $('lim-editor-note').textContent = e.message; });
    }

    function showPreview(t) {
        $('lim-preview').style.display = 'block';
        $('lim-preview-title').textContent = t.scope + ' ' + t.name;
        $('lim-preview-out').innerHTML = '<p class="ua-muted">Computing…</p>';
        $('lim-apply').disabled = true;
        api('preview', {scope: t.scope, name: t.name}).then(function (d) {
            var r = d.result;
            state.preview = r;
            $('lim-preview-out').innerHTML = '<p>' + esc(r.changed) + ' of ' + esc(r.plans.length) + ' site(s) would change.</p>' +
                r.plans.map(function (p) {
                    return '<div style="margin-bottom:10px"><strong>' + esc(p.domain) + '</strong> ' +
                        (p.error ? '<span class="ua-badge ua-badge-fail">skipped</span> ' + esc(p.error) :
                            (p.changed ? '<span class="ua-badge ua-badge-info">changes</span>' : '<span class="ua-badge ua-badge-pass">already applied</span>')) +
                        p.warnings.map(function (w) { return '<div class="ua-fix">&#9888; ' + esc(w) + '</div>'; }).join('') +
                        (p.diff ? '<div class="ua-pre">' + esc(p.diff) + '</div>' : '') + '</div>';
                }).join('');
            $('lim-apply').disabled = !r.changed;
        }).catch(function (e) { UA.showError($('lim-preview-out'), e); });
    }

    $('lim-apply').addEventListener('click', function () {
        var p = state.preview, button = this;
        if (!p || !window.confirm('Apply the new limits to ' + p.changed + ' site(s) and gracefully restart OpenLiteSpeed?')) { return; }
        UA.busy(button, true);
        api('apply', {scope: p.scope, name: p.name, token: p.token}).then(function (d) {
            watch(d.result.job_id, function () { UA.busy(button, false); button.disabled = true; load(); });
        }).catch(function (e) { UA.busy(button, false); UA.showError($('lim-preview-out'), e); });
    });

    root.addEventListener('click', function (e) {
        var button = e.target.closest('button');
        if (!button) { return; }
        if (button.classList.contains('lim-edit')) { openEditor(target(button)); }
        if (button.classList.contains('lim-preview')) { showPreview(target(button)); }
    });
    $('lim-save').addEventListener('click', function () { saveProfile(false); });
    $('lim-clear').addEventListener('click', function () { if (window.confirm('Remove this profile? Its sites fall back to the next level.')) { saveProfile(true); } });
    $('lim-cancel').addEventListener('click', function () { $('lim-editor').style.display = 'none'; });
    $('lim-filter').addEventListener('input', function () { if (state.data) { renderSites(); } });
    $('lim-du').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('du_scan', {}).then(function (d) {
            watch(d.result.job_id, function () { UA.busy(button, false); load(); });
        }).catch(function (e) { UA.busy(button, false); UA.showError($('lim-job-out'), e); $('lim-job').style.display = 'block'; });
    });

    load();
})();
