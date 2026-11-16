(function () {
    'use strict';
    var root = document.getElementById('ua-sitetools');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {domain: '', info: null, sites: [], redirects: [], code: null};

    function badge(kind, text) { return '<span class="ua-badge ua-badge-' + kind + '">' + esc(text) + '</span>'; }
    function list(value) { return String(value || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean); }
    function done(text) { $('stt-out').innerHTML = '<p>' + badge('pass', 'Done') + ' ' + esc(text) + '</p>'; }
    function fail(e) { UA.showError($('stt-out'), e); }
    function body(extra) { var b = {domain: state.domain}; Object.keys(extra || {}).forEach(function (k) { b[k] = extra[k]; }); return b; }

    root.querySelectorAll('#stt-main .ua-tabs button').forEach(function (tab) {
        tab.addEventListener('click', function () {
            root.querySelectorAll('#stt-main .ua-tabs button').forEach(function (b) { b.classList.remove('active'); });
            root.querySelectorAll('#stt-main .ua-pane').forEach(function (p) { p.classList.remove('active'); });
            tab.classList.add('active');
            $('stt-pane-' + tab.dataset.pane).classList.add('active');
            $('stt-out').innerHTML = '';
        });
    });

    function watch(jobId, after) {
        $('stt-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('stt-job-out').innerHTML = '<p>' + esc(j.step || '') + ' ' + badge(j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail'), j.state) + '</p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-150).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (after) { after(j); }
            }).catch(function (e) { UA.showError($('stt-job-out'), e); });
        })();
        $('stt-job').scrollIntoView({behavior: 'smooth'});
    }
    function startJob(name, payload, button) {
        UA.busy(button, true);
        return api(name, payload).then(function (d) { watch(d.result.job_id, function () { load(); }); })
            .catch(fail).then(function () { UA.busy(button, false); });
    }

    function loadSites() {
        return api('sites', {}).then(function (d) {
            state.sites = d.result.sites;
            var wanted = root.dataset.site;
            $('stt-site').innerHTML = state.sites.length ? state.sites.map(function (s) {
                return '<option' + (s === wanted ? ' selected' : '') + '>' + esc(s) + '</option>';
            }).join('') : '<option value="">No sites</option>';
            if (state.sites.length) { select($('stt-site').value); }
        }).catch(function (e) { UA.showError($('stt-wp'), e); });
    }

    function select(domain) {
        state.domain = domain;
        $('stt-target').innerHTML = state.sites.filter(function (s) { return s !== domain; })
            .map(function (s) { return '<option>' + esc(s) + '</option>'; }).join('');
        $('stt-label-domain').textContent = '.' + domain;
        load();
    }

    function load() {
        if (!state.domain) { return; }
        return api('overview', {domain: state.domain}).then(function (d) {
            var r = state.info = d.result;
            $('stt-main').style.display = 'block';
            $('stt-docroot').textContent = r.docroot;
            $('stt-wp').innerHTML = r.wordpress ? '<p>' + badge('info', 'WordPress') + ' This site runs WordPress. Use the <a href="' + esc(r.wordpress_url) +
                '?site=' + encodeURIComponent(r.domain) + '">WordPress add-on</a> to clone it to staging and push it back; the other tools below work for it as usual.</p>' : '';
            renderStaging(r); renderAuth(r); renderErrors(r);
            state.redirects = r.redirects.slice(); renderRedirects();
            var h = r.hotlink;
            $('stt-hl-enabled').checked = !!h.enabled; $('stt-hl-domains').value = (h.domains || []).join(', ');
            $('stt-hl-ext').value = (h.extensions || []).join(', '); $('stt-hl-empty').checked = h.allow_empty !== false;
            $('stt-hl-redirect').value = h.redirect || '';
        }).catch(fail);
    }

    function renderStaging(r) {
        var s = r.staging, html = '';
        if (s.live) { html += '<p>' + badge('info', 'staging') + ' This is a staging copy of <strong>' + esc(s.live) + '</strong>.</p>'; }
        if (s.copies.length) { html += '<p>Staging copies of this site: ' + s.copies.map(function (c) { return '<a href="?site=' + encodeURIComponent(c) + '">' + esc(c) + '</a>'; }).join(', ') + '</p>'; }
        $('stt-staging-info').innerHTML = html;
        $('stt-push-box').style.display = s.live ? 'block' : 'none';
        $('stt-clone').disabled = !!r.wordpress;
        $('stt-dbs').innerHTML = r.databases.length ? 'Databases: ' + r.databases.map(function (db) {
            return '<label><input type="checkbox" class="stt-db" value="' + esc(db.name) + '"' + (db.used ? ' checked' : '') + '> ' + esc(db.name) +
                (db.used ? ' <span class="ua-muted">(used by the site)</span>' : '') + '</label>';
        }).join(' ') : '<span class="ua-muted">The panel lists no databases for this site.</span>';
        $('stt-backups').innerHTML = r.backups.length ? '<table class="ua-table"><tbody>' + r.backups.map(function (b) {
            return '<tr><td>' + esc(new Date(b.created * 1000).toLocaleString()) + '</td><td>' + esc(b.label) + '</td><td>' + (b.files ? 'files ' : '') +
                esc((b.dbs || []).join(', ')) + '</td><td><button class="ua-btn ua-btn-secondary stt-restore" data-id="' + esc(b.id) + '">Restore</button></td></tr>';
        }).join('') + '</tbody></table>' : '<p class="ua-muted">None.</p>';
    }

    function renderAuth(r) {
        $('stt-auth-list').innerHTML = r.auth.length ? '<table class="ua-table"><thead><tr><th>Directory</th><th>Users</th><th></th></tr></thead><tbody>' + r.auth.map(function (a) {
            return '<tr><td><strong>/' + esc(a.path) + '</strong><div class="ua-muted">' + esc(a.name) + '</div></td><td>' + a.users.map(function (u) {
                return esc(u) + ' <a href="#" class="stt-user-rm" data-path="' + esc(a.path) + '" data-user="' + esc(u) + '">remove</a>';
            }).join('<br>') + '<div class="ua-row" style="margin-top:6px"><input class="stt-nu" placeholder="user" style="min-width:120px"><input class="stt-np" type="password" placeholder="password" style="min-width:140px" autocomplete="new-password">' +
                '<button class="ua-btn ua-btn-secondary stt-user-set" data-path="' + esc(a.path) + '">Add / change</button></div></td><td><button class="ua-btn ua-btn-secondary stt-unprotect" data-path="' +
                esc(a.path) + '">Remove protection</button></td></tr>';
        }).join('') + '</tbody></table>' : '<p class="ua-muted">No protected directories.</p>';
    }

    function renderErrors(r) {
        $('stt-errors-list').innerHTML = '<table class="ua-table"><tbody>' + r.errorpages.map(function (p) {
            return '<tr><td><strong>' + esc(p.code) + '</strong></td><td>' + (p.active ? badge('pass', 'custom') : badge('info', 'default')) + '</td><td>' +
                '<button class="ua-btn ua-btn-secondary stt-err-edit" data-code="' + esc(p.code) + '">Edit</button> ' +
                (p.active ? '<button class="ua-btn ua-btn-secondary stt-err-rm" data-code="' + esc(p.code) + '">Use the default</button>' : '') + '</td></tr>';
        }).join('') + '</tbody></table>';
    }

    function renderRedirects() {
        $('stt-redirect-rows').innerHTML = state.redirects.map(function (r, i) {
            return '<tr data-i="' + i + '"><td><select class="stt-r-code"><option' + (r.code === '301' ? ' selected' : '') + '>301</option><option' + (r.code === '302' ? ' selected' : '') + '>302</option></select></td>' +
                '<td><select class="stt-r-kind"><option value="path"' + (r.kind === 'path' ? ' selected' : '') + '>path</option><option value="regex"' + (r.kind === 'regex' ? ' selected' : '') + '>regex</option></select></td>' +
                '<td><input class="stt-r-source" value="' + esc(r.source) + '" placeholder="/old-page"></td><td><input class="stt-r-target" value="' + esc(r.target) + '" placeholder="/new-page or https://…"></td>' +
                '<td><button class="ua-btn ua-btn-secondary stt-r-del">Delete</button></td></tr>';
        }).join('') || '<tr><td colspan="5" class="ua-muted">No redirects.</td></tr>';
    }
    function readRedirects() {
        return Array.prototype.map.call(root.querySelectorAll('#stt-redirect-rows tr[data-i]'), function (row) {
            return {code: row.querySelector('.stt-r-code').value, kind: row.querySelector('.stt-r-kind').value,
                    source: row.querySelector('.stt-r-source').value.trim(), target: row.querySelector('.stt-r-target').value.trim()};
        });
    }

    function editError(code) {
        state.code = code;
        api('errorpage_get', body({code: code})).then(function (d) {
            $('stt-error-edit').style.display = 'block';
            $('stt-error-title').textContent = code + (d.result.exists ? '' : ' (starting from a default page)');
            $('stt-error-html').value = d.result.html;
        }).catch(fail);
    }

    $('stt-site').addEventListener('change', function () { select(this.value); });
    $('stt-error-file').addEventListener('change', function () {
        var file = this.files[0];
        if (!file) { return; }
        if (file.size > 256 * 1024) { fail(new Error('The page must be at most 256 KB.')); return; }
        var reader = new FileReader();
        reader.onload = function () { $('stt-error-html').value = reader.result; };
        reader.readAsText(file);
    });

    root.addEventListener('click', function (event) {
        var t = event.target, b;
        if ((b = t.closest('.stt-r-del'))) { state.redirects = readRedirects(); state.redirects.splice(+b.closest('tr').dataset.i, 1); renderRedirects(); return; }
        if ((b = t.closest('.stt-err-edit'))) { editError(b.dataset.code); return; }
        if ((b = t.closest('.stt-err-rm'))) {
            if (!window.confirm('Go back to the default ' + b.dataset.code + ' page?')) { return; }
            UA.busy(b, true);
            api('errorpage_remove', body({code: b.dataset.code})).then(function () { done('Default page restored.'); load(); }).catch(fail);
            return;
        }
        if ((b = t.closest('.stt-unprotect'))) {
            if (!window.confirm('Remove the password protection of /' + b.dataset.path + '?')) { return; }
            UA.busy(b, true);
            api('unprotect', body({path: b.dataset.path})).then(function () { done('Protection removed.'); load(); }).catch(fail);
            return;
        }
        if ((b = t.closest('.stt-user-set'))) {
            var row = b.closest('td');
            UA.busy(b, true);
            api('user_set', body({path: b.dataset.path, username: row.querySelector('.stt-nu').value.trim(), password: row.querySelector('.stt-np').value,
                                   scheme: $('stt-auth-scheme').value})).then(function () { done('User saved.'); load(); }).catch(fail)
                .then(function () { UA.busy(b, false); });
            return;
        }
        if ((b = t.closest('.stt-user-rm'))) {
            event.preventDefault();
            if (!window.confirm('Remove ' + b.dataset.user + '?')) { return; }
            api('user_remove', body({path: b.dataset.path, username: b.dataset.user})).then(function () { done('User removed.'); load(); }).catch(fail);
            return;
        }
        if ((b = t.closest('.stt-restore'))) {
            if (!window.confirm('Restore backup ' + b.dataset.id + ' over ' + state.domain + '?')) { return; }
            startJob('restore', body({backup: b.dataset.id}), b);
        }
    });

    $('stt-redirect-add').addEventListener('click', function () {
        state.redirects = readRedirects();
        state.redirects.push({code: '301', kind: 'path', source: '', target: ''});
        renderRedirects();
    });
    $('stt-redirect-save').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('redirects', body({rules: readRedirects()})).then(function (d) {
            done(d.result.changed ? 'Redirects saved; OpenLiteSpeed restarted gracefully.' : 'Nothing needed changing.'); load();
        }).catch(fail).then(function () { UA.busy(button, false); });
    });
    $('stt-hl-save').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('hotlink', body({config: {enabled: $('stt-hl-enabled').checked, domains: list($('stt-hl-domains').value),
                                      extensions: list($('stt-hl-ext').value), allow_empty: $('stt-hl-empty').checked,
                                      redirect: $('stt-hl-redirect').value.trim()}})).then(function (d) {
            done(d.result.changed ? 'Hotlink protection saved.' : 'Nothing needed changing.'); load();
        }).catch(fail).then(function () { UA.busy(button, false); });
    });
    $('stt-error-save').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('errorpage_save', body({code: state.code, html: $('stt-error-html').value})).then(function () {
            done('Error page ' + state.code + ' saved and in use.'); load();
        }).catch(fail).then(function () { UA.busy(button, false); });
    });
    $('stt-auth-add').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('protect', body({path: $('stt-auth-path').value.trim(), name: $('stt-auth-name').value.trim(), username: $('stt-auth-user').value.trim(),
                             password: $('stt-auth-pass').value, scheme: $('stt-auth-scheme').value})).then(function () {
            $('stt-auth-pass').value = ''; done('Directory protected.'); load();
        }).catch(fail).then(function () { UA.busy(button, false); });
    });
    $('stt-clone').addEventListener('click', function () {
        var mode = root.querySelector('input[name=stt-mode]:checked').value;
        var target = mode === 'site' ? $('stt-target').value : $('stt-label').value.trim() + '.' + state.domain;
        if (!window.confirm('Copy ' + state.domain + ' into ' + target + '?')) { return; }
        startJob('clone', {source: state.domain, mode: mode, label: $('stt-label').value.trim(), target: $('stt-target').value,
                           databases: Array.prototype.map.call(root.querySelectorAll('.stt-db:checked'), function (c) { return c.value; }),
                           exclude_cache: $('stt-clone-cache').checked, excludes: list($('stt-clone-excludes').value)}, this);
    });
    $('stt-push').addEventListener('click', function () {
        if (!window.confirm('Push ' + state.domain + ' over the live site ' + state.info.staging.live + '?')) { return; }
        startJob('push', {staging: state.domain, push_files: $('stt-push-files').checked, push_db: $('stt-push-db').checked,
                          backup_files: $('stt-backup-files').checked, backup_db: $('stt-backup-db').checked,
                          exclude_cache: $('stt-push-cache').checked, exclude_uploads: $('stt-push-uploads').checked,
                          excludes: list($('stt-push-excludes').value)}, this);
    });

    loadSites();
})();
