/* Backup destinations page (every account type). Credentials are sent once, base64-encoded JSON,
   and never read back: the server returns only public settings. */
(function () {
    'use strict';
    var root = document.getElementById('ua-destinations');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/';
    var api = function (name, body) { return UA.api(base + 'ajax/' + name, body); };
    var AUTH_HOSTS = {gdrive: 'accounts.google.com', onedrive: 'login.microsoftonline.com', dropbox: 'www.dropbox.com',
                      box: 'account.box.com', pcloud: 'my.pcloud.com'};
    var state = {overview: null, providers: {}, editing: null, snapshots: null};

    function b64(object) { return window.btoa(unescape(encodeURIComponent(JSON.stringify(object)))); }
    function option(value, label) { return '<option value="' + esc(value) + '">' + esc(label) + '</option>'; }
    function badge(ok, text) { return '<span class="ua-badge ua-badge-' + (ok ? 'pass' : 'fail') + '">' + esc(text) + '</span>'; }
    function note(target, text, good) {
        target.innerHTML = '<div class="' + (good ? 'ua-muted' : 'ua-alert') + '">' + esc(text) + '</div>';
    }

    root.querySelectorAll('.ua-tabs button').forEach(function (tab) {
        tab.addEventListener('click', function () {
            root.querySelectorAll('.ua-tabs button').forEach(function (b) { b.classList.remove('active'); });
            root.querySelectorAll('.ua-pane').forEach(function (p) { p.classList.remove('active'); });
            tab.classList.add('active');
            $('pane-' + tab.dataset.pane).classList.add('active');
            if (tab.dataset.pane === 'apps') { loadApps(); }
            if (tab.dataset.pane === 'sites') { loadJobs(); }
        });
    });

    // ------------------------------------------------------------------ provider form
    function visible(field, values) {
        return Object.keys(field.show || {}).every(function (other) {
            return (field.show[other] || []).indexOf(values[other]) !== -1;
        });
    }

    function formValues() {
        var values = {};
        root.querySelectorAll('#dst-fields [data-key]').forEach(function (input) {
            values[input.dataset.key] = input.type === 'checkbox' ? input.checked : input.value;
        });
        return values;
    }

    function renderFields(keep) {
        var provider = state.providers[$('dst-provider').value];
        if (!provider) { $('dst-fields').innerHTML = ''; return; }
        var values = keep || {};
        var html = provider.fields.map(function (f) {
            var value = values[f.key] !== undefined ? values[f.key] : f['default'];
            var input;
            if (f.kind === 'select') {
                input = '<select data-key="' + esc(f.key) + '">' + f.choices.map(function (c) {
                    return '<option value="' + esc(c[0]) + '"' + (c[0] === value ? ' selected' : '') + '>' + esc(c[1]) + '</option>';
                }).join('') + '</select>';
            } else if (f.kind === 'checkbox') {
                input = '<input type="checkbox" data-key="' + esc(f.key) + '"' + (value === true ? ' checked' : '') + '>';
            } else if (f.kind === 'textarea') {
                input = '<textarea data-key="' + esc(f.key) + '" rows="5" style="min-width:420px" autocomplete="off"></textarea>';
            } else {
                input = '<input data-key="' + esc(f.key) + '" type="' + (f.kind === 'password' ? 'password' : (f.kind === 'number' ? 'number' : 'text')) +
                    '" autocomplete="' + (f.secret ? 'new-password' : 'off') + '" value="' + (f.secret ? '' : esc(value == null ? '' : value)) + '">';
            }
            var hint = f.secret && state.editing ? ' <span class="ua-muted">(leave empty to keep the saved value)</span>' : '';
            return '<div class="ua-row dst-field" data-field="' + esc(f.key) + '"><label>' + esc(f.label) + hint + ' ' + input +
                '</label>' + (f.help ? '<span class="ua-muted">' + esc(f.help) + '</span>' : '') + '</div>';
        }).join('');
        $('dst-fields').innerHTML = html;
        root.querySelectorAll('#dst-fields [data-key]').forEach(function (input) {
            input.addEventListener('change', applyVisibility);
        });
        applyVisibility();
        var oauth = provider.kind === 'oauth';
        $('dst-oauth-note').style.display = oauth ? 'block' : 'none';
        if (oauth) {
            var ready = state.overview.oauth_ready[provider.key];
            $('dst-oauth-note').textContent = ready ? 'A sign-in window opens. Allow access to finish; the destination is saved when you confirm.' :
                'The administrator has not set up ' + provider.title + ' sign-in yet' + (state.overview.is_admin ? ' (see Sign-in apps).' : '.');
        }
        $('dst-save').textContent = oauth ? (state.editing ? 'Reconnect' : 'Connect') : (state.editing ? 'Save changes' : 'Save destination');
    }

    function applyVisibility() {
        var provider = state.providers[$('dst-provider').value];
        var values = formValues();
        provider.fields.forEach(function (f) {
            var row = root.querySelector('#dst-fields [data-field="' + f.key + '"]');
            if (row) { row.style.display = visible(f, values) ? 'flex' : 'none'; }
        });
    }

    function authorizationUrlOk(provider, value) {
        try {
            var url = new URL(value);
            return url.protocol === 'https:' && url.hostname === AUTH_HOSTS[provider] && !url.port && !url.username &&
                !url.hash && url.searchParams.getAll('state').length === 1 &&
                url.searchParams.get('redirect_uri') === window.location.origin + '/addons/destinations/oauth/' + provider + '/callback';
        } catch (e) {
            return false;
        }
    }

    function connect(provider, body, button) {
        // Open the window synchronously, inside the click, so popup blockers allow it.
        var popup = window.open('about:blank', '_blank');
        if (!popup) { note($('dst-form-out'), 'Allow pop-ups for this panel, then click again.'); return; }
        popup.opener = null;
        UA.busy(button, true);
        UA.api(base + 'oauth/' + provider + '/begin', body).then(function (d) {
            if (!authorizationUrlOk(provider, d.authorization_url)) {
                popup.close();
                note($('dst-form-out'), 'The sign-in address did not match this panel (' + window.location.origin +
                    '). Open the panel by the host name registered with the provider and try again.');
                return;
            }
            popup.location.href = d.authorization_url;
            note($('dst-form-out'), 'Finish signing in in the new window, then reload this page.', true);
        }).catch(function (e) { popup.close(); UA.showError($('dst-form-out'), e); })
            .then(function () { UA.busy(button, false); });
    }

    function resetForm() {
        state.editing = null;
        $('dst-provider').disabled = false;
        $('dst-name').disabled = false;
        $('dst-name').value = '';
        $('dst-form-title').textContent = 'Add destination';
        $('dst-cancel').style.display = 'none';
        renderFields();
    }

    $('dst-provider').addEventListener('change', function () { renderFields(); });
    $('dst-cancel').addEventListener('click', resetForm);
    $('dst-save').addEventListener('click', function () {
        var provider = state.providers[$('dst-provider').value];
        var values = formValues();
        if (provider.kind === 'oauth') {
            var body = state.editing ? {destination: state.editing.id} : {name: $('dst-name').value, folder: values.folder};
            connect(provider.key, body, $('dst-save'));
            return;
        }
        var settings = {}, secrets = {};
        provider.fields.forEach(function (f) {
            if (!visible(f, values)) { return; }
            if (f.secret) { if (values[f.key]) { secrets[f.key] = values[f.key]; } } else { settings[f.key] = values[f.key]; }
        });
        var request = {provider: provider.key, name: $('dst-name').value, settings: settings, secrets: b64(secrets)};
        if (state.editing) { request.id = state.editing.id; }
        UA.busy($('dst-save'), true);
        api('save', request).then(function () {
            note($('dst-form-out'), 'Saved. Use Test to check the connection.', true);
            resetForm();
            load();
        }).catch(function (e) { UA.showError($('dst-form-out'), e); })
            .then(function () { UA.busy($('dst-save'), false); });
    });

    // ------------------------------------------------------------------ list
    function renderList() {
        var items = state.overview.destinations;
        if (!items.length) { $('dst-list').innerHTML = '<p class="ua-muted">No destinations yet. Add one below.</p>'; return; }
        $('dst-list').innerHTML = '<table class="ua-table"><tr><th>Name</th><th>Provider</th><th>Where</th><th>Status</th><th></th></tr>' +
            items.map(function (d) {
                var s = d.settings || {};
                var where = s.folder || (s.bucket ? s.bucket + (s.prefix ? '/' + s.prefix : '') : '') ||
                    ((s.user ? s.user + '@' : '') + (s.host || '') + (s.path ? ' ' + s.path : ''));
                var status = !d.connected ? badge(false, 'not connected') :
                    (d.last_test_ok === true ? badge(true, 'tested') : (d.last_test_ok === false ? badge(false, 'test failed') : '<span class="ua-badge ua-badge-info">untested</span>'));
                return '<tr><td>' + esc(d.name) + '</td><td>' + esc(d.provider_title) + '</td><td>' + esc(where) + '</td><td>' + status +
                    (d.last_test_message ? '<br><span class="ua-muted">' + esc(d.last_test_message) + '</span>' : '') + '</td><td>' +
                    '<button class="ua-btn ua-btn-secondary" data-act="test" data-id="' + d.id + '">Test</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-act="usage" data-id="' + d.id + '">Usage</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-act="edit" data-id="' + d.id + '">' + (d.kind === 'oauth' ? 'Reconnect' : 'Edit') + '</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-act="rename" data-id="' + d.id + '">Rename</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-act="delete" data-id="' + d.id + '">Delete</button></td></tr>';
            }).join('') + '</table>';
    }

    $('dst-list').addEventListener('click', function (event) {
        var button = event.target.closest('button[data-act]');
        if (!button) { return; }
        var dest = state.overview.destinations.filter(function (d) { return String(d.id) === button.dataset.id; })[0];
        var act = button.dataset.act;
        if (act === 'test' || act === 'usage') {
            UA.busy(button, true);
            api(act, {id: dest.id}).then(function (d) {
                var r = d.result;
                if (act === 'test') { note($('dst-out'), r.message, r.ok); load(); return; }
                note($('dst-out'), r.supported ? dest.name + ': ' + ['used', 'free', 'total'].filter(function (k) { return r[k + '_text']; })
                    .map(function (k) { return k + ' ' + r[k + '_text']; }).join(', ') : r.message, true);
            }).catch(function (e) { UA.showError($('dst-out'), e); }).then(function () { UA.busy(button, false); });
        } else if (act === 'rename') {
            var name = window.prompt('New name for ' + dest.name, dest.name);
            if (name && name !== dest.name) {
                api('rename', {id: dest.id, name: name}).then(load).catch(function (e) { UA.showError($('dst-out'), e); });
            }
        } else if (act === 'delete') {
            var typed = window.prompt('Delete destination "' + dest.name + '"? Its backups stay in your storage. Type the name to confirm.');
            if (typed !== dest.name) { return; }
            var purge = window.confirm('Also delete the backups stored in this destination? This cannot be undone.\n\nOK = delete the backups too, Cancel = keep them.');
            api('delete', {id: dest.id, confirm: typed, purge: purge}).then(function () {
                note($('dst-out'), 'Deleted ' + dest.name + (purge ? ' and its backups.' : '. Its backups were kept.'), true);
                load();
            }).catch(function (e) { UA.showError($('dst-out'), e); });
        } else if (act === 'edit') {
            state.editing = dest;
            $('dst-provider').value = dest.provider;
            $('dst-provider').disabled = true;
            $('dst-name').value = dest.name;
            $('dst-name').disabled = true;
            $('dst-form-title').textContent = (dest.kind === 'oauth' ? 'Reconnect ' : 'Edit ') + dest.name;
            $('dst-cancel').style.display = 'inline-block';
            renderFields(dest.settings);
            $('dst-form-title').scrollIntoView({behavior: 'smooth'});
        }
    });

    // ------------------------------------------------------------------ sites
    function loadSiteDestinations() {
        var domain = $('site-domain').value;
        $('site-dest').innerHTML = '';
        if (!domain) { return; }
        api('site_destinations', {domain: domain}).then(function (d) {
            $('site-dest').innerHTML = d.destinations.length ? d.destinations.map(function (x) {
                return option(x.id, x.name + ' (' + x.provider_title + ') - ' + x.label);
            }).join('') : option('', 'No destination available');
        }).catch(function (e) { UA.showError($('site-out'), e); });
    }
    $('site-domain').addEventListener('change', loadSiteDestinations);

    function selection() { return {domain: $('site-domain').value, destination: $('site-dest').value}; }

    function watch(jobId) {
        $('dst-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('dst-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-60).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 4000); }
            }).catch(function (e) { UA.showError($('dst-job-out'), e); });
        })();
        $('dst-job').scrollIntoView({behavior: 'smooth'});
    }

    $('job-save').addEventListener('click', function () {
        var body = selection();
        body.schedule = $('job-schedule').value;
        body.hour = $('job-hour').value;
        body.keep_daily = $('job-keep-daily').value;
        body.keep_weekly = $('job-keep-weekly').value;
        body.keep_monthly = $('job-keep-monthly').value;
        api('save_job', body).then(function () { note($('site-out'), 'Schedule saved.', true); loadJobs(); })
            .catch(function (e) { UA.showError($('site-out'), e); });
    });
    $('site-backup-now').addEventListener('click', function () {
        api('backup_now', selection()).then(function (d) { watch(d.result.job_id); })
            .catch(function (e) { UA.showError($('site-out'), e); });
    });
    $('site-snapshots').addEventListener('click', function () {
        var sel = selection();
        $('snap-card').style.display = 'block';
        $('snap-list').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('snapshots', sel).then(function (d) {
            state.snapshots = {sel: sel, databases: d.result.databases || []};
            var items = d.result.snapshots || [];
            $('snap-list').innerHTML = !items.length ? '<p class="ua-muted">No backups of this site in this destination yet.</p>' :
                '<table class="ua-table"><tr><th>Time (UTC)</th><th>What</th><th>Snapshot</th><th></th></tr>' + items.map(function (s) {
                    var what = s.unit === 'db' ? 'database ' + s.database : 'files';
                    return '<tr><td>' + esc(s.time) + '</td><td>' + esc(what) + (s.tags.indexOf('pre-restore') !== -1 ? ' (safety copy)' : '') +
                        '</td><td>' + esc(s.id) + '</td><td><button class="ua-btn ua-btn-secondary" data-snap="' + esc(s.full_id) +
                        '" data-kind="' + (s.unit === 'db' ? 'db' : 'files') + '" data-db="' + esc(s.database || '') + '">Restore</button></td></tr>';
                }).join('') + '</table>';
        }).catch(function (e) { UA.showError($('snap-list'), e); });
    });
    $('snap-list').addEventListener('click', function (event) {
        var button = event.target.closest('button[data-snap]');
        if (!button || !state.snapshots) { return; }
        var sel = state.snapshots.sel, kind = button.dataset.kind;
        var body = {domain: sel.domain, destination: sel.destination, snapshot: button.dataset.snap, kind: kind};
        if (kind === 'db') {
            body.database = button.dataset.db;
            if (!window.confirm('Replace database ' + body.database + ' with this backup? A copy of the current database is saved first.')) { return; }
        } else {
            var path = window.prompt('Restore which path? Leave /home/' + sel.domain + ' for the whole site.', '/home/' + sel.domain);
            if (path === null) { return; }
            body.include = path;
            if (!window.confirm('Restore ' + path + ' from this backup? Current files are snapshotted first.')) { return; }
        }
        api('restore', body).then(function (d) { watch(d.result.job_id); }).catch(function (e) { UA.showError($('snap-list'), e); });
    });

    function loadJobs() {
        api('jobs', {}).then(function (d) {
            $('job-list').innerHTML = !d.jobs.length ? '<p class="ua-muted">No schedules yet.</p>' :
                '<table class="ua-table"><tr><th>Website</th><th>Destination</th><th>Schedule</th><th>Keep (d/w/m)</th><th>Last run</th><th></th></tr>' +
                d.jobs.map(function (j) {
                    return '<tr><td>' + esc(j.domain) + '</td><td>' + esc(j.destination_name + ' - ' + j.label) + '</td><td>' +
                        esc(j.schedule + (j.schedule === 'daily' || j.schedule === 'weekly' ? ' at ' + j.hour + ':xx' : '')) + '</td><td>' +
                        esc(j.keep_daily + '/' + j.keep_weekly + '/' + j.keep_monthly) + '</td><td>' + esc((j.last_run || '').slice(0, 16)) +
                        ' ' + esc(j.last_status) + '</td><td><button class="ua-btn ua-btn-secondary" data-job="' + j.id + '">Delete</button></td></tr>';
                }).join('') + '</table>';
        }).catch(function (e) { UA.showError($('job-list'), e); });
    }
    $('job-list').addEventListener('click', function (event) {
        var button = event.target.closest('button[data-job]');
        if (!button || !window.confirm('Delete this schedule? Existing backups are kept.')) { return; }
        api('delete_job', {id: button.dataset.job}).then(loadJobs).catch(function (e) { UA.showError($('job-list'), e); });
    });

    // ------------------------------------------------------------------ sign-in apps (administrators)
    function loadApps() {
        api('oauth_clients', {}).then(renderApps).catch(function (e) { UA.showError($('apps-list'), e); });
    }
    function renderApps(d) {
        $('apps-list').innerHTML = d.providers.map(function (p) {
            return '<div class="ua-card" data-app="' + esc(p.provider) + '"><h3>' + esc(p.title) + ' ' + badge(p.configured, p.configured ? 'set up' : 'not set up') + '</h3>' +
                '<ol>' + p.steps.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ol>' +
                '<p>Redirect URI: <code>' + esc(p.redirect_uri) + '</code> &middot; <a href="' + esc(p.console) + '" target="_blank" rel="noopener">Open the provider console</a>' +
                (p.pkce ? ' &middot; PKCE' : '') + '</p>' + (p.error ? '<div class="ua-alert">' + esc(p.error) + '</div>' : '') +
                '<div class="ua-row"><input data-f="client_id" placeholder="Client ID" autocomplete="off" value="' + esc(p.client_id) + '">' +
                '<input data-f="client_secret" type="password" autocomplete="new-password" placeholder="Client secret (' + esc(p.client_secret) + ')">' +
                '<button class="ua-btn" data-app-save="' + esc(p.provider) + '">Save</button>' +
                (p.configured ? ' <button class="ua-btn ua-btn-secondary" data-app-clear="' + esc(p.provider) + '">Remove</button>' : '') + '</div></div>';
        }).join('');
    }
    $('apps-list').addEventListener('click', function (event) {
        var save = event.target.closest('button[data-app-save]'), clear = event.target.closest('button[data-app-clear]');
        if (!save && !clear) { return; }
        var provider = (save || clear).dataset[save ? 'appSave' : 'appClear'];
        var card = root.querySelector('[data-app="' + provider + '"]');
        var body = {provider: provider};
        if (clear) {
            if (!window.confirm('Remove this sign-in app? Connected destinations stop working until it is set up again.')) { return; }
            body.clear = true;
        } else {
            body.client_id = card.querySelector('[data-f="client_id"]').value;
            body.client_secret_b64 = b64({client_secret: card.querySelector('[data-f="client_secret"]').value});
        }
        api('oauth_clients', body).then(function (d) { renderApps(d); load(); }).catch(function (e) { UA.showError(card, e); });
    });

    // ------------------------------------------------------------------ load
    function load() {
        return api('overview', {}).then(function (d) {
            state.overview = d;
            state.providers = {};
            d.providers.forEach(function (p) { state.providers[p.key] = p; });
            if (!$('dst-provider').options.length) {
                $('dst-provider').innerHTML = d.providers.map(function (p) { return option(p.key, p.title); }).join('');
                var wanted = new URLSearchParams(window.location.search).get('provider');
                if (wanted && state.providers[wanted]) { $('dst-provider').value = wanted; }
                renderFields();
            }
            if (!$('site-domain').options.length) {
                $('site-domain').innerHTML = option('', 'Choose a website…') + d.sites.map(function (s) { return option(s, s); }).join('');
            }
            $('tab-apps').style.display = d.is_admin ? 'inline-block' : 'none';
            renderList();
        }).catch(function (e) { UA.showError($('dst-list'), e); });
    }
    load();
    api('tools', {}).then(function (d) {
        if (!d.result.rclone) { $('dst-tools').innerHTML = '<div class="ua-alert">rclone is not installed on this server, so destinations cannot be tested or used yet. Ask the administrator to install rclone (https://rclone.org/install/).</div>'; }
    }).catch(function () {});
}());
