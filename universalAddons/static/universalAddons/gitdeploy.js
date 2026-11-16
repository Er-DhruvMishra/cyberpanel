(function () {
    'use strict';
    var root = document.getElementById('ua-gitdeploy');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {domain: '', status: null};

    function badge(kind, text) { return '<span class="ua-badge ua-badge-' + kind + '">' + esc(text) + '</span>'; }
    function auth() { var c = root.querySelector('input[name="gd-auth"]:checked'); return c ? c.value : 'public'; }
    function setAuth(value) { root.querySelectorAll('input[name="gd-auth"]').forEach(function (r) { r.checked = r.value === value; }); authChanged(); }
    function authChanged() { $('gd-token-row').style.display = auth() === 'token' ? 'flex' : 'none'; }
    function modeChanged() { $('gd-keep-row').style.display = $('gd-mode').value === 'releases' ? '' : 'none'; }
    root.querySelectorAll('input[name="gd-auth"]').forEach(function (r) { r.addEventListener('change', authChanged); });
    $('gd-mode').addEventListener('change', modeChanged);

    function watch(jobId, after) {
        $('gd-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('gd-job-out').innerHTML = '<p>' + esc(j.step || '') + ' ' + badge(j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail'), j.state) + '</p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-150).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (after) { after(j); }
            }).catch(function (e) { UA.showError($('gd-job-out'), e); });
        })();
        $('gd-job').scrollIntoView({behavior: 'smooth'});
    }

    function render(s) {
        state.status = s;
        $('gd-settings').style.display = 'block';
        $('gd-steps').innerHTML = s.steps.map(function (step) {
            return '<label><input type="checkbox" class="gd-step" value="' + esc(step.key) + '"> ' + esc(step.title) + '</label>';
        }).join('');
        $('gd-app').innerHTML = '<option value="">(none)</option>' + s.apps.map(function (a) { return '<option>' + esc(a) + '</option>'; }).join('');
        var c = s.config;
        $('gd-overview').style.display = c ? 'block' : 'none';
        $('gd-webhook-card').style.display = c ? 'block' : 'none';
        $('gd-disconnect').style.display = c ? '' : 'none';
        $('gd-secret').textContent = '';
        $('gd-site-state').textContent = c ? 'Connected to ' + c.url + ' (' + c.branch + ')' : 'No repository connected yet.';
        if (!c) {
            $('gd-url').value = ''; $('gd-branch').value = 'main'; $('gd-target').value = s.default_target; $('gd-mode').value = 'pull';
            setAuth('public'); modeChanged(); $('gd-key-card').style.display = 'none';
            return;
        }
        $('gd-url').value = c.url; $('gd-branch').value = c.branch; $('gd-target').value = c.target; $('gd-mode').value = c.mode;
        $('gd-keep').value = c.keep; $('gd-token-user').value = c.token_user || ''; $('gd-script').checked = !!c.custom_script;
        $('gd-script-timeout').value = c.script_timeout || 600; $('gd-app').value = c.restart_app || '';
        root.querySelectorAll('.gd-step').forEach(function (box) { box.checked = c.steps.indexOf(box.value) >= 0; });
        setAuth(c.auth); modeChanged();
        $('gd-token-state').textContent = s.has_token ? 'A token is saved; leave empty to keep it.' : '';
        $('gd-key-card').style.display = c.auth === 'key' ? 'block' : 'none';
        $('gd-key').textContent = s.public_key || '(no key yet)';
        $('gd-webhook').innerHTML = '<p><code>' + esc(s.hook_url) + '</code></p>';
        $('gd-summary').innerHTML = '<p>' + esc(c.mode === 'releases' ? 'Releases in ~/.indianscloud/deploy, current: ' + (s.current || 'none yet') : 'Git working tree in ' + c.target) +
            (s.deploying ? ' ' + badge('info', 'deploying now') : '') + '</p>';
        $('gd-rollback').style.display = c.mode === 'releases' && (s.releases || []).length > 1 ? '' : 'none';
        var history = s.history || [];
        $('gd-history').innerHTML = history.length ? '<table class="ua-table"><thead><tr><th>#</th><th>When</th><th>Trigger</th><th>Result</th><th>Commit</th><th></th></tr></thead><tbody>' +
            history.map(function (h) {
                return '<tr><td>' + h.n + '</td><td>' + esc(new Date(h.ts * 1000).toLocaleString()) + '</td><td>' + esc(h.trigger) + '</td><td>' +
                    badge(h.state === 'ok' ? 'pass' : 'fail', h.state) + (h.error ? ' <span class="ua-muted">' + esc(h.error) + '</span>' : '') + '</td><td><code>' +
                    esc((h.commit || '').slice(0, 10)) + '</code>' + (h.release ? ' <span class="ua-muted">' + esc(h.release) + '</span>' : '') +
                    '</td><td><button class="ua-btn ua-btn-secondary gd-log" data-n="' + h.n + '">Log</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No deploys yet.</p>';
    }

    function load() {
        state.domain = $('gd-site').value;
        if (!state.domain) { return Promise.resolve(); }
        $('gd-log').style.display = 'none';
        return api('status', {domain: state.domain}).then(function (d) { render(d.result); })
            .catch(function (e) { UA.showError($('gd-site-state'), e); });
    }

    api('sites', {}).then(function (d) {
        var sites = d.result.sites || [];
        $('gd-site').innerHTML = sites.map(function (s) { return '<option value="' + esc(s) + '">' + esc(s) + '</option>'; }).join('');
        if (root.dataset.site && sites.indexOf(root.dataset.site) >= 0) { $('gd-site').value = root.dataset.site; }
        if (!sites.length) { $('gd-site-state').textContent = 'You have no websites.'; return; }
        load();
    }).catch(function (e) { UA.showError($('gd-site-state'), e); });
    $('gd-site').addEventListener('change', load);

    root.addEventListener('click', function (event) {
        var t = event.target.closest('button');
        if (!t) { return; }
        var domain = state.domain;
        if (t.id === 'gd-save') {
            var steps = [];
            root.querySelectorAll('.gd-step:checked').forEach(function (b) { steps.push(b.value); });
            var repo = {url: $('gd-url').value.trim(), branch: $('gd-branch').value.trim() || 'main', auth: auth(), target: $('gd-target').value.trim(),
                        mode: $('gd-mode').value, keep: parseInt($('gd-keep').value, 10) || 5, steps: steps, restart_app: $('gd-app').value,
                        custom_script: $('gd-script').checked, script_timeout: parseInt($('gd-script-timeout').value, 10) || 600,
                        token_user: $('gd-token-user').value.trim() || 'x-access-token'};
            var payload = {domain: domain, repo: repo};
            if (auth() === 'token' && $('gd-token').value) { payload.secrets = {token: $('gd-token').value}; }
            UA.busy(t, true);
            api('save', payload).then(function (d) {
                $('gd-token').value = '';
                $('gd-save-out').textContent = 'Saved.';
                render(d.result);
            }).catch(function (e) { UA.showError($('gd-save-out'), e); }).then(function () { UA.busy(t, false); });
        } else if (t.id === 'gd-deploy' || t.id === 'gd-rollback') {
            var rollback = t.id === 'gd-rollback';
            if (rollback && !window.confirm('Switch ' + domain + ' back to the previous release?')) { return; }
            api(rollback ? 'rollback' : 'deploy', {domain: domain}).then(function (d) { watch(d.result.job_id, load); })
                .catch(function (e) { $('gd-job').style.display = 'block'; UA.showError($('gd-job-out'), e); });
        } else if (t.classList.contains('gd-log')) {
            api('log', {domain: domain, n: parseInt(t.dataset.n, 10)}).then(function (d) {
                $('gd-log').style.display = 'block';
                $('gd-log').textContent = d.result.lines.join('\n');
            }).catch(function (e) { UA.showError($('gd-log'), e); });
        } else if (t.id === 'gd-secret-show' || t.id === 'gd-secret-new') {
            var fresh = t.id === 'gd-secret-new';
            if (fresh && !window.confirm('Make a new webhook secret? Update it in your Git host afterwards.')) { return; }
            api('secret', {domain: domain, regenerate: fresh}).then(function (d) { $('gd-secret').textContent = d.result.secret; })
                .catch(function (e) { UA.showError($('gd-secret'), e); });
        } else if (t.id === 'gd-key-new') {
            if (!window.confirm('Replace the deploy key? Add the new public key to the repository afterwards.')) { return; }
            api('key', {domain: domain, replace: true}).then(function (d) { $('gd-key').textContent = d.result.public_key; })
                .catch(function (e) { UA.showError($('gd-key'), e); });
        } else if (t.id === 'gd-disconnect') {
            if (!window.confirm('Disconnect the repository from ' + domain + '? Deployed files stay; the webhook stops working.')) { return; }
            api('disconnect', {domain: domain}).then(load).catch(function (e) { UA.showError($('gd-save-out'), e); });
        }
    });
})();
