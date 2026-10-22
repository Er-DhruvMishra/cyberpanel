(function () {
    'use strict';
    var root = document.getElementById('ua-rspamd');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var NUMBERS = ['greylist', 'add_header', 'reject'], FLAGS = ['greylisting', 'bayes_autolearn', 'dkim_signing', 'arc_signing'];

    function badge(ok, yes, no) {
        return '<span class="ua-badge ua-badge-' + (ok ? 'pass' : 'warn') + '">' + esc(ok ? yes : no) + '</span>';
    }

    function show(id, on) { $(id).style.display = on ? 'block' : 'none'; }

    function refresh() {
        return api('detect', {}).then(function (d) {
            var s = d.result;
            var rows = [
                ['Rspamd', badge(s.installed, 'installed ' + (s.version || ''), 'not installed')],
                ['Service', badge(s.running, 'running', 'stopped')],
                ['Redis', badge(s.redis_running, 'running', 'stopped')],
                ['Postfix filtering', badge(s.milter_enabled, 'on', 'off')],
                ['Milters', esc(s.milters.join(' ') || 'none')],
                ['If a milter is down', esc(s.milter_default_action) + (s.milter_default_action === 'accept' ? '' :
                    ' <span class="ua-muted">(mail is deferred; enabling filtering sets accept)</span>')]
            ];
            var html = '<table class="ua-table"><tbody>' + rows.map(function (r) {
                return '<tr><td style="width:200px"><strong>' + r[0] + '</strong></td><td>' + r[1] + '</td></tr>';
            }).join('') + '</tbody></table>';
            if (s.conflicts.length) {
                html += '<h2 style="margin-top:16px">Conflicts</h2><table class="ua-table"><tbody>' + s.conflicts.map(function (c) {
                    return '<tr><td><span class="ua-badge ua-badge-warn">' + esc(c.id) + '</span></td><td>' + esc(c.detail) +
                        '<div class="ua-fix">' + esc(c.resolution) + '</div></td></tr>';
                }).join('') + '</tbody></table>';
            }
            $('rs-status').innerHTML = html;
            show('rs-install-row', !s.installed);
            ['rs-filter-card', 'rs-settings-card', 'rs-learn-card', 'rs-stats-card'].forEach(function (id) { show(id, s.installed); });
            fillSettings(s.managed_settings);
        }).catch(function (e) { UA.showError($('rs-status'), e); });
    }

    function fillSettings(s) {
        NUMBERS.forEach(function (k) { $('rs-' + k).value = s[k]; });
        FLAGS.forEach(function (k) { $('rs-' + k).checked = !!s[k]; });
        $('rs-allow_list').value = (s.allow_list || []).join('\n');
        $('rs-deny_list').value = (s.deny_list || []).join('\n');
    }

    function watchJob(jobId, target, onDone) {
        (function poll() {
            api('job', {job: jobId}).then(function (d) {
                var j = d.result;
                target.innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-60).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (onDone) { onDone(j); }
            }).catch(function (e) { UA.showError(target, e); });
        })();
    }

    $('rs-install').addEventListener('click', function () {
        if (!window.confirm('Install Rspamd and Redis from the official Rspamd repository?')) { return; }
        var button = this;
        UA.busy(button, true);
        api('install', {}).then(function (d) { watchJob(d.result.job_id, $('rs-job'), refresh); })
            .catch(function (e) { UA.showError($('rs-job'), e); }).then(function () { UA.busy(button, false); });
    });

    function planHtml(p) {
        var lines = Object.keys(p.postconf).map(function (k) { return 'postconf -e "' + k + '=' + p.postconf[k] + '"'; })
            .concat(p.remove_master_params.map(function (m) { return 'postconf -PX ' + m; }));
        return lines.length ? '<div class="ua-pre">' + esc(lines.join('\n')) + '</div>' : '<p class="ua-muted">No changes needed.</p>';
    }

    $('rs-preview').addEventListener('click', function () {
        api('plan', {enable: true, replaceSpamAssassin: $('rs-replace-sa').checked})
            .then(function (d) { $('rs-filter-out').innerHTML = '<p>Enabling would run:</p>' + planHtml(d.result); })
            .catch(function (e) { UA.showError($('rs-filter-out'), e); });
    });
    function setFiltering(enable, button) {
        if (!window.confirm((enable ? 'Enable' : 'Disable') + ' Rspamd filtering for all mail? main.cf and master.cf are backed up first.')) { return; }
        UA.busy(button, true);
        api('filtering', {enable: enable, replaceSpamAssassin: $('rs-replace-sa').checked})
            .then(function (d) { $('rs-filter-out').innerHTML = '<p>Applied:</p>' + planHtml(d.result); refresh(); })
            .catch(function (e) { UA.showError($('rs-filter-out'), e); }).then(function () { UA.busy(button, false); });
    }
    $('rs-enable').addEventListener('click', function () { setFiltering(true, this); });
    $('rs-disable').addEventListener('click', function () { setFiltering(false, this); });

    $('rs-save').addEventListener('click', function () {
        var body = {}, button = this;
        NUMBERS.forEach(function (k) { body[k] = Number($('rs-' + k).value); });
        FLAGS.forEach(function (k) { body[k] = $('rs-' + k).checked; });
        body.allow_list = $('rs-allow_list').value.split(/\s+/).filter(Boolean);
        body.deny_list = $('rs-deny_list').value.split(/\s+/).filter(Boolean);
        UA.busy(button, true);
        api('apply', body).then(function () {
            $('rs-settings-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">OK</span> Configuration validated (rspamadm configtest) and Rspamd reloaded.</p>';
            refresh();
        }).catch(function (e) { UA.showError($('rs-settings-out'), e); }).then(function () { UA.busy(button, false); });
    });

    $('rs-migrate').addEventListener('click', function () {
        api('migrate_dkim', {}).then(function (d) {
            $('rs-settings-out').innerHTML = '<p>Copied keys for ' + esc(d.result.domains.length) + ' domain(s): ' + esc(d.result.domains.join(', ')) + '</p>';
        }).catch(function (e) { UA.showError($('rs-settings-out'), e); });
    });

    $('rs-learn').addEventListener('click', function () {
        api('learn', {mailbox: $('rs-mailbox').value.trim(), folder: $('rs-folder').value, kind: $('rs-kind').value})
            .then(function (d) { watchJob(d.result.job_id, $('rs-learn-out')); })
            .catch(function (e) { UA.showError($('rs-learn-out'), e); });
    });

    $('rs-stats').addEventListener('click', function () {
        api('stats', {}).then(function (d) {
            var s = d.result;
            $('rs-stats-out').innerHTML = '<p>Scanned <strong>' + esc(s.scanned) + '</strong>, spam ' + esc(s.spam_count) +
                ', ham ' + esc(s.ham_count) + ', learned ' + esc(s.learned) + '</p><div class="ua-grid"><div class="ua-card"><h2>Actions</h2>' +
                Object.keys(s.actions).map(function (k) { return esc(k) + ' <strong>' + esc(s.actions[k]) + '</strong>'; }).join('<br>') +
                '</div><div class="ua-card"><h2>Top symbols</h2>' + s.top_symbols.map(function (t) {
                    return esc(t.symbol) + ' <strong>' + esc(t.hits) + '</strong>';
                }).join('<br>') + '</div></div>';
        }).catch(function (e) { UA.showError($('rs-stats-out'), e); });
    });
    $('rs-log').addEventListener('click', function () {
        api('log', {lines: 200}).then(function (d) {
            $('rs-stats-out').innerHTML = '<div class="ua-pre">' + esc(d.result.lines.join('\n')) + '</div>';
        }).catch(function (e) { UA.showError($('rs-stats-out'), e); });
    });

    refresh();
})();
