(function () {
    'use strict';
    var root = document.getElementById('ua-sshsec');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {firewall: false};

    // CyberPanel's request filter rejects ':' in values, so IPv6 colons travel as '-'.
    function wire(addr) { return String(addr).trim().replace(/:/g, '-'); }
    function when(t) { return t ? new Date(t * 1000).toLocaleString() : ''; }
    function badge(kind, text) { return '<span class="ua-badge ua-badge-' + esc(kind) + '">' + esc(text) + '</span>'; }
    function table(head, rows) {
        return '<table class="ua-table"><thead><tr>' + head.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('') +
            '</tr></thead><tbody>' + (rows.length ? rows.join('') : '<tr><td colspan="' + head.length + '" class="ua-muted">None</td></tr>') + '</tbody></table>';
    }
    function blockedCell(list) {
        return list && list.length ? list.map(function (l) { return badge('pass', l); }).join(' ') : '<span class="ua-muted">no</span>';
    }
    function blockButton(ip, blocked) {
        return state.firewall && !(blocked && blocked.length) ? '<button type="button" class="btn btn-default btn-xs ss-quick" data-ip="' + esc(ip) + '">Block</button>' : '';
    }

    function loadStatus() {
        api('overview', {}).then(function (d) {
            var r = d.result, fw = r.firewall, f2b = r.fail2ban;
            state.firewall = fw.running;
            $('ss-status').innerHTML =
                'firewalld: ' + (fw.running ? badge('pass', 'running') + ' zone <code>' + esc(fw.zone) + '</code>' +
                    (fw.zone_has_interfaces ? '' : ' ' + badge('warn', 'default zone has no interfaces')) : badge('fail', 'not running')) +
                ' &nbsp; fail2ban: ' + (f2b.running ? badge('pass', 'running') : badge(f2b.installed ? 'warn' : 'fail', f2b.installed ? 'stopped' : 'not installed')) +
                ' sshd jail ' + (f2b.jail ? badge('pass', 'on') : badge('warn', 'off')) +
                ' &nbsp; logs: <code>' + esc(r.log_sources.join(', ')) + '</code> &nbsp; blocklist: ' + esc(r.blocked_count) +
                (fw.running ? '' : '<div class="ua-alert">firewalld is not running, so this page cannot block addresses. Start it with <code>systemctl enable --now firewalld</code> (check that your SSH port is allowed first). There is no iptables fallback.</div>');
            $('ss-block-form').style.display = fw.running ? '' : 'none';
        }).catch(function (e) { UA.showError($('ss-status'), e); });
    }

    function renderAnalysis(r) {
        var t = r.totals, out = '';
        out += '<p>' + badge('info', r.window) + ' ' + esc(when(r.earliest)) + ' → ' + esc(when(r.latest)) + ' from <code>' +
            esc(r.coverage.map(function (c) { return c.path; }).join(', ') || 'nothing') + '</code>' +
            (r.truncated ? ' ' + badge('warn', 'partial: size limit reached, newest data only') : '') + '</p>';
        out += '<div class="ua-grid">' + [['Failed passwords', t.failed], ['Invalid-user attempts', t.invalid_user], ['Failed root logins', t.root_failed],
            ['Pre-auth probes', t.probes], ['Successful logins', t.accepted], ['Attacking IPs', t.attacking_ips + ' (' + t.already_blocked + ' blocked)']].map(function (x) {
            return '<div class="ua-tile"><div class="ua-muted">' + esc(x[0]) + '</div><strong style="font-size:1.4em">' + esc(x[1]) + '</strong></div>';
        }).join('') + '</div>';
        out += '<h3>Successful logins</h3>' + table(['User', 'From', 'Method', 'Count', 'Last'], r.successful.map(function (s) {
            return '<tr><td><strong>' + esc(s.user) + '</strong></td><td><code>' + esc(s.ip) + '</code>' + (r.client.indexOf(s.ip) >= 0 ? ' ' + badge('info', 'you') : '') +
                (s.blocked_by.length ? ' ' + badge('warn', 'now blocked') : '') + '</td><td>' + esc(s.method) + '</td><td>' + esc(s.count) + '</td><td>' + esc(when(s.last)) + '</td></tr>';
        }));
        out += '<h3>Top attacking IPs</h3>' + table(['IP', 'Failed', 'Invalid user', 'Root', 'Probes', 'Type', 'Users tried', 'First / last seen', 'Blocked', ''], r.top_ips.map(function (i) {
            return '<tr><td><code>' + esc(i.ip) + '</code>' + (i.you ? ' ' + badge('fail', 'your address') : '') + (i.accepted ? ' ' + badge('warn', i.accepted + ' successful') : '') +
                '</td><td>' + esc(i.failed) + '</td><td>' + esc(i.invalid) + '</td><td>' + esc(i.root) + '</td><td>' + esc(i.probes) + '</td><td>' +
                i.kinds.map(function (k) { return badge('warn', k); }).join(' ') + '</td><td class="ua-muted">' + esc(i.users.join(', ')) + '</td><td class="ua-muted">' +
                esc(when(i.first)) + '<br>' + esc(when(i.last)) + '</td><td>' + blockedCell(i.blocked_by) + '</td><td>' + (i.you ? '' : blockButton(i.ip, i.blocked_by)) + '</td></tr>';
        }));
        out += '<h3>Usernames tried</h3>' + table(['User', 'Failed', 'Exists?', 'IPs', 'Successful'], r.top_users.map(function (u) {
            return '<tr><td><code>' + esc(u.user) + '</code></td><td>' + esc(u.failed) + '</td><td>' + (u.invalid ? '<span class="ua-muted">no (invalid user)</span>' : badge('warn', 'yes')) +
                '</td><td>' + esc(u.ips) + '</td><td>' + esc(u.accepted) + '</td></tr>';
        }));
        out += '<h3>Likely port scans and pre-auth disconnect floods</h3>' + table(['IP', 'Probes', 'Auth attempts', 'Last seen', 'Blocked', ''], r.scans.map(function (i) {
            return '<tr><td><code>' + esc(i.ip) + '</code></td><td>' + esc(i.probes) + '</td><td>' + esc(i.failed + i.invalid) + '</td><td>' + esc(when(i.last)) +
                '</td><td>' + blockedCell(i.blocked_by) + '</td><td>' + (i.you ? '' : blockButton(i.ip, i.blocked_by)) + '</td></tr>';
        }));
        $('ss-analysis').innerHTML = out;
    }

    function watch(jobId, done) {
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }, function (e, n) {
                $('ss-job').innerHTML = '<p class="ua-muted">The panel is busy (' + esc(e.message) + '); reconnecting, attempt ' + esc(n) + '.</p>';
            }).then(function (d) {
                var j = d.result;
                if (j.state === 'running') { $('ss-job').innerHTML = '<p class="ua-muted">Reading logs…</p>'; setTimeout(poll, 2000); return; }
                $('ss-job').innerHTML = j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '';
                done(j);
            }).catch(function (e) { UA.showError($('ss-job'), e); done({state: 'failed'}); });
        })();
    }

    $('ss-analyze').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        $('ss-analysis').innerHTML = '';
        api('analyze', {window: $('ss-window').value}).then(function (d) {
            watch(d.result.job_id, function (j) {
                UA.busy(button, false);
                if (j.state === 'done') { renderAnalysis(j.result.Analysis); }
            });
        }).catch(function (e) { UA.busy(button, false); UA.showError($('ss-job'), e); });
    });

    $('ss-audit').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('audit', {}).then(function (d) {
            UA.busy(button, false);
            var r = d.result;
            $('ss-audit-out').innerHTML = '<table class="ua-table"><tbody>' + UA.resultRows(r.rows.map(function (row) {
                return {status: row.status, title: row.title + ' = ' + row.value, detail: row.detail, fix: row.fix};
            })) + '</tbody></table>' + (r.can_enable_jail ? '<div class="ua-row" style="margin-top:12px"><button class="ua-btn" id="ss-jail">Enable fail2ban sshd jail</button>' +
                '<span class="ua-muted">Writes only /etc/fail2ban/jail.d/cp-sshd.local, tests the config, then reloads fail2ban.</span></div>' : '');
        }).catch(function (e) { UA.busy(button, false); UA.showError($('ss-audit-out'), e); });
    });

    root.addEventListener('click', function (e) {
        if (e.target.id === 'ss-jail') {
            if (!window.confirm('Enable the fail2ban sshd jail? Repeated failed logins (including yours) will be banned for the jail\'s ban time.')) { return; }
            UA.busy(e.target, true);
            api('enable_jail', {confirm: true}).then(function (d) {
                $('ss-audit-out').insertAdjacentHTML('afterbegin', '<p>' + badge('pass', 'Done') + ' ' + esc(d.result.message) + '</p>');
                e.target.remove();
                loadStatus();
            }).catch(function (err) { UA.busy(e.target, false); UA.showError($('ss-audit-out'), err); });
        } else if (e.target.classList.contains('ss-quick')) {
            $('ss-addr').value = e.target.dataset.ip;
            $('ss-reason').value = 'SSH attacks';
            $('ss-addr').scrollIntoView({behavior: 'smooth', block: 'center'});
        } else if (e.target.classList.contains('ss-unblock')) {
            var target = e.target.dataset.target;
            if (!window.confirm('Remove the block on ' + target + '?')) { return; }
            api('unblock', {addr: wire(target)}).then(loadBlocklist).catch(function (err) { UA.showError($('ss-block-msg'), err); });
        }
    });

    function doBlock(confirmed) {
        var addr = $('ss-addr').value, reason = $('ss-reason').value.trim();
        if (!addr.trim()) { return; }
        api('block', {addr: wire(addr), reason: reason, confirm: confirmed}).then(function (d) {
            var r = d.result;
            if (r.needs_confirm) {
                if (window.confirm(r.needs_confirm.join('\n') + '\n\nBlock it anyway?')) { doBlock(true); }
                return;
            }
            $('ss-block-msg').innerHTML = '<p>' + badge('pass', 'Blocked') + ' <code>' + esc(r.blocked.target) + '</code></p>';
            $('ss-addr').value = '';
            loadBlocklist();
            loadStatus();
        }).catch(function (e) { UA.showError($('ss-block-msg'), e); });
    }
    $('ss-block').addEventListener('click', function () {
        if (window.confirm('Drop all traffic from ' + $('ss-addr').value.trim() + '?')) { doBlock(false); }
    });

    function loadBlocklist() {
        api('blocklist', {}).then(function (d) {
            $('ss-blocklist').innerHTML = table(['Address', 'Reason', 'Added', 'By', 'Rule active', ''], d.result.entries.map(function (e) {
                return '<tr><td><code>' + esc(e.target) + '</code></td><td>' + esc(e.reason) + '</td><td>' + esc(when(e.added)) + '</td><td>' + esc(e.by) +
                    '</td><td>' + (e.active ? badge('pass', 'yes') : badge('warn', 'missing')) + '</td><td>' +
                    (d.result.firewall.running ? '<button type="button" class="btn btn-default btn-xs ss-unblock" data-target="' + esc(e.target) + '">Unblock</button>' : '') + '</td></tr>';
            }));
        }).catch(function (e) { UA.showError($('ss-blocklist'), e); });
    }

    loadStatus();
    loadBlocklist();
})();
