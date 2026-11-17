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

    // ------------------------------------------------------------------ login options
    var login = {state: null, timer: null};
    function b64(text) { return window.btoa(unescape(encodeURIComponent(text))); }
    function fpWire(fp) { return String(fp).replace(/^SHA256:/, ''); }
    function radio(name, value) {
        Array.prototype.forEach.call(document.getElementsByName(name), function (r) { r.checked = r.value === value; });
    }
    function radioValue(name) {
        var picked = Array.prototype.filter.call(document.getElementsByName(name), function (r) { return r.checked; })[0];
        return picked ? picked.value : null;
    }
    function keyTable(keys, selectable) {
        return table((selectable ? [''] : []).concat(['Type', 'Bits', 'Fingerprint (SHA256)', 'Comment', 'Options', 'Line']), keys.map(function (k) {
            return '<tr>' + (selectable ? '<td><input type="checkbox" class="ss-key-pick" value="' + esc(fpWire(k.fingerprint)) + '"></td>' : '') +
                '<td>' + esc(k.type) + '</td><td>' + esc(k.bits) + '</td><td><code>' + esc(k.fingerprint) + '</code></td><td>' + esc(k.comment) +
                '</td><td class="ua-muted">' + esc((k.options || []).join(', ')) + '</td><td>' + esc(k.line) + '</td></tr>';
        }));
    }
    function selectUsers(select, users, current) {
        select.innerHTML = users.map(function (u) { return '<option value="' + esc(u) + '"' + (u === current ? ' selected' : '') + '>' + esc(u) + '</option>'; }).join('');
    }

    function renderPending(p) {
        clearInterval(login.timer);
        if (!p) { $('ss-login-pending').innerHTML = ''; return; }
        function draw() {
            var left = Math.max(0, p.deadline - Math.floor(Date.now() / 1000));
            $('ss-login-pending').innerHTML = '<div class="ua-alert" style="background:#fffbeb;border-color:#f59e0b;color:#92400e">' +
                '<strong>Trial running.</strong> Open a NEW SSH session now and check that you can log in. ' +
                (p.expired || left === 0 ? 'The 5-minute safety timer should have undone this change; if it is still shown, the timer did not run (for example after a reboot). Choose below.'
                    : 'The previous settings come back automatically in <strong>' + Math.floor(left / 60) + ':' + ('0' + left % 60).slice(-2) + '</strong> unless you confirm.') +
                '<div class="ua-row" style="margin-top:8px"><button class="ua-btn" id="ss-confirm">Confirm: keep the new settings</button>' +
                '<button class="ua-btn ua-btn-secondary" id="ss-undo">Undo now</button></div></div>';
            if (left === 0 && !p.expired) { clearInterval(login.timer); setTimeout(loadLogin, 15000); }
        }
        draw();
        login.timer = setInterval(draw, 1000);
    }

    function loadLoginKeys() {
        var user = $('ss-login-user').value || 'root';
        $('ss-tested-help').textContent = 'in a second terminal I logged in with my key as ' + user + ', and that session is still open.';
        api('keys_list', {user: user}).then(function (d) {
            var r = d.result;
            $('ss-login-keys').innerHTML = (r.keys.length ? '<p>' + esc(user) + ' has ' + esc(r.keys.length) + ' key(s). Check that yours is one of these:</p>' + keyTable(r.keys, false)
                : '<div class="ua-alert">' + esc(user) + ' has no public key in ' + esc(r.path) + '. Password login cannot be turned off' + (user === 'root' ? ', and root cannot be set to keys only,' : '') + ' until you add one (SSH keys card below) and test it.</div>') +
                (r.problems.length ? '<p class="ua-muted">' + esc(r.problems.length) + ' line(s) in the file are not valid keys and are ignored by sshd.</p>' : '');
        }).catch(function (e) { UA.showError($('ss-login-keys'), e); });
    }

    function loadLogin() {
        api('login_state', {}).then(function (d) {
            var r = d.result, eff = r.effective, notes = [];
            login.state = r;
            renderPending(r.pending);
            if (r.last && r.last.result === 'reverted') { notes.push(badge('warn', 'Undone') + ' The last change was undone (' + esc(r.last.reason) + ') at ' + esc(when(r.last.time)) + '. ' + esc(r.last.detail || '')); }
            if (r.last && r.last.result === 'not-reverted') { notes.push(badge('fail', 'Not undone') + ' ' + esc(r.last.detail)); }
            if (r.block.present && r.block.edited) { notes.push(badge('warn', 'Edited elsewhere') + ' The IndiansCloud block in <code>' + esc(r.file) + '</code> was changed outside this page (for example by Security &gt; Secure SSH). The values below are what sshd uses now.'); }
            r.match_blocks.forEach(function (m) {
                if (m.sets.length) { notes.push(badge('info', 'Match') + ' <code>Match ' + esc(m.match) + '</code> overrides ' + esc(m.sets.join(', ')) + ' for the connections it matches; this page does not change Match blocks.'); }
            });
            if (eff.authenticationmethods && eff.authenticationmethods !== 'any') { notes.push(badge('info', 'AuthenticationMethods') + ' <code>' + esc(eff.authenticationmethods) + '</code>'); }
            notes.push('<span class="ua-muted">Now in effect (sshd -T): password login <strong>' + esc(eff.passwordauthentication) + '</strong>, keyboard-interactive <strong>' +
                esc(eff.kbdinteractiveauthentication || eff.challengeresponseauthentication || '?') + '</strong>, root login <strong>' + esc(eff.permitrootlogin) + '</strong>, port <strong>' + esc(eff.port) +
                '</strong>. Settings live in <code>' + esc(r.file) + '</code>' + (r.mode === 'block' ? ' (marked block before any Match section)' : ' (drop-in read first)') + '.</span>');
            $('ss-login-notes').innerHTML = notes.map(function (n) { return '<p>' + n + '</p>'; }).join('');
            radio('ss-pw', eff.passwordauthentication === 'no' ? 'no' : 'yes');
            radio('ss-root', eff.permitrootlogin === 'without-password' ? 'prohibit-password' : (eff.permitrootlogin === 'forced-commands-only' ? 'prohibit-password' : eff.permitrootlogin));
            var ports = String(eff.port || '').split(' ');
            $('ss-port').value = ports.length === 1 ? ports[0] : '';
            $('ss-maxauth').value = eff.maxauthtries || '';
            $('ss-grace').value = eff.logingracetime || '';
            var portNote = r.socket_activated ? 'sshd is socket-activated here; the port cannot be changed from this page.' : (r.csf ? 'CSF manages the firewall here; the port cannot be changed from this page.' : '');
            $('ss-port').disabled = !!portNote;
            $('ss-port-note').dataset.extra = portNote;
            if (portNote) { $('ss-port-note').textContent = portNote; }
            var current = $('ss-login-user').value || (r.pending && r.pending.login_user) || 'root';
            selectUsers($('ss-login-user'), r.users, current);
            selectUsers($('ss-keys-user'), r.users, $('ss-keys-user').value || 'root');
            $('ss-login-form').style.display = r.pending ? 'none' : '';
            loadLoginKeys();
        }).catch(function (e) { UA.showError($('ss-login-notes'), e); });
    }

    $('ss-login-user').addEventListener('change', loadLoginKeys);
    $('ss-login-apply').addEventListener('click', function () {
        var button = this, settings = {password: radioValue('ss-pw'), root: radioValue('ss-root'), port: $('ss-port').disabled ? '' : $('ss-port').value,
            maxauthtries: $('ss-maxauth').value, logingracetime: $('ss-grace').value};
        var summary = 'Password login: ' + (settings.password === 'yes' ? 'ON' : 'OFF') + '\nRoot login: ' + settings.root + (settings.port ? '\nPort: ' + settings.port : '') +
            '\n\nKeep this SSH session open. You will have 5 minutes to test a new login and confirm.';
        if (!window.confirm(summary)) { return; }
        UA.busy(button, true);
        $('ss-login-msg').innerHTML = '';
        api('login_apply', {settings: settings, login_user: $('ss-login-user').value, tested: $('ss-tested').checked}).then(function (d) {
            UA.busy(button, false);
            var r = d.result;
            $('ss-login-msg').innerHTML = '<p>' + badge(r.changed ? 'pass' : 'info', r.changed ? 'Applied' : 'No change') + ' ' + esc(r.message) + '</p>' +
                (r.notes || []).map(function (n) { return '<p class="ua-muted">' + esc(n) + '</p>'; }).join('');
            $('ss-tested').checked = false;
            loadLogin();
        }).catch(function (e) { UA.busy(button, false); UA.showError($('ss-login-msg'), e); });
    });
    root.addEventListener('click', function (e) {
        var p = login.state && login.state.pending;
        if (!p || (e.target.id !== 'ss-confirm' && e.target.id !== 'ss-undo')) { return; }
        UA.busy(e.target, true);
        api(e.target.id === 'ss-confirm' ? 'login_confirm' : 'login_revert', {token: p.token}).then(function (d) {
            $('ss-login-msg').innerHTML = '<p>' + badge('pass', 'Done') + ' ' + esc(d.result.message) + '</p>';
            loadLogin();
            loadStatus();
        }).catch(function (err) { UA.busy(e.target, false); UA.showError($('ss-login-msg'), err); loadLogin(); });
    });

    // ------------------------------------------------------------------ SSH keys
    function keysUser() { return $('ss-keys-user').value || 'root'; }
    function picked() { return Array.prototype.map.call(root.querySelectorAll('.ss-key-pick:checked'), function (c) { return c.value; }); }
    function loadKeys() {
        api('keys_list', {user: keysUser()}).then(function (d) {
            var r = d.result;
            $('ss-keys-list').innerHTML = '<p class="ua-muted"><code>' + esc(r.path) + '</code>' + (r.key_only ? ' ' + badge('warn', 'key login only: ' + r.key_only) + ' the last key cannot be removed.' : '') + '</p>' +
                keyTable(r.keys, true) + (r.problems.length ? '<p class="ua-muted">Ignored lines (not valid keys): ' + esc(r.problems.map(function (p) { return p.line; }).join(', ')) + '</p>' : '');
        }).catch(function (e) { UA.showError($('ss-keys-list'), e); });
    }
    function keysDone(text) {
        $('ss-keys-msg').innerHTML = '<p>' + badge('pass', 'Done') + ' ' + esc(text) + '</p>';
        loadKeys();
        if ($('ss-login-user').value === keysUser()) { loadLoginKeys(); }
    }
    $('ss-keys-user').addEventListener('change', loadKeys);
    $('ss-keys-reload').addEventListener('click', loadKeys);
    $('ss-keys-remove').addEventListener('click', function () {
        var fps = picked();
        if (!fps.length) { $('ss-keys-msg').innerHTML = '<p class="ua-muted">Tick the keys to remove first.</p>'; return; }
        if (!window.confirm('Remove ' + fps.length + ' key(s) from ' + keysUser() + '\'s authorized_keys? Whoever uses them can no longer log in.')) { return; }
        api('keys_remove', {user: keysUser(), fps: fps}).then(function (d) { keysDone('Removed ' + d.result.removed.length + ' key(s).'); })
            .catch(function (e) { UA.showError($('ss-keys-msg'), e); });
    });
    function addKey(rotate) {
        var text = $('ss-key-text').value.trim(), fps = picked();
        if (!text) { return; }
        if (/PRIVATE KEY|BEGIN OPENSSH|PuTTY-User-Key-File/.test(text)) {
            $('ss-key-text').value = '';
            UA.showError($('ss-keys-msg'), 'That is a PRIVATE key. It was not sent anywhere. Paste the .pub file instead.');
            return;
        }
        if (rotate && !fps.length) { $('ss-keys-msg').innerHTML = '<p class="ua-muted">Tick the old keys to replace first.</p>'; return; }
        if (rotate && !window.confirm('Add the new key, then remove ' + fps.length + ' old key(s)?')) { return; }
        api(rotate ? 'keys_rotate' : 'keys_add', {user: keysUser(), key_b64: b64(text), fps: fps, allow_options: $('ss-key-options').checked}).then(function (d) {
            $('ss-key-text').value = '';
            keysDone('Added ' + d.result.added.fingerprint + (rotate ? '; removed ' + d.result.removed.length + ' old key(s).' : '.'));
        }).catch(function (e) { UA.showError($('ss-keys-msg'), e); });
    }
    $('ss-key-add').addEventListener('click', function () { addKey(false); });
    $('ss-key-rotate').addEventListener('click', function () { addKey(true); });

    function download(name, text) {
        var url = URL.createObjectURL(new Blob([text], {type: 'application/octet-stream'}));
        var a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }
    $('ss-gen').addEventListener('click', function () {
        var button = this, pass = $('ss-gen-pass').value, replace = $('ss-gen-replace').checked, fps = replace ? picked() : [];
        if (!$('ss-gen-ok').checked) { UA.showError($('ss-gen-out'), 'Tick that you understand the private key is shown only once.'); return; }
        if (pass !== $('ss-gen-pass2').value) { UA.showError($('ss-gen-out'), 'The passphrases do not match.'); return; }
        if (pass && pass.length < 8) { UA.showError($('ss-gen-out'), 'Use at least 8 characters, or leave the passphrase empty.'); return; }
        if (!pass && !window.confirm('Create the key WITHOUT a passphrase? Anyone who gets the file can log in.')) { return; }
        if (replace && !fps.length) { UA.showError($('ss-gen-out'), 'Tick the old keys to replace, or untick "Replace".'); return; }
        UA.busy(button, true);
        var body = {user: keysUser(), comment: $('ss-gen-comment').value.trim(), understood: true, fps: fps};
        if (pass) { body.secret_b64 = b64(pass); }
        api('keys_generate', body).then(function (d) {
            UA.busy(button, false);
            var r = d.result;
            $('ss-gen-pass').value = $('ss-gen-pass2').value = '';
            $('ss-gen-ok').checked = false;
            download(r.filename, r.private_key);
            r.private_key = null;
            $('ss-gen-out').innerHTML = '<p>' + badge('pass', 'Key installed') + ' <code>' + esc(r.added.fingerprint) + '</code> for ' + esc(r.user) +
                (r.removed && r.removed.length ? '; removed ' + esc(r.removed.length) + ' old key(s)' : '') + '. The private key was downloaded as <code>' + esc(r.filename) +
                '</code>' + (r.encrypted ? ' (passphrase-protected)' : ' (<strong>no passphrase</strong>)') + ' and deleted from the server; it cannot be downloaded again.</p>' +
                '<p class="ua-muted">Move it to ~/.ssh/, run <code>chmod 600</code> on it, and test: <code>ssh -i ' + esc(r.filename) + ' ' + esc(r.user) + '@this-server</code>. Public key:</p><pre class="ua-pre">' + esc(r.public_key) + '</pre>';
            keysDone('New key added.');
        }).catch(function (e) { UA.busy(button, false); UA.showError($('ss-gen-out'), e); });
    });

    loadStatus();
    loadBlocklist();
    loadLogin();
    loadKeys();
})();
