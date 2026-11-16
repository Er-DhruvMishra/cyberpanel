(function () {
    'use strict';
    var root = document.getElementById('ua-smtprelay');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var PORTS = ['587', '465', '25'];
    var TLS = [['starttls', 'STARTTLS'], ['implicit', 'Implicit TLS'], ['none', 'No encryption']];

    function badge(kind, text) { return '<span class="ua-badge ua-badge-' + esc(kind) + '">' + esc(text) + '</span>'; }
    function options(list, value) {
        return list.map(function (o) {
            var v = Array.isArray(o) ? o[0] : o, t = Array.isArray(o) ? o[1] : o;
            return '<option value="' + esc(v) + '"' + (String(value) === String(v) ? ' selected' : '') + '>' + esc(t) + '</option>';
        }).join('');
    }
    function scope() { var c = root.querySelector('input[name=sr-scope]:checked'); return c ? c.value : 'all'; }

    function domainRow(d) {
        d = d || {};
        var div = document.createElement('div');
        div.className = 'ua-row sr-domain';
        div.innerHTML = '<input class="sr-d-domain" placeholder="sender domain, e.g. example.com" value="' + esc(d.domain || '') + '" style="min-width:200px">' +
            '<input class="sr-d-host" placeholder="relay host (empty: global relay)" value="' + esc(d.host || '') + '" style="min-width:200px">' +
            '<select class="sr-d-port">' + options(PORTS, d.port || 587) + '</select>' +
            '<select class="sr-d-tls">' + options(TLS, d.tls || 'starttls') + '</select>' +
            '<input class="sr-d-user" placeholder="user name (optional)" value="' + esc(d.username || '') + '" autocomplete="off" style="min-width:160px">' +
            '<input class="sr-d-pass" type="password" placeholder="' + (d.has_password ? 'stored; type to change' : 'password') + '" autocomplete="new-password" style="min-width:160px">' +
            '<button type="button" class="btn btn-default btn-xs sr-d-remove">Remove</button>';
        div.querySelector('.sr-d-remove').addEventListener('click', function () { div.parentNode.removeChild(div); });
        return div;
    }

    function fill(config) {
        var r = (config && config.relay) || {};
        var radio = root.querySelector('input[name=sr-scope][value="' + ((config && config.scope) || 'all') + '"]');
        if (radio) { radio.checked = true; }
        $('sr-host').value = r.host || '';
        $('sr-port').value = String(r.port || 587);
        $('sr-tls').value = r.tls || 'starttls';
        $('sr-user').value = r.username || '';
        $('sr-pass').value = '';
        $('sr-pass').placeholder = r.has_password ? 'stored; type to change' : 'password';
        $('sr-pass-note').textContent = r.has_password ? 'A password is stored. Leave empty to keep it.' : '';
        $('sr-domains').innerHTML = '';
        ((config && config.domains) || []).forEach(function (d) { $('sr-domains').appendChild(domainRow(d)); });
        var target = $('sr-test-target');
        target.innerHTML = '<option value="global">Global relay</option>' + ((config && config.domains) || []).map(function (d) {
            return '<option value="domain:' + esc(d.domain) + '">Sender domain ' + esc(d.domain) + '</option>';
        }).join('');
        tlsWarning();
    }

    function tlsWarning() {
        $('sr-tls-warn').innerHTML = $('sr-tls').value === 'none' ? '<div class="ua-alert">Without encryption the login and every message cross the network in clear text. Use it only for a relay on a private network.</div>' : '';
    }

    function collect() {
        var secrets = {};
        if ($('sr-pass').value) { secrets.global = $('sr-pass').value; }
        var domains = Array.prototype.map.call(root.querySelectorAll('.sr-domain'), function (row) {
            var d = {domain: row.querySelector('.sr-d-domain').value.trim(), host: row.querySelector('.sr-d-host').value.trim(),
                port: parseInt(row.querySelector('.sr-d-port').value, 10), tls: row.querySelector('.sr-d-tls').value,
                username: row.querySelector('.sr-d-user').value.trim()};
            var pass = row.querySelector('.sr-d-pass').value;
            if (pass) { secrets['domain:' + d.domain.toLowerCase()] = pass; }
            return d;
        });
        var host = $('sr-host').value.trim();
        return {config: {scope: scope(), relay: host ? {host: host, port: parseInt($('sr-port').value, 10), tls: $('sr-tls').value,
            username: $('sr-user').value.trim()} : null, domains: domains}, secrets: secrets};
    }

    function renderStatus(r) {
        var e = r.effective, q = r.queue || {}, out = '';
        out += '<p>Relay: ' + (r.enabled ? badge('pass', 'on') : badge('info', 'off')) +
            ' &nbsp; Postfix: ' + (r.postfix_running ? badge('pass', 'running') : badge('fail', 'not running')) +
            ' &nbsp; relayhost: <code>' + esc(e.relayhost || '(none: direct delivery)') + '</code>' +
            (e.sender_dependent_relayhost_maps ? ' &nbsp; per-domain map: <code>' + esc(e.sender_dependent_relayhost_maps) + '</code>' : '') +
            (e.smtp_tls_wrappermode === 'yes' ? ' ' + badge('info', 'implicit TLS') : '') + '</p>';
        if (!r.sasl_plugin) {
            out += '<div class="ua-alert">The SASL PLAIN/LOGIN plugin is not installed, so Postfix cannot log in to a relay. Install cyrus-sasl-plain (dnf) or libsasl2-modules (apt).</div>';
        }
        if (r.foreign && Object.keys(r.foreign).length) {
            out += '<div class="ua-alert">main.cf already has relay settings that this page did not write: ' +
                Object.keys(r.foreign).map(function (k) { return '<code>' + esc(k) + ' = ' + esc(r.foreign[k]) + '</code>'; }).join(', ') +
                '. Saving here replaces them (main.cf is backed up first).</div>';
        }
        (r.warnings || []).forEach(function (w) { out += '<p>' + badge('warn', 'warning') + ' ' + esc(w) + '</p>'; });
        if (q.error) {
            out += '<p class="ua-muted">Queue: ' + esc(q.error) + '</p>';
        } else {
            var by = q.by_queue || {};
            out += '<p>Queue: <strong>' + esc(q.total || 0) + '</strong> message(s)' + (q.truncated ? ' (counted the first ' + esc(q.total) + ')' : '') +
                Object.keys(by).sort().map(function (k) { return ' &nbsp; ' + esc(k) + ': ' + esc(by[k]); }).join('') + '</p>';
            if ((q.top_reasons || []).length) {
                out += '<table class="ua-table"><thead><tr><th>Deferred because</th><th>Recipients</th></tr></thead><tbody>' +
                    q.top_reasons.map(function (t) { return '<tr><td>' + esc(t.reason) + '</td><td>' + esc(t.count) + '</td></tr>'; }).join('') + '</tbody></table>';
            }
        }
        $('sr-status').innerHTML = out;
        $('sr-log').innerHTML = r.log && r.log.length ? '<p class="ua-muted">From ' + esc(r.log_file) + '</p><div class="ua-pre">' + esc(r.log.join('\n')) + '</div>'
            : '<p class="ua-muted">No relay-related lines in the newest part of ' + esc(r.log_file || 'the mail log') + '.</p>';
    }

    function load(refill) {
        return api('overview', {}).then(function (d) {
            renderStatus(d.result);
            if (refill) { fill(d.result.config); }
        }).catch(function (e) { UA.showError($('sr-status'), e); });
    }

    function save(confirm) {
        var body = collect(), button = $('sr-save');
        body.confirm = !!confirm;
        UA.busy(button, true);
        $('sr-save-msg').innerHTML = '';
        api('save', body).then(function (d) {
            var r = d.result;
            if (r.needs_confirm) {
                if (window.confirm(r.needs_confirm.join('\n') + '\n\nContinue?')) { UA.busy(button, false); return save(true); }
                return;
            }
            $('sr-save-msg').innerHTML = '<p>' + badge('pass', 'applied') + ' ' + esc(r.note) + ' Backup: <code>' + esc(r.backup) + '</code></p>' +
                '<div class="ua-pre">' + esc((r.main_cf || []).map(function (kv) { return kv[0] + ' = ' + kv[1]; }).join('\n')) + '</div>' +
                (r.warnings || []).map(function (w) { return '<p>' + badge('warn', 'warning') + ' ' + esc(w) + '</p>'; }).join('');
            return load(true);
        }).catch(function (e) { UA.showError($('sr-save-msg'), e); }).then(function () { UA.busy(button, false); });
    }

    function disable() {
        var forget = $('sr-forget').checked;
        if (!window.confirm('Remove the relay settings from main.cf and deliver mail directly again?' + (forget ? ' The stored passwords are deleted too.' : ''))) { return; }
        var button = $('sr-disable');
        UA.busy(button, true);
        api('disable', {confirm: true, forget: forget}).then(function (d) {
            $('sr-save-msg').innerHTML = '<p>' + badge('info', 'disabled') + ' ' + esc(d.result.note) + ' Backup: <code>' + esc(d.result.backup) + '</code></p>';
            return load(true);
        }).catch(function (e) { UA.showError($('sr-save-msg'), e); }).then(function () { UA.busy(button, false); });
    }

    function test() {
        var button = $('sr-test');
        UA.busy(button, true);
        $('sr-test-out').innerHTML = '<p class="ua-muted">Talking to the relay…</p>';
        api('test', {test: {target: $('sr-test-target').value, to: $('sr-test-to').value.trim(), from: $('sr-test-from').value.trim()}}).then(function (d) {
            var r = d.result;
            $('sr-test-out').innerHTML = '<p>' + (r.ok ? badge('pass', 'delivered to relay') : badge('fail', 'failed')) + ' ' + esc(r.message) +
                ' <span class="ua-muted">(' + esc(r.relay) + ', ' + esc(r.tls) + (r.tls_verified === false ? ', certificate not verified' : '') +
                (r.authenticated ? ', logged in' : '') + ', ' + esc(r.seconds) + ' s)</span></p><div class="ua-pre">' + esc((r.transcript || []).join('\n')) + '</div>';
        }).catch(function (e) { UA.showError($('sr-test-out'), e); }).then(function () { UA.busy(button, false); });
    }

    $('sr-add-domain').addEventListener('click', function () { $('sr-domains').appendChild(domainRow()); });
    $('sr-tls').addEventListener('change', tlsWarning);
    $('sr-port').addEventListener('change', function () {
        if ($('sr-port').value === '465') { $('sr-tls').value = 'implicit'; } else if ($('sr-tls').value === 'implicit') { $('sr-tls').value = 'starttls'; }
        tlsWarning();
    });
    $('sr-save').addEventListener('click', function () { save(false); });
    $('sr-disable').addEventListener('click', disable);
    $('sr-test').addEventListener('click', test);
    load(true);
})();
