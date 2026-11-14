(function () {
    'use strict';
    var root = document.getElementById('ua-webterm');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var admin = root.dataset.admin === '1';
    var term = null, fit = null, socket = null;

    function state(text) { $('wt-state').textContent = text; }

    function ensureTerminal() {
        if (term) { return; }
        term = new window.Terminal({cursorBlink: true, fontSize: 14, scrollback: 5000, convertEol: false});
        fit = new window.FitAddon.FitAddon();
        term.loadAddon(fit);
        term.open($('wt-term'));
        fit.fit();
        term.onData(function (data) { if (socket && socket.readyState === 1) { socket.send('0' + data); } });
        window.addEventListener('resize', function () {
            fit.fit();
            if (socket && socket.readyState === 1) { socket.send('1' + JSON.stringify({cols: term.cols, rows: term.rows})); }
        });
    }

    function connect() {
        ensureTerminal();
        var domain = $('wt-domain') ? $('wt-domain').value : '';
        var asRoot = admin && $('wt-asroot') && $('wt-asroot').checked;
        UA.busy($('wt-connect'), true);
        state('Requesting access…');
        api('ticket', {domain: domain, root: asRoot}).then(function (d) {
            var info = d.result;
            socket = new WebSocket(info.url);
            socket.binaryType = 'arraybuffer';
            socket.onopen = function () {
                socket.send(JSON.stringify({ticket: info.ticket, cols: term.cols, rows: term.rows}));
                state('Connected' + (asRoot ? ' as root' : ' to ' + domain));
                $('wt-disconnect').disabled = false;
                term.focus();
            };
            socket.onmessage = function (event) {
                term.write(typeof event.data === 'string' ? event.data : new Uint8Array(event.data));
            };
            socket.onclose = function (event) {
                state('Disconnected' + (event.reason ? ': ' + event.reason : ''));
                term.write('\r\n\x1b[33m[session closed' + (event.reason ? ': ' + event.reason : '') + ']\x1b[0m\r\n');
                $('wt-disconnect').disabled = true;
                UA.busy($('wt-connect'), false);
                socket = null;
            };
        }).catch(function (e) { state(e.message); UA.busy($('wt-connect'), false); });
    }

    $('wt-connect').addEventListener('click', connect);
    $('wt-disconnect').addEventListener('click', function () { if (socket) { socket.close(1000, 'closed by user'); } });

    if (admin) {
        var out = $('wt-admin-out');
        var render = function (r) {
            var s = r.service || {};
            $('wt-status').innerHTML = 'Service: <strong>' + UA.esc(s.state || 'not installed') + '</strong>' +
                (r.config && r.config.site ? ' · carried on <code>' + UA.esc(r.config.site) + '</code>' : '') +
                (r.proxied ? ' · proxy active' : ' · proxy not set up') +
                (s.memory_mb ? ' · ' + UA.esc(s.memory_mb) + ' MB' : '');
            if (r.proxied && r.config && r.config.site && $('wt-site')) { $('wt-site').value = r.config.site; }
            $('wt-users').checked = !!(r.policy && r.policy.terminal_for_users);
            $('wt-root').checked = !!(r.policy && r.policy.terminal_root_for_admins);
        };
        var load = function () { api('status', {}).then(function (d) { render(d.result); }).catch(function (e) { UA.showError(out, e); }); };
        $('wt-setup').addEventListener('click', function () {
            UA.busy($('wt-setup'), true);
            api('setup', {site: $('wt-site').value}).then(function (d) { out.innerHTML = ''; render(d.result); })
                .catch(function (e) { UA.showError(out, e); }).then(function () { UA.busy($('wt-setup'), false); });
        });
        $('wt-teardown').addEventListener('click', function () {
            api('teardown', {}).then(function (d) { render(d.result); }).catch(function (e) { UA.showError(out, e); });
        });
        var savePolicy = function () {
            api('policy', {terminal_for_users: $('wt-users').checked, terminal_root_for_admins: $('wt-root').checked})
                .then(load).catch(function (e) { UA.showError(out, e); });
        };
        $('wt-users').addEventListener('change', savePolicy);
        $('wt-root').addEventListener('change', savePolicy);
        load();
    }
})();
